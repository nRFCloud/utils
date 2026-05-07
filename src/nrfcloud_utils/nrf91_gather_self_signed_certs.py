#!/usr/bin/env python3
#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import csv
import logging
import os
import sys
import semver

from nrfcloud_utils.cli_helpers import (
    setup_logging,
    parser_add_comms_args,
    CMD_TERM_DICT, CMD_TYPE_AUTO, CMD_TYPE_AT, CMD_TYPE_AT_SHELL,
)
from nrfcloud_utils.device_credentials_installer import parse_mfw_ver
from nrfcredstore.command_interface import ATCommandInterface
from nrfcredstore.comms import Comms

logger = logging.getLogger(__name__)

MIN_REQD_MFW_VER = "2.0.2"
DEFAULT_SECTAG = 16842753
CSV_HEADERS = ["deviceId", "selfSignedCertificateAttestation"]
KEYGEN_TIMEOUT_S = 30


def get_parser():
    parser = argparse.ArgumentParser(
        description="Generate a self-signed certificate on an nRF91x1 device "
                    "and emit (deviceId, attestation) for nRF Cloud onboarding.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False,
    )
    parser_add_comms_args(parser)
    parser.add_argument("--csv", type=str, default="",
                        help="Filepath to onboarding CSV file. "
                             "If empty (default), only print to stdout.")
    parser.add_argument("-o", "--overwrite", action="store_true", default=False,
                        help="When saving CSV, overwrite the file instead of appending")
    parser.add_argument("--keep", action="store_true", default=False,
                        help="When appending: if device already exists in CSV, "
                             "keep old data instead of replacing")
    parser.add_argument("--sectag", type=int, default=DEFAULT_SECTAG,
                        help="Security tag to use for the self-signed certificate")
    parser.add_argument("-c", "--clear-sectag", action="store_true", default=False,
                        help="Clear the existing certificate and key in the "
                             "sectag before generating a new one. Required if "
                             "the slot is already populated.")
    parser.add_argument("-P", "--plain", action="store_true", default=False,
                        help="Plain output (no colors)")
    parser.add_argument("--log-level", default="info",
                        choices=["debug", "info", "warning", "error", "critical"],
                        help="Set the logging level")
    return parser


def parse_args(in_args):
    _p = get_parser()
    parser = argparse.ArgumentParser(parents=[_p], description=_p.description,
                                     formatter_class=_p.formatter_class)
    args = parser.parse_args(in_args)
    setup_logging(level=args.log_level, use_color=not args.plain)
    return args


def error_exit(msg, code=1):
    logger.error(msg)
    sys.exit(code)


def check_mfw_version(cred_if):
    ver = cred_if.get_mfw_version()
    if not ver:
        error_exit("Failed to obtain modem firmware version")
    logger.info(f"Modem FW version: {ver}")

    parsed = parse_mfw_ver(ver)
    if parsed is None:
        error_exit(f"Could not parse modem FW version from '{ver}'")
    if semver.Version.parse(parsed).compare(MIN_REQD_MFW_VER) < 0:
        error_exit(f"Modem FW version must be >= {MIN_REQD_MFW_VER}, got {parsed}")
    return ver


def get_device_uuid(cred_if):
    if not cred_if.at_command("AT%DEVICEUUID", wait_for_result=False):
        return None
    ok, output = cred_if.comms.expect_response("OK", "ERROR", "%DEVICEUUID:")
    if not ok:
        return None
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("%DEVICEUUID:"):
            uuid_str = line.split(":", 1)[1].strip()
            if uuid_str:
                return uuid_str
    return None


def gen_self_signed_cert(cred_if, sectag):
    cmd = f"AT%KEYGEN={sectag},14,2"
    if not cred_if.at_command(cmd, wait_for_result=False):
        return None
    ok, output = cred_if.comms.expect_response(
        "OK", "ERROR", "%KEYGEN:", timeout=KEYGEN_TIMEOUT_S
    )
    if not ok:
        return None
    for line in output.split("\n"):
        line = line.strip()
        if line.startswith("%KEYGEN:"):
            value = line.split(":", 1)[1].strip()
            return value.strip('"')
    return None


def check_if_device_exists_in_csv(csv_filename, dev_id, delete_duplicates):
    row_count = 0
    duplicate_rows = []
    keep_rows = [] if delete_duplicates else None
    try:
        with open(csv_filename) as f:
            for row in csv.reader(f):
                if not row:
                    continue
                if row[0] == CSV_HEADERS[0]:
                    if delete_duplicates:
                        keep_rows.append(row)
                    continue
                row_count += 1
                if row[0] == dev_id:
                    duplicate_rows.append(row)
                elif delete_duplicates:
                    keep_rows.append(row)
    except OSError:
        logger.error(f"Error opening (read) file {csv_filename}")
        return duplicate_rows, row_count

    if delete_duplicates and duplicate_rows:
        try:
            with open(csv_filename, "w", newline="\n") as f:
                w = csv.writer(f, delimiter=",", lineterminator="\n",
                               quoting=csv.QUOTE_MINIMAL)
                w.writerows(keep_rows)
        except OSError:
            logger.error(f"Error opening (write) file {csv_filename}")

    return duplicate_rows, row_count


def user_request_open_mode(filename, append):
    mode = "a" if append else "w"
    exists = os.path.isfile(filename)
    if not append and exists:
        answer = " "
        while answer not in "yan":
            answer = input(
                f"--- File {filename} exists; overwrite, append, or quit (y,a,n)? "
            )
        if answer == "n":
            logger.info("File will not be overwritten")
            return None
        mode = "w" if answer == "y" else "a"
    elif not exists and append:
        mode = "w"
        logger.warning("Append specified but file does not exist...")
    return mode


def save_csv(csv_filename, append, replace, dev_id, attestation):
    mode = user_request_open_mode(csv_filename, append)
    if mode is None:
        return

    write_header = mode == "w" or not os.path.isfile(csv_filename)

    if mode == "a" and not write_header:
        duplicate_rows, _ = check_if_device_exists_in_csv(csv_filename, dev_id, replace)
        if duplicate_rows:
            if replace:
                logger.warning(f"Removed existing row(s):\n\t{duplicate_rows}")
            else:
                logger.error(
                    f"Device {dev_id} already exists in {csv_filename}; row NOT added"
                )
                return

    try:
        with open(csv_filename, mode, newline="\n") as f:
            w = csv.writer(f, delimiter=",", lineterminator="\n",
                           quoting=csv.QUOTE_MINIMAL)
            if write_header:
                w.writerow(CSV_HEADERS)
            w.writerow([dev_id, attestation])
        logger.info(f"CSV file {csv_filename} saved")
    except OSError:
        logger.error(f"Error opening file {csv_filename}")


def main(in_args):
    args = parse_args(in_args)

    if args.cmd_type not in (CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_AUTO):
        error_exit("Self-signed certificate generation requires AT command support")

    serial_interface = Comms(
        port=args.port,
        serial=args.serial_number,
        baudrate=args.baud,
        xonxoff=args.xonxoff,
        rtscts=not args.rtscts_off,
        dsrdtr=args.dsrdtr,
        line_ending=CMD_TERM_DICT[args.term],
        list_all=args.all,
        rtt=args.rtt,
    )

    cred_if = ATCommandInterface(serial_interface)
    if args.cmd_type == CMD_TYPE_AUTO:
        cred_if.detect_shell_mode()
    elif args.cmd_type == CMD_TYPE_AT_SHELL:
        cred_if.set_shell_mode(True)
    elif args.rtt:
        cred_if.write_raw("at at_cmd_mode start")

    check_mfw_version(cred_if)

    logger.info("Reading device UUID...")
    dev_id = get_device_uuid(cred_if)
    if not dev_id:
        error_exit("Failed to read device UUID")
    logger.info(f"Device UUID: {dev_id}")

    logger.info("Switching modem to offline mode...")
    if not cred_if.go_offline():
        error_exit("Failed to switch modem to offline mode")

    if args.clear_sectag:
        logger.info(f"Clearing existing credentials in sectag {args.sectag}...")
        cred_if.delete_credential(args.sectag, 1)
        cred_if.delete_credential(args.sectag, 2)

    logger.info(f"Generating self-signed certificate (sectag {args.sectag})...")
    attestation = gen_self_signed_cert(cred_if, args.sectag)
    if not attestation:
        error_exit("Failed to generate self-signed certificate, use --clear-sectag if the slot is already occupied")

    logger.info("Returning modem to online mode...")
    if not cred_if.at_command("AT+CFUN=1", wait_for_result=True):
        logger.warning("Failed to return modem to online mode")

    print(f"{dev_id},{attestation}")

    if args.csv:
        save_csv(args.csv, append=not args.overwrite, replace=not args.keep,
                 dev_id=dev_id, attestation=attestation)


def run():
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
