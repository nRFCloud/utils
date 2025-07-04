#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import sys
import csv
import argparse
from nrfcloud_utils import modem_credentials_parser
from nrfcloud_utils.cli_helpers import is_linux, is_windows, is_macos
from nrfcloud_utils.cli_helpers import CMD_TERM_DICT, CMD_TYPE_AUTO, CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_TLS_SHELL, parser_add_comms_args
from nrfcredstore.comms import Comms
from nrfcredstore.command_interface import ATCommandInterface
from datetime import datetime, timezone
import coloredlogs, logging

logger = logging.getLogger(__name__)

IMEI_LEN = 15

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="Gather Attestation Tokens",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser_add_comms_args(parser)
    parser.add_argument("--csv", type=str,
                        help="Filepath to attestation token CSV file",
                        default="attestation_tokens.csv")
    parser.add_argument("-o", "--overwrite",
                        help="When saving attestation token CSV file, overwrite it",
                        action='store_true', default=False)
    parser.add_argument("--keep",
                        help="When appending to CSV files: if UUID exists in file, keep old data not current",
                        action='store_true', default=False)
    parser.add_argument("-P", "--plain",
                        help="bool: Plain output (no colors)",
                        action='store_true', default=False)
    parser.add_argument('--log-level',
                        default='info',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level'
    )
    args = parser.parse_args(in_args)
    if args.plain:
        logging.basicConfig(level=args.log_level.upper())
    else:
        coloredlogs.install(level=args.log_level.upper(), fmt='%(levelname)-8s %(message)s')
    return args

def check_if_device_exists_in_csv(csv_filename, uuid, delete_duplicates):
    row_count = 0
    duplicate_rows = list()
    if delete_duplicates:
        keep_rows = list()

    try:
        with open(csv_filename) as csvfile:
            csv_contents = csv.reader(csvfile, delimiter=',')

            for row in csv_contents:
                row_count += 1
                # Second column is the UUID
                if row[1] == uuid:
                    # uuid found, save the row
                    duplicate_rows.append(row)
                else:
                    if delete_duplicates:
                        # Copy all non-duplicate rows if the delete flag is set
                        keep_rows.append(row)

            csvfile.close()
    except OSError:
        logger.error(f'Error opening (read) file {csv_filename}')

    # Re-write the file without the duplicate rows
    if delete_duplicates and len(duplicate_rows):
        # Get new row count
        row_count = len(keep_rows)
        try:
            with open(csv_filename, 'w', newline='\n') as csvfile:
                csv_writer = csv.writer(csvfile, delimiter=',', lineterminator='\n',
                                        quoting=csv.QUOTE_MINIMAL)
                csv_writer.writerows(keep_rows)
                csvfile.close()
        except OSError:
            logger.error(f'Error opening file (write) {csv_filename}')

    return duplicate_rows, row_count

def user_request_open_mode(filename, append):
    mode = 'a' if append else 'w'
    exists = os.path.isfile(filename)

    # if not appending, give user a choice whether to overwrite
    if not append and exists:
        answer = ' '
        while answer not in 'yan':
            answer = input('--- File {} exists; overwrite, append, or quit (y,a,n)? '.format(filename))

        if answer == 'n':
            logger.debug('File will not be overwritten')
            return None
        elif answer == 'y':
            mode = 'w'
        else:
            mode = 'a'

    elif not exists and append:
        mode = 'w'
        logger.warning('Append specified but file does not exist...')

    return mode

def save_attestation_csv(csv_filename, append, replace, imei, uuid, attestation_token):
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return

    row_count = 0

    row = f'{imei},{uuid},{attestation_token},{datetime.now(timezone.utc).isoformat()}\n'

    if mode == 'a':
        duplicate_rows, row_count = check_if_device_exists_in_csv(csv_filename, uuid, replace)

        if len(duplicate_rows):
            if replace:
                logger.warning(f'Removed existing data:\r\n\t{duplicate_rows}')
            else:
                logger.error('Device already exists in CSV, the following row was NOT added:')
                logger.debug(row)
                return

    try:
        with open(csv_filename, mode, newline='\n') as devinfo_file:
            devinfo_file.write(row)
        logger.info(f'Attestation CSV file {csv_filename} saved, row count: {row_count + 1}')
    except OSError:
        logger.error('Error opening file {}'.format(csv_filename))

def error_exit(err_msg):
    if err_msg:
        logger.error(err_msg)
    sys.exit(1)

def main(in_args):

    # initialize arguments
    args = parse_args(in_args)

    if args.cmd_type not in (CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_AUTO):
        logger.error('Attestation tokens are only supported on devices with AT command support')
        sys.exit(1)

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

    cred_if = None
    cred_if = ATCommandInterface(serial_interface)
    if args.cmd_type == CMD_TYPE_AUTO:
        cred_if.detect_shell_mode()
    elif args.cmd_type == CMD_TYPE_AT_SHELL:
        cred_if.set_shell_mode(True)
    elif args.rtt:
        cred_if.write_raw('at at_cmd_mode start')

    # verify that the device is not nrf9160
    model_id = cred_if.get_model_id()
    if model_id and 'nRF9160' in model_id:
        logger.error('Device is nRF9160, not supported')
        sys.exit(1)

    # get attestation token
    attest_tok = cred_if.get_attestation_token()
    if not attest_tok:
        error_exit('Failed to obtain attestation token')

    if args.log_level == 'debug':
        modem_credentials_parser.parse_attesttoken_output(attest_tok)

    # get the IMEI
    imei = cred_if.get_imei()

    if imei:
        # display the IMEI for reference
        logger.debug('Device IMEI: ' + imei)

    # get device UUID from attestation token
    dev_uuid = modem_credentials_parser.get_device_uuid(attest_tok)
    logger.debug('Device UUID: ' + dev_uuid)

    if len(args.csv) > 0:
        save_attestation_csv(args.csv, not args.overwrite, not args.keep, imei,
                             dev_uuid, attest_tok)

    logger.debug('Done.')

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
