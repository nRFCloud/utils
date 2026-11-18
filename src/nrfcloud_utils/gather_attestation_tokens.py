#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import sys
import argparse
from nrfcloud_utils import modem_credentials_parser
from nrfcloud_utils.cli_helpers import setup_logging, save_device_create_csv
from nrfcloud_utils.cli_helpers import CMD_TERM_DICT, CMD_TYPE_AUTO, CMD_TYPE_AT, CMD_TYPE_AT_SHELL, RTT_UNAVAILABLE_MSG, parser_add_comms_args
from nrfcredstore.comms import Comms
from nrfcredstore.exceptions import RTTUnavailableError
from nrfcredstore.command_interface import ATCommandInterface
import logging

logger = logging.getLogger(__name__)

IMEI_LEN = 15

def get_parser():
    parser = argparse.ArgumentParser(description="Gather Attestation Tokens",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     add_help=False)
    parser_add_comms_args(parser)
    parser.add_argument("--csv", type=str,
                        help="Filepath to attestation token CSV file, for use with `nrfcloud device create`",
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
    return parser

def parse_args(in_args):
    _p = get_parser()
    parser = argparse.ArgumentParser(parents=[_p], description=_p.description, formatter_class=_p.formatter_class)
    args = parser.parse_args(in_args)
    setup_logging(level=args.log_level, use_color=not args.plain)
    return args

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

def save_attestation_csv(csv_filename, append, replace, uuid, attestation_token):
    """Save the device UUID and its attestation token to a CSV for `nrfcloud device create`."""
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return True

    return save_device_create_csv(csv_filename, 'attestationToken', uuid, attestation_token,
                                  replace=replace, overwrite=(mode == 'w'))

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

    try:
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
    except RTTUnavailableError:
        error_exit(RTT_UNAVAILABLE_MSG)

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
        if not save_attestation_csv(args.csv, not args.overwrite, not args.keep,
                                    dev_uuid, attest_tok):
            error_exit('Attestation token was not saved')

    logger.debug('Done.')

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
