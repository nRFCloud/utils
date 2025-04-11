#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import sys
import csv
import time
import json
import argparse
import platform
from nrfcloud_utils import modem_credentials_parser, rtt_interface
from nrfcloud_utils.cli_helpers import is_linux, is_windows, is_macos
from nrfcloud_utils.nordic_boards import ask_for_port, get_serial_port
from datetime import datetime, timezone
import coloredlogs, logging

logger = logging.getLogger(__name__)
CMD_TERM_DICT = {'NULL': '\0',
                 'CR':   '\r',
                 'LF':   '\n',
                 'CRLF': '\r\n'}
cmd_term_key = 'CRLF'
full_encoding = 'mbcs' if is_windows else 'ascii'
lf_done = False
plain = False
serial_timeout = 1
at_cmd_prefix = ''
args = None
IMEI_LEN = 15

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="Gather Attestation Tokens",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--csv", type=str,
                        help="Filepath to attestation token CSV file",
                        default="attestation_tokens.csv")
    parser.add_argument("-o", "--overwrite",
                        help="When saving attestation token CSV file, overwrite it",
                        action='store_true', default=False)
    parser.add_argument("--keep",
                        help="When appending to CSV files: if UUID exists in file, keep old data not current",
                        action='store_true', default=False)
    parser.add_argument("--port", type=str,
                        help="Specify which serial port to open, otherwise pick from list",
                        default=None)
    parser.add_argument("--baud", type=int,
                        help="Baud rate for serial port",
                        default=115200)
    parser.add_argument("-A", "--all",
                        help="List ports of all types, not just Nordic devices",
                        action='store_true', default=False)
    parser.add_argument("-P", "--plain",
                        help="bool: Plain output (no colors)",
                        action='store_true', default=False)
    parser.add_argument("--xonxoff",
                        help="Enable software flow control for serial connection",
                        action='store_true', default=False)
    parser.add_argument("--rtscts-off",
                        help="Disable hardware (RTS/CTS) flow control for serial connection",
                        action='store_true', default=False)
    parser.add_argument("--dsrdtr",
                        help="Enable hardware (DSR/DTR) flow control for serial connection",
                        action='store_true', default=False)
    parser.add_argument("--rtt",
                        help="Use RTT instead of serial. Requires application configured for RTT console",
                        action='store_true', default=False)
    parser.add_argument("--jlink-sn", type=int,
                        help="Serial number of J-Link device to use for RTT; optional",
                        default=None)
    parser.add_argument("--shell",
                        help="Use provisioning shell",
                        action='store_true', default=False)
    parser.add_argument('--log-level',
                        default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level'
    )
    args = parser.parse_args(in_args)
    level = getattr(logging, args.log_level.upper(), logging.INFO)
    fmt = '%(levelname)-8s %(message)s'
    coloredlogs.install(level=level, fmt=fmt)
    return args

def ensure_lf(line):
    global lf_done
    done = lf_done
    lf_done = True
    return '\n' + line if not done else line


def write_line(line, hidden = False):
    global cmd_term_key
    if not hidden:
        logger.debug('-> {}'.format(line))
    if ser:
        ser.write(bytes((line + CMD_TERM_DICT[cmd_term_key]).encode('utf-8')))
    elif rtt:
        rtt_interface.send_rtt(rtt, line + CMD_TERM_DICT[cmd_term_key])

def write_at_cmd(at_cmd):
    write_line(f'{at_cmd_prefix}{at_cmd}')

def wait_for_prompt(val1=b'uart:~$: ', val2=None, timeout=15, store=None):
    global lf_done
    found = False
    retval = False
    output = None

    if ser:
        ser.flush()
    else:
        rtt_lines = rtt_interface.readlines_at_rtt(rtt, timeout)

    while not found and timeout != 0:
        if ser:
            line = ser.readline()
        else:
            if len(rtt_lines) == 0:
                break
            line = rtt_lines.pop(0).encode()

        if line == b'\r\n':
            # Skip the initial CRLF (see 3GPP TS 27.007 AT cmd specification)
            continue

        if line == None or len(line) == 0:
            if timeout > 0:
                timeout -= serial_timeout
            continue

        if val1 in line:
            found = True
            retval = True
        elif val2 != None and val2 in line:
            found = True
            retval = False
        elif store != None and (store in line or str(store) in str(line)):
            output = line

    lf_done = b'\n' in line
    if ser:
        ser.flush()
    if store != None and output == None:
        logger.error('String {} not detected in line {}'.format(store, line))

    if timeout == 0:
        logger.error('Serial timeout')
        retval = False

    return retval, output

def cleanup():
    global ser
    global rtt
    if ser:
        ser.close()
    if rtt:
        rtt.close()

def get_attestation_token(verbose):
    write_at_cmd('AT%ATTESTTOKEN')
    # include the CRLF in OK because 'OK' could be found in the output string
    retval, output = wait_for_prompt(b'OK\r', b'ERROR', store=b'%ATTESTTOKEN: ')
    if not retval:
        error_exit('ATTESTTOKEN command failed')
    elif output == None:
        error_exit('Unable to detect ATTESTTOKEN output')

    # remove quotes
    attest_tok = str(output).split('"')[1]
    logger.debug('Attestation token: {}'.format(attest_tok))

    if verbose:
        modem_credentials_parser.parse_attesttoken_output(attest_tok)

    return attest_tok

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
    cleanup()
    if err_msg:
        logger.error(err_msg)
        sys.exit(1)
    else:
        sys.exit('Error... exiting.')

def main(in_args):
    global args
    global plain
    global ser
    global rtt
    global cmd_term_key
    global at_cmd_prefix

    # initialize arguments
    args = parse_args(in_args)
    plain = args.plain

    rtt = None

    # Set to CRLF for interaction with provisioning sample
    cmd_term_key = 'CRLF'

    # Adjust method to send an AT command
    at_cmd_prefix = '' if not args.shell else 'at '

    if args.rtt:
        cmd_term_key = 'CRLF'

        rtt = rtt_interface.connect_rtt(args.jlink_sn, args.mosh_rtt_hex)
        if not rtt:
            logger.error('Failed connect to device via RTT')
            sys.exit(2)

        if not rtt_interface.enable_at_cmds_mosh_rtt(rtt):
            logger.error('Failed to enable AT commands via RTT')
            sys.exit(3)
        ser = None
    else:
        # get a serial port to use
        logger.debug('Opening serial port...')
        if args.port:
            port = args.port
        else:
            port = ask_for_port(args.all)
        if port == None:
            sys.exit(1)

        logger.debug('Selected serial port: {}'.format(port))

        # try to open the serial port
        ser = get_serial_port(port, args.baud, xonxoff= args.xonxoff, rtscts=(not args.rtscts_off),
                            dsrdtr=args.dsrdtr)

    # get attestation token
    attest_tok = get_attestation_token(args.log_level == 'DEBUG')
    if not attest_tok:
        error_exit('Failed to obtain attestation token')

    # get the IMEI
    write_at_cmd('AT+CGSN')
    retval, imei = wait_for_prompt(b'OK', b'ERROR', store=b'\r\n')
    if not retval:
        logger.error('Failed to obtain IMEI')
        imei = None

    if imei:
        # display the IMEI for reference
        imei = str(imei.decode("utf-8"))[:IMEI_LEN]
        logger.debug('Device IMEI: ' + imei)

    # get device UUID from attestation token
    dev_uuid = modem_credentials_parser.get_device_uuid(attest_tok)
    logger.debug('Device UUID: ' + dev_uuid)

    if len(args.csv) > 0:
        save_attestation_csv(args.csv, not args.overwrite, not args.keep, imei,
                             dev_uuid, attest_tok)

    logger.debug('Done.')
    cleanup()

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
