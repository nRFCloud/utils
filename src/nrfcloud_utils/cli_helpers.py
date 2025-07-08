#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

from os import path
from os import makedirs
import platform
import os
import csv
import logging

MAX_CSV_ROWS = 1000

is_macos = platform.system() == 'Darwin'
is_windows = platform.system() == 'Windows'
is_linux = platform.system() == 'Linux'
full_encoding = 'mbcs' if is_windows else 'ascii'

logger = logging.getLogger(__name__)

def write_file(pathname, filename, bytes):
    """
    save bytes to file
    """

    if not path.isdir(pathname):
        try:
            makedirs(pathname, exist_ok=True)
        except OSError as e:
            raise RuntimeError(f"Error creating file path [{pathname}]")

    full_path = path.join(pathname, filename)

    try:
        f = open(full_path, "wb")
    except OSError:
        raise RuntimeError("Error opening file: " + full_path)

    f.write(bytes)
    logger.info("File created: " + path.abspath(f.name))
    f.close()

    return

def user_request_open_mode(filename, append):
    mode = 'a' if append else 'w'
    exists = os.path.isfile(filename)

    # if not appending, give user a choice whether to overwrite
    if not append and exists:
        answer = ' '
        while answer not in 'yan':
            answer = input('--- File {} exists; overwrite, append, or quit (y,a,n)? '.format(filename))

        if answer == 'n':
            logger.info('File will not be overwritten')
            return None
        elif answer == 'y':
            mode = 'w'
        else:
            mode = 'a'

    elif not exists and append:
        mode = 'w'
        logger.warning('Append specified but file does not exist...')

    return mode

def save_onboarding_csv(csv_filename, append, replace, dev_id, sub_type, tags, fw_types, dev):
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return

    row_count = 0

    row = [dev_id, sub_type, tags, fw_types, str(dev, encoding=full_encoding)]

    if mode == 'a':
        do_not_write = False
        duplicate_rows, row_count = check_if_device_exists_in_csv(csv_filename, dev_id, replace)

        if row_count >= MAX_CSV_ROWS:
            logger.error('Onboarding CSV file is full')
            do_not_write = True

        if len(duplicate_rows):
            if replace:
                logger.warning(f'Removed existing device onboarding data:\r\n\t{duplicate_rows}')
            else:
                logger.error(f'Onboarding CSV file already contains device \'{dev_id}\'')
                do_not_write = True

        if do_not_write:
            logger.error('The following row was NOT added to the onboarding CSV file:')
            logger.info(str(row))
            return

    try:
        with open(csv_filename, mode, newline='\n') as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=',', lineterminator='\n',
                                    quoting=csv.QUOTE_MINIMAL)
            csv_writer.writerow(row)
        logger.info(f'Onboarding CSV file saved, row count: {row_count + 1}')
    except OSError:
        logger.error(f'Error opening file {csv_filename}')

def check_if_device_exists_in_csv(csv_filename, dev_id, delete_duplicates):
    row_count = 0
    duplicate_rows = list()
    if delete_duplicates:
        keep_rows = list()

    try:
        with open(csv_filename) as csvfile:
            csv_contents = csv.reader(csvfile, delimiter=',')

            for row in csv_contents:
                row_count += 1
                # First column is the device ID
                if row[0] == dev_id:
                    # Device ID found, save the row
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

def save_devinfo_csv(csv_filename, append, replace, dev_id, mfw_ver = None, imei = None):
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return

    row_count = 0

    row = f'{dev_id},{mfw_ver if mfw_ver else ""},{imei if imei else ""}\n'

    if mode == 'a':
        duplicate_rows, row_count = check_if_device_exists_in_csv(csv_filename, dev_id, replace)

        if len(duplicate_rows):
            if replace:
                logger.warning(f'Removed existing device info data:\r\n\t{duplicate_rows}')
            else:
                logger.error('Device already exists in device info CSV, the following row was NOT added:')
                logger.info(row)
                return

    try:
        with open(csv_filename, mode, newline='\n') as devinfo_file:
            devinfo_file.write(row)
        logger.info(f'Device info CSV file saved, row count: {row_count + 1}')
    except OSError:
        logger.error('Error opening file {}'.format(csv_filename))

CMD_TERM_DICT = {'NULL': '\0',
                 'CR':   '\r',
                 'LF':   '\n',
                 'CRLF': '\r\n'}

CMD_TYPE_AT = "at"
CMD_TYPE_AT_SHELL = "at_shell"
CMD_TYPE_TLS_SHELL = "tls_cred_shell"
CMD_TYPE_AUTO = "auto"

def parser_add_comms_args(parser):
    parser.add_argument("-A", "--all",
                        help="List ports of all types, not just Nordic devices",
                        action='store_true', default=False)
    parser.add_argument("--port", type=str,
                        help="Specify which serial port to open, otherwise pick from list",
                        default=None)
    parser.add_argument("--serial-number", type=int,
                        help="Serial number of Nordic or J-Link device",
                        default=None)
    parser.add_argument("--baud", type=int,
                        help="Baud rate for serial port",
                        default=115200)
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
                        help="Use RTT instead of serial. Requires device run Modem Shell sample application configured with RTT overlay",
                        action='store_true', default=False)
    parser.add_argument("--cmd-type", default=CMD_TYPE_AUTO, choices=[CMD_TYPE_AUTO, CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_TLS_SHELL], type=str.lower,
                    help=f"Specify the device command line type. '{CMD_TYPE_AT}' will use AT commands, '{CMD_TYPE_AT_SHELL}' will prefix AT commands with 'at ', and '{CMD_TYPE_TLS_SHELL}' will use TLS Credentials Shell commands.")
    parser.add_argument("--term", type=str,
                        help="AT command termination",choices=list(CMD_TERM_DICT.keys()),
                        default='CRLF')
