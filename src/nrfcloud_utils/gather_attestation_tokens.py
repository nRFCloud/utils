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
import serial
import argparse
import platform
from nrfcloud_utils import modem_credentials_parser, rtt_interface
from nrfcloud_utils.cli_helpers import is_linux, is_windows, is_macos
from nrfcloud_utils.nordic_boards import usb_patterns
from serial.tools import list_ports
from datetime import datetime, timezone
from colorama import init, Fore, Back, Style

CMD_TERM_DICT = {'NULL': '\0',
                 'CR':   '\r',
                 'LF':   '\n',
                 'CRLF': '\r\n'}
# 'CR' is the default termination value for the at_host library in the nRF Connect SDK
cmd_term_key = 'CR'
full_encoding = 'mbcs' if is_windows else 'ascii'
lf_done = False
plain = False
verbose = False
serial_timeout = 1
at_cmd_prefix = ''
args = None
IMEI_LEN = 15

def parse_args(in_args):
    global verbose

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
    parser.add_argument("-A", "--all",
                        help="List ports of all types, not just Nordic devices",
                        action='store_true', default=False)
    parser.add_argument("-v", "--verbose",
                        help="bool: Make output verbose",
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
    args = parser.parse_args(in_args)
    verbose = args.verbose
    return args

def ensure_lf(line):
    global lf_done
    done = lf_done
    lf_done = True
    return '\n' + line if not done else line

def local_style(line):
    return ensure_lf(Fore.CYAN + line
                     + Style.RESET_ALL) if not plain else line

def hivis_style(line):
    return ensure_lf(Fore.MAGENTA + line
                     + Style.RESET_ALL) if not plain else line

def send_style(line):
    return ensure_lf(Fore.BLUE + line
                     + Style.RESET_ALL) if not plain else line

def error_style(line):
    return ensure_lf(Fore.RED + line + Style.RESET_ALL) if not plain else line

def ask_for_port(selected_port, list_all):
    """
    Show a list of ports and ask the user for a choice, unless user specified
    a specific port on the command line. To make selection easier on systems
    with long device names, also allow the input of an index.
    """
    ports = []
    dev_types = []

    if selected_port == None and not list_all:
        pattern = r'SER=(' + r'|'.join(name[0] for name in usb_patterns) + r')'
        print(send_style('Available ports:'))
    else:
        pattern = r''

    port_num = 1
    for n, (port, desc, hwid) in enumerate(sorted(list_ports.grep(pattern)), 1):

        if not is_macos:
            # if a specific port is not requested, filter out ports with
            # LOCATION in hwid that do not end in '.0' because these are
            # usually not the logging or shell ports
            if selected_port == None and not list_all and 'LOCATION' in hwid:
                if hwid[-2] != '.' or hwid[-1] != '0':
                    if verbose:
                        print(send_style('Skipping: {:2}: {:20} {!r} {!r}'.
                                          format(port_num, port, desc, hwid)))
                    continue
        else:
            # if a specific port not requested, filter out ports whose /dev
            # does not end in a 1
            if selected_port == None and not list_all and port[-1] != '1':
                if verbose:
                    print(send_style('Skipping: {:2}: {:20} {!r} {!r}'.
                                      format(port_num, port, desc, hwid)))
                continue

        name = ''
        for nm in usb_patterns:
            if nm[0] in hwid:
                name = nm[1]
                break

        if selected_port != None:
            if selected_port == port:
                return port
        else:
            print(send_style('{:2}: {:20} {:17}'.format(port_num, port, name)))
            if verbose:
                print(send_style('  {!r} {!r}'.format(desc, hwid)))

            ports.append(port)
            dev_types.append(False)
            port_num += 1

    if len(ports) == 0:
        sys.stderr.write(error_style('No device found\n'))
        return None
    if len(ports) == 1:
        return ports[0]
    while True:
        port = input('--- Enter port index: ')
        try:
            index = int(port) - 1
            if not 0 <= index < len(ports):
                sys.stderr.write(error_style('--- Invalid index!\n'))
                continue
        except ValueError:
            pass
        else:
            port = ports[index]
        return port

def write_line(line, hidden = False):
    global cmd_term_key
    if not hidden:
        print(send_style('-> {}'.format(line)))
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

        #sys.stdout.write('<- ' + str(line, encoding=full_encoding))

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
        print(error_style('String {} not detected in line {}'.format(store, line)))

    if timeout == 0:
        print(error_style('Serial timeout'))
        retval = False

    return retval, output

def cleanup():
    global ser
    global rtt
    if ser:
        ser.close()
    if rtt:
        rtt.close()

def get_attestation_token():
    write_at_cmd('AT%ATTESTTOKEN')
    # include the CRLF in OK because 'OK' could be found in the output string
    retval, output = wait_for_prompt(b'OK\r', b'ERROR', store=b'%ATTESTTOKEN: ')
    if not retval:
        error_exit('ATTESTTOKEN command failed')
    elif output == None:
        error_exit('Unable to detect ATTESTTOKEN output')

    # remove quotes
    attest_tok = str(output).split('"')[1]
    print(local_style('Attestation token: {}'.format(attest_tok)))

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
        print(error_style(f'Error opening (read) file {csv_filename}'))

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
            print(error_style(f'Error opening file (write) {csv_filename}'))

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
            print(local_style('File will not be overwritten'))
            return None
        elif answer == 'y':
            mode = 'w'
        else:
            mode = 'a'

    elif not exists and append:
        mode = 'w'
        print('Append specified but file does not exist...')

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
                print(hivis_style(f'Removed existing data:\r\n\t{duplicate_rows}'))
            else:
                print(error_style('Device already exists in CSV, the following row was NOT added:'))
                print(local_style(row))
                return

    try:
        with open(csv_filename, mode, newline='\n') as devinfo_file:
            devinfo_file.write(row)
        print(local_style(f'Attestation CSV file {csv_filename} saved, row count: {row_count + 1}'))
    except OSError:
        print(error_style('Error opening file {}'.format(csv_filename)))

def error_exit(err_msg):
    cleanup()
    if err_msg:
        sys.stderr.write(error_style(err_msg))
        sys.stderr.write('\n')
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

    # initialize colorama
    if is_windows:
        init(convert = not plain)

    if args.verbose:
        print(send_style('OS detect: Linux={}, MacOS={}, Windows={}\n'.
                          format(is_linux, is_macos, is_windows)))

    if args.rtt:
        cmd_term_key = 'CRLF'

        rtt = rtt_interface.connect_rtt(args.jlink_sn, args.mosh_rtt_hex)
        if not rtt:
            sys.stderr.write(error_style('Failed connect to device via RTT'))
            sys.exit(2)

        if not rtt_interface.enable_at_cmds_mosh_rtt(rtt):
            sys.stderr.write(error_style('Failed to enable AT commands via RTT'))
            sys.exit(3)
        ser = None
    else:
        # get a serial port to use
        print(local_style('Opening serial port...'))
        port = ask_for_port(args.port, args.all)
        if port == None:
                sys.exit(1)

        print(local_style('Selected serial port: {}'.format(port)))

        # try to open the serial port
        try:
                ser = serial.Serial(port, 115200, xonxoff= args.xonxoff, rtscts=(not args.rtscts_off),
                                dsrdtr=args.dsrdtr, timeout=serial_timeout)
                ser.reset_output_buffer()
                write_line('')
                time.sleep(0.2)
                ser.reset_input_buffer()
        except serial.serialutil.SerialException:
                error_exit('Port could not be opened; not a device, or open already')

    # get attestation token
    attest_tok = get_attestation_token()
    if not attest_tok:
        error_exit('Failed to obtain attestation token')

    # get the IMEI
    write_at_cmd('AT+CGSN')
    retval, imei = wait_for_prompt(b'OK', b'ERROR', store=b'\r\n')
    if not retval:
        print(error_style('Failed to obtain IMEI'))
        imei = None

    if imei:
        # display the IMEI for reference
        imei = str(imei.decode("utf-8"))[:IMEI_LEN]
        print(send_style('\nDevice IMEI: ' + imei))

    # get device UUID from attestation token
    dev_uuid = modem_credentials_parser.get_device_uuid(attest_tok)
    print(send_style('Device UUID: ' + dev_uuid))

    if len(args.csv) > 0:
        save_attestation_csv(args.csv, not args.overwrite, not args.keep, imei,
                             dev_uuid, attest_tok)

    print(local_style('Done.'))
    cleanup()
    sys.exit(0)

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
