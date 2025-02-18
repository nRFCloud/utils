#!/usr/bin/env python3
#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

import argparse
import re
import os
import sys
import csv
import serial
import getpass
import ca_certs
import rtt_interface
from cli_helpers import write_file
import semver
import create_device_credentials
from create_device_credentials import create_device_cert, create_local_csr
import cli_helpers
from cli_helpers import (
    error_style, local_style, send_style, hivis_style, init_colorama, cli_disable_styles,
    print_os_detect
)
from command_interface import ATCommandInterface, ATKeygenException, TLSCredShellInterface
from serial_interface import SerialInterfaceGeneric

from serial.tools import list_ports
from cryptography import x509
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

CMD_TERM_DICT = {'NULL': '\0',
                 'CR':   '\r',
                 'LF':   '\n',
                 'CRLF': '\r\n'}
# 'CR' is the default termination value for the at_host library in the nRF Connect SDK

CMD_TYPE_AT = "at"
CMD_TYPE_AT_SHELL = "at_shell"
CMD_TYPE_TLS_SHELL = "tls_cred_shell"

cmd_term_key = 'CR'

default_password = 'nordic'
is_gateway = False
verbose = False
serial_timeout = 1
IMEI_LEN = 15
DEV_ID_MAX_LEN = 64
MAX_CSV_ROWS = 1000
MIN_REQD_MFW_VER = "1.3.0"
MIN_REQD_MFW_VER_FOR_VERIFY = "1.3.2"

def parse_args():
    global verbose

    parser = argparse.ArgumentParser(description="Device Credentials Installer",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--dv", type=int, help="Number of days cert is valid",
                        default=(10 * 365))
    parser.add_argument("--ca", type=str, help="Filepath to your CA cert PEM",
                        default="")
    parser.add_argument("--ca_key", type=str,
                        help="Filepath to your CA's private key PEM",
                        default="")
    parser.add_argument("--csv", type=str,
                        help="Filepath to onboarding CSV file",
                        default="onboard.csv")
    parser.add_argument("--port", type=str,
                        help="Specify which serial port to open, otherwise pick from list",
                        default=None)
    parser.add_argument("--id_str", type=str,
                        help="Device ID to use instead of UUID. Will be a prefix if used with --id_imei",
                        default="")
    parser.add_argument("--id_imei",
                        help="Use IMEI for device ID instead of UUID. Add a prefix with --id_str",
                        action='store_true', default=False)
    parser.add_argument("-a", "--append",
                        help="When saving onboarding CSV, append to it",
                        action='store_true', default=False)
    parser.add_argument("-A", "--all",
                        help="List ports of all types, not just Nordic devices",
                        action='store_true', default=False)
    parser.add_argument("-g", "--gateway",
                        help="Force use of shell commands to enter and exit AT command mode",
                        action='store_true', default=False)
    parser.add_argument("-f", "--fileprefix", type=str,
                        help="Prefix for output files (<prefix><UUID>_<sec_tag>_<type>.pem). Selects -s",
                        default="")
    parser.add_argument("-v", "--verbose",
                        help="bool: Make output verbose",
                        action='store_true', default=False)
    parser.add_argument("-s", "--save", action='store_true',
                        help="Save PEM file(s): <UUID>_<sec_tag>_<type>.pem")
    parser.add_argument("-S", "--sectag", type=int,
                        help="integer: Security tag to use", default=16842753)
    parser.add_argument("-p", "--path", type=str,
                        help="Path to save files.  Selects -s", default="./")
    parser.add_argument("-P", "--plain",
                        help="bool: Plain output (no colors)",
                        action='store_true', default=False)
    parser.add_argument("-d", "--delete",
                        help="bool: Delete sectag from modem first",
                        action='store_true', default=False)
    parser.add_argument("-w", "--password", type=str,
                        help="nRF Cloud Gateway password",
                        default=default_password)
    parser.add_argument("-t", "--tags", type=str,
                        help="Pipe (|) delimited device tags; enclose in double quotes", default="")
    parser.add_argument("-T", "--subtype", type=str,
                        help="Custom device type", default='')
    parser.add_argument("-F", "--fwtypes", type=str,
                        help="""
                        Pipe (|) delimited firmware types for FOTA of the set
                        {APP MODEM BOOT SOFTDEVICE BOOTLOADER}; enclose in double quotes
                        """, default="APP|MODEM")
    parser.add_argument("--coap",
                        help="Install the CoAP server root CA cert",
                        action='store_true')
    parser.add_argument("--aws",
                        help="Install the AWS root CA cert",
                        action='store_true')
    parser.add_argument("--devinfo", type=str,
                        help="Filepath for device info CSV file which will contain the device ID, installed modem FW version, and IMEI",
                        default=None)
    parser.add_argument("--devinfo_append",
                        help="When saving device info CSV, append to it",
                        action='store_true', default=False)
    parser.add_argument("--replace",
                        help="When appending to onboarding or device info CSV files: if device ID exists in file, replace old data with current",
                        action='store_true', default=False)
    parser.add_argument("--local_cert",
                        help="Generate device cert and private key on the host machine, rather than on the device.",
                        action='store_true', default=False)
    parser.add_argument("--xonxoff",
                        help="Enable software flow control for serial connection",

                        action='store_true', default=False)
    parser.add_argument("--rtscts_off",
                        help="Disable hardware (RTS/CTS) flow control for serial connection",
                        action='store_true', default=False)
    parser.add_argument("--dsrdtr",
                        help="Enable hardware (DSR/DTR) flow control for serial connection",
                        action='store_true', default=False)
    parser.add_argument("--term", type=str,
                        help="AT command termination:" + "".join([' {}'.format(k) for k, v in CMD_TERM_DICT.items()]),
                        default=cmd_term_key)
    parser.add_argument("--rtt",
                        help="Use RTT instead of serial. Requires device run Modem Shell sample application configured with RTT overlay",
                        action='store_true', default=False)
    parser.add_argument("--cmd_type", default=CMD_TYPE_AT, choices=[CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_TLS_SHELL], type=str.lower,
                    help=f"Specify the device command line type. '{CMD_TYPE_AT}' will use AT commands, '{CMD_TYPE_AT_SHELL}' will prefix AT commands with 'at ', and '{CMD_TYPE_TLS_SHELL}' will use TLS Credentials Shell commands.")
    parser.add_argument("--jlink_sn", type=int,
                        help="Serial number of J-Link device to use for RTT; optional",
                        default=None)
    parser.add_argument("--mosh_rtt_hex", type=str, help="Optional filepath to RTT enabled Modem Shell hex file. If provided, device will be erased and programmed",
                        default="")
    parser.add_argument("--verify",
                        help="Confirm credentials have been installed",
                        action='store_true', default=False)
    parser.add_argument("--stage", type=str,
                        help="For internal (Nordic) use only", default="prod")
    args = parser.parse_args()
    verbose = args.verbose
    return args


def ask_for_port(selected_port, list_all):
    """
    Show a list of ports and ask the user for a choice, unless user specified
    a specific port on the command line. To make selection easier on systems
    with long device names, also allow the input of an index.
    """
    global is_gateway
    ports = []
    dev_types = []
    usb_patterns = [(r'THINGY91', 'Thingy:91', False),
                    (r'PCA20035', 'Thingy:91', False),
                    (r'0010550',  'Thingy:91 X', False),
                    (r'0010551',  'Thingy:91 X', False),
                    (r'0010513',  'Thingy:91 X', False),
                    (r'0009600',  'nRF9160-DK', False),
                    (r'0010509',  'nRF9161-DK', False),
                    (r'0010512',  'nRF9151-DK', False),
                    (r'0009601',  'nRF5340-DK', False),
                    (r'NRFBLEGW', 'nRF Cloud Gateway', True)]
    if selected_port == None and not list_all:
        pattern = r'SER=(' + r'|'.join(name[0] for name in usb_patterns) + r')'
        print(local_style('Available ports:'))
    else:
        pattern = r''

    port_num = 1
    for n, (port, desc, hwid) in enumerate(sorted(list_ports.grep(pattern)), 1):

        if not cli_helpers.is_macos:
            # if a specific port is not requested, filter out ports with
            # LOCATION in hwid that do not end in '.0' because these are
            # usually not the logging or shell ports
            if selected_port == None and not list_all and 'LOCATION' in hwid:
                if hwid[-2] != '.' or hwid[-1] != '0':
                    if verbose:
                        print(local_style('Skipping: {:2}: {:20} {!r} {!r}'.
                                          format(port_num, port, desc, hwid)))
                    continue
        else:
            # if a specific port not requested, filter out ports whose /dev
            # does not end in a 1
            if selected_port == None and not list_all and port[-1] != '1':
                if verbose:
                    print(local_style('Skipping: {:2}: {:20} {!r} {!r}'.
                                      format(port_num, port, desc, hwid)))
                continue

        name = ''
        is_gateway = False
        for nm in usb_patterns:
            if nm[0] in hwid:
                name = nm[1]
                is_gateway = nm[2]
                break

        if selected_port != None:
            if selected_port == port:
                return port
        else:
            print(local_style('{:2}: {:20} {:17}'.format(port_num, port, name)))
            if verbose:
                print(local_style('  {!r} {!r}'.format(desc, hwid)))

            ports.append(port)
            dev_types.append(is_gateway)
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

def login_gateway():
    global password

    if ser:
        ser.write('\r'.encode('utf-8'))

    while True:
        if sif.wait_for_prompt(b'login: ', b'gateway:# ', 10)[0]:
            sif.write_line(password, hidden=True)
            sif.flush()
            if not ser.wait_for_prompt(val2=b'Incorrect password!')[0]:
                password = getpass.getpass('Enter correct password:')
            else:
                break
        else:
            break

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
                print(hivis_style(f'Removed existing device info data:\r\n\t{duplicate_rows}'))
            else:
                print(error_style('Device already exists in device info CSV, the following row was NOT added:'))
                print(local_style(row))
                return

    try:
        with open(csv_filename, mode, newline='\n') as devinfo_file:
            devinfo_file.write(row)
        print(local_style(f'Device info CSV file saved, row count: {row_count + 1}'))
    except OSError:
        print(error_style('Error opening file {}'.format(csv_filename)))

def save_onboarding_csv(csv_filename, append, replace, dev_id, sub_type, tags, fw_types, dev):
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return

    row_count = 0

    row = [dev_id, sub_type, tags, fw_types, str(dev, encoding=cli_helpers.full_encoding)]

    if mode == 'a':
        do_not_write = False
        duplicate_rows, row_count = check_if_device_exists_in_csv(csv_filename, dev_id, replace)

        if verbose:
            print(local_style("Onboarding CSV row count [max {}]: {}".format(MAX_CSV_ROWS, row_count)))

        if row_count >= MAX_CSV_ROWS:
            print(error_style('Onboarding CSV file is full'))
            do_not_write = True

        if len(duplicate_rows):
            if replace:
                print(hivis_style(f'Removed existing device onboarding data:\r\n\t{duplicate_rows}'))
            else:
                print(error_style(f'Onboarding CSV file already contains device \'{dev_id}\''))
                do_not_write = True

        if do_not_write:
            print(error_style('The following row was NOT added to the onboarding CSV file:'))
            print(local_style(str(row)))
            return

    try:
        with open(csv_filename, mode, newline='\n') as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=',', lineterminator='\n',
                                    quoting=csv.QUOTE_MINIMAL)
            csv_writer.writerow(row)
        print(local_style(f'Onboarding CSV file saved, row count: {row_count + 1}'))
    except OSError:
        print(error_style(f'Error opening file {csv_filename}'))

def cleanup():
    if not is_gateway:
        return
    print(local_style('Restoring terminal...'))
    sif.write_line('exit')
    sif.wait_for_prompt()
    sif.write_line('logout')
    sif.wait_for_prompt(b'login:')
    print(local_style('\nDone.'))

def parse_mfw_ver(ver_str):
    # example modem fw version formats:
    #   'mfw_nrf9160_1.3.0'
    #   'mfw_nrf9160_1.3.0-FOTA-TEST'
    #   'mfw_nrf9161_2.0.0'

    # Use regex to match the numeric portion (x.x.x) of the version string
    # lookahead/lookbehind ensure the version is prefixed/suffixed by - or _, or is at either
    # end of the string.
    matches = re.findall(r"(?:(?<=[-_])|(?<=^))[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?=[-_]|$)",
                         ver_str.strip())

    # If the version regex does not match exactly once, then we are dealing with a malformed
    # version number.
    if len(matches) != 1:
        print(error_style('Unexpected modem firmware version format'))
        return None

    return matches[0]

def check_mfw_version():
    # get the modem firmware version
    ver = cred_if.get_mfw_version()
    if not ver:
        print(error_style('Failed to obtain modem FW version'))
        cleanup()
        sys.exit(8)

    # display version for reference
    print(hivis_style('Modem FW version: ' + ver))

    # check for required version
    parsed_ver = parse_mfw_ver(ver)

    if parsed_ver is None:
        print(error_style('Unexpected modem FW version format... continuing'))
    elif semver.compare(parsed_ver, MIN_REQD_MFW_VER) < 0:
        print(error_style(f'Modem FW version must be >= {MIN_REQD_MFW_VER}'))
        cleanup()
        sys.exit(8)
    return ver

# Get a CSR, either by generating one on-device, or generating it locally.
def get_csr(custom_dev_id = "", sectag = 0, local = False):
    local_priv_key = None

    if (local):
        csr, local_priv_key = create_local_csr(cn = custom_dev_id)
    else:
        # Use AT commands to request a CSR.
        try:
            csr = cred_if.get_csr(sectag, custom_dev_id)
        except ATKeygenException as e:
            print(error_style(str(e)))
            cleanup()
            sys.exit(e.exit_code)

    return csr, local_priv_key

def format_cred(cred, is_gateway = False):
    formatted = cred

    if not isinstance(cred, str):
        formatted = str(cred, encoding=cli_helpers.full_encoding)

    if is_gateway:
        formatted = formatted.replace("\n", "\\n")

    return formatted

def main():
    global ser
    global rtt
    global sif
    global password
    global is_gateway
    global cmd_term_key
    global cred_if

    # initialize arguments
    args = parse_args()

    if args.plain:
        cli_disable_styles()

    password = args.password

    rtt = None

    if not args.aws:
        print(error_style("Warning: The AWS root cert is no longer included by default. Add the -aws argument if you need this cert."))

    print("args", args.aws, args.coap)
    if not args.aws and not args.coap:
        print(error_style('At least one CA cert must be installed. Enable -aws, -coap, or both.'))
        cleanup()
        sys.exit(0)

    if args.term in CMD_TERM_DICT.keys():
        cmd_term_key = args.term
    else:
        print(error_style('Invalid --term value provided, using default'))

    id_len = len(args.id_str)
    if (id_len > DEV_ID_MAX_LEN) or (args.id_imei and ((id_len + IMEI_LEN) > DEV_ID_MAX_LEN)):
        print(error_style('Device ID must not exceed {} characters'.format(DEV_ID_MAX_LEN)))
        cleanup()
        sys.exit(0)

    # initialize colorama (if needed)
    init_colorama()

    if verbose:
        cli_helpers.print_os_detect()

    cmd_type_has_at = args.cmd_type in (CMD_TYPE_AT, CMD_TYPE_AT_SHELL)
    has_shell = (args.cmd_type == CMD_TYPE_AT_SHELL)

    if args.gateway and not cmd_type_has_at:
        print(error_style(f"--gateway requires cmd_type '{CMD_TYPE_AT}' or '{CMD_TYPE_AT_SHELL}'"))
        cleanup()
        sys.exit(0)

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
        port = ask_for_port(args.port, args.all)
        if port == None:
            sys.exit(4)

        # let user know which we are using and as what kind of device
        if args.gateway:
            is_gateway = True
        print(local_style('Opening port {} as {}...'.format(port,
                                                    'gateway' if is_gateway
                                                    else 'generic device')))

        # try to open the serial port
        try:
            ser = serial.Serial(port, 115200, xonxoff= args.xonxoff, rtscts=(not args.rtscts_off),
                                dsrdtr=args.dsrdtr, timeout=serial_timeout)
            ser.reset_input_buffer()
            ser.reset_output_buffer()
        except serial.serialutil.SerialException:
            sys.stderr.write(error_style('Port could not be opened; not a device, or open already\n'))
            sys.exit(5)

    # Create a SerialInterface wrapping either the `ser` or `rtt` interfaces.
    sif = SerialInterfaceGeneric(ser, rtt)
    sif.set_terminator(CMD_TERM_DICT[cmd_term_key])

    # for gateways, get to the AT command prompt first
    if is_gateway:
        sif.set_default_prompt('gateway:# ')

        print(local_style('Getting to prompt...'))
        login_gateway()

        print(local_style('Disabling logs...'))
        sif.write_line('log disable')
        sif.wait_for_prompt()

        print(local_style('Getting to AT mode...'))
        sif.write_line('at enable')
        sif.wait_for_prompt(b'to exit AT mode')

    cred_if = None
    if cmd_type_has_at:
        cred_if = ATCommandInterface(sif, verbose)
        if args.cmd_type == CMD_TYPE_AT_SHELL:
            cred_if.set_shell_mode(True)

    if args.cmd_type == CMD_TYPE_TLS_SHELL:
        # cred_if = TLSCredShellInterface(write_line, wait_for_prompt, verbose)
        cred_if = TLSCredShellInterface(sif, verbose)

    # prepare modem so we can interact with security keys
    if (cmd_type_has_at):
        print(local_style('Disabling LTE and GNSS...'))
        if not cred_if.go_offline():
            print(error_style('Unable to communicate'))
            cleanup()
            sys.exit(6)

    # get the IMEI
    imei = None
    if (cmd_type_has_at):
        imei = cred_if.get_imei()

        if imei is None:
            print(error_style('Failed to obtain IMEI'))
            cleanup()
            sys.exit(7)

        # display the IMEI for reference
        print(hivis_style('Device IMEI: ' + imei))

    # get and verify the modem firmware version
    mfw_ver = None
    if (cmd_type_has_at):
        mfw_ver = check_mfw_version()

    # set custom device ID
    custom_dev_id = args.id_str
    if args.id_imei and imei is not None:
        custom_dev_id += imei

    # remove old keys if we are replacing existing ones;
    # it's ok if some or all of these error out -- the slots were empty already
    if args.delete:
        print(local_style('Deleting sectag {}...'.format(args.sectag)))
        cred_if.delete_credential(args.sectag, 0)
        cred_if.delete_credential(args.sectag, 1)
        cred_if.delete_credential(args.sectag, 2)

    # now get a new certificate signing request (CSR)
    print(local_style('Generating private key and requesting a CSR for sectag {}...'.format(args.sectag)))

    # Get a CSR
    csr, prv_key = get_csr(custom_dev_id, args.sectag, local=args.local_cert)

    # Collect or generate associated artifacts
    csr_bytes = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr)
    prv_bytes = None
    prv_text = None
    if prv_key is not None:
        prv_bytes = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, prv_key)
        prv_text = format_cred(prv_bytes, has_shell)
    pub_key = csr.get_pubkey()
    pub_bytes = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pub_key)
    dev_id = csr.get_subject().CN

    if len(dev_id) == 0:
        print(error_style('CSR\'s Common Name (CN) is empty'))
        cleanup()
        sys.exit(11)

    if args.save:
        # Save CSR if desired
        write_file(args.path, args.fileprefix + dev_id + "_csr.pem", csr_bytes)

        # Save private key if available
        if prv_key is not None:
            write_file(args.path, args.fileprefix + dev_id + "_prv.pem", prv_bytes)

    # display CSR info
    print(hivis_style('Device ID: {}'.format(dev_id)))
    if verbose:
        print(hivis_style('CSR PEM: {}'.format(csr_bytes)))
        print(hivis_style('Pub key: {}'.format(pub_bytes)))

    # check if we have all we need to proceed
    if len(args.ca) == 0 or len(args.ca_key) == 0:
        print(local_style('No CA or CA key provided; skipping creating dev cert'))
        cleanup()
        sys.exit(0)

    # load the user's certificate authority (CA)
    print(local_style('Loading CA and key...'))
    ca_cert = create_device_credentials.load_ca(args.ca)
    ca_key = create_device_credentials.load_ca_key(args.ca_key)

    # create a device cert
    print(local_style('Creating device certificate...'))
    device_cert = create_device_cert(args.dv, csr, pub_key, ca_cert, ca_key)

    # save device cert and/or print it
    dev_bytes = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, device_cert)
    dev_text = format_cred(dev_bytes, has_shell)

    if verbose:
        print(local_style('Dev cert: {}'.format(dev_bytes)))
    if args.save:
        print(local_style('Saving dev cert...'))
        write_file(args.path, args.fileprefix + dev_id + "_crt.pem", dev_bytes)

    # save public key and/or print it
    if verbose:
        print(local_style('Pub key: {}'.format(pub_bytes)))
    if args.save:
        print(local_style('Saving pub key...'))
        write_file(args.path, args.fileprefix + dev_id + "_pub.pem", pub_bytes)

    # write CA cert(s) to device
    nrf_ca_cert_text = format_cred(ca_certs.get_ca_certs(args.coap, args.aws, stage=args.stage), has_shell)
    print("the cert" + nrf_ca_cert_text)

    print(local_style(f'Writing CA cert(s) to device...'))
    cred_if.write_credential(args.sectag, 0, nrf_ca_cert_text)

    # write dev cert to device
    print(local_style(f'Writing dev cert to device...'))
    cred_if.write_credential(args.sectag, 1, dev_text)

    # If the private key was locally generated, write it to the device
    if prv_text is not None:
        print(local_style(f'Writing private key to device...'))
        cred_if.write_credential(args.sectag, 2, prv_text)

    if args.verify:
        print(error_style('Verifying credentials...'))
        check_sha = True

        # AT-command-based SHA check has a modem firmware version requirement
        if (cmd_type_has_at):
            parsed_ver = parse_mfw_ver(mfw_ver)
            if parsed_ver and semver.compare(parsed_ver, MIN_REQD_MFW_VER_FOR_VERIFY) < 0:
                print(error_style('Skipping SHA verification, ' +
                                f'modem FW version must be >= {MIN_REQD_MFW_VER_FOR_VERIFY}'))
                check_sha = False

        verify_res = verify_credentials(args.sectag, nrf_ca_cert_text, dev_text, prv_text,
                                        check_sha=check_sha)
        if not verify_res:
            print(error_style('Credential verification: FAIL'))
            cleanup()
            sys.exit(12)

        print(local_style('Credential verification: PASS'))

    # write onboarding information to csv if requested by user
    if len(args.csv) > 0:
        print(local_style('{} nRF Cloud device onboarding CSV file {}...'
                          .format('Appending' if args.append else 'Saving', args.csv)))
        sub_type = 'gateway' if is_gateway else ''
        if len(args.subtype) > 0:
            sub_type = args.subtype
        save_onboarding_csv(args.csv, args.append, args.replace, dev_id, sub_type, args.tags,
                            args.fwtypes, dev_bytes)

    # write device ID, modem firmware version, and IMEI to a file
    if args.devinfo:
        save_devinfo_csv(args.devinfo, args.devinfo_append, args.replace, dev_id, mfw_ver, imei)

    if rtt:
        rtt.close()

    cleanup()

def verify_credentials(sec_tag, ca_cert, client_cert, client_prv=None, check_sha=False):
    global cred_if

    # verify the CA cert
    if not verify_credential(sec_tag, 0, ca_cert, verify_hash = check_sha):
        return False

    # verify client cert
    if not verify_credential(sec_tag, 1, client_cert, verify_hash = check_sha):
        return False

    if not verify_credential(sec_tag, 2, client_prv, get_hash = check_sha,
                             verify_hash = (client_prv is not None) and check_sha):
        return False

    return True

def verify_credential(sec_tag, cred_type, cred = None, get_hash = False, verify_hash = False):
    if (verify_hash):
        get_hash = True

    cred_type_name = ['CA Cert', 'Client Cert', 'Private Key'][cred_type]
    print(local_style(f'Verifying {cred_type_name}'))

    if verify_hash and not cred:
        print(error_style('Invalid credential string'))
        return False

    present, hash = cred_if.check_credential_exists(sec_tag, cred_type, get_hash = get_hash)

    if not present:
        print(error_style(f'...{cred_type_name} not found'))
        return False

    if get_hash and not hash:
        print(error_style(f'...{cred_type_name} has invalid hash'))
        return False

    if verify_hash:
        expected_hash = cred_if.calculate_expected_hash(cred)
        if hash != expected_hash:
                print(error_style(f'{cred_type_name} - SHA mismatch:'))
                print(error_style(f'\tDevice    : {hash}'))
                print(error_style(f'\tCalculated: {expected_hash}'))
                return False
    else:
        print(hivis_style(f'{cred_type_name} exists, SHA not verified'))

    return True

if __name__ == '__main__':
    main()
