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
import time
import serial
import hashlib
import getpass
import ca_certs
import platform
import rtt_interface
import modem_credentials_parser
from modem_credentials_parser import write_file
import create_device_credentials
from create_device_credentials import create_device_cert, create_local_csr

from serial.tools import list_ports
from colorama import init, Fore, Back, Style
from cryptography import x509
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM
from enum import Enum

CMD_TERM_DICT = {'NULL': '\0',
                 'CR':   '\r',
                 'LF':   '\n',
                 'CRLF': '\r\n'}
# 'CR' is the default termination value for the at_host library in the nRF Connect SDK
cmd_term_key = 'CR'
is_macos = platform.system() == 'Darwin'
is_windows = platform.system() == 'Windows'
is_linux = platform.system() == 'Linux'
full_encoding = 'mbcs' if is_windows else 'ascii'
default_password = 'nordic'
lf_done = False
plain = False
is_gateway = False
verbose = False
serial_timeout = 1
IMEI_LEN = 15
DEV_ID_MAX_LEN = 64
MAX_CSV_ROWS = 1000
MIN_REQD_MFW_VER = [1, 3, 0]
MIN_REQD_MFW_VER_FOR_VERIFY = [1, 3, 2]
parsed_mfw_ver=[]

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
                        help="Install the CoAP server root CA cert in addition to the AWS root CA cert",
                        action='store_true', default=False)
    parser.add_argument("--devinfo", type=str,
                        help="Filepath for device info CSV file which will contain the device ID, installed modem FW version, and IMEI",
                        default=None)
    parser.add_argument("--devinfo_append",
                        help="When saving device info CSV, append to it",
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
    parser.add_argument("--jlink_sn", type=int,
                        help="Serial number of J-Link device to use for RTT; optional",
                        default=None)
    parser.add_argument("--mosh_rtt_hex", type=str, help="Optional filepath to RTT enabled Modem Shell hex file. If provided, device will be erased and programmed",
                        default="")
    parser.add_argument("--verify",
                        help="Confirm credentials have been installed",
                        action='store_true', default=False)
    parser.add_argument("--stage", type=str,
                        help="For internal (Nordic) use only", default="")
    args = parser.parse_args()
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
    global is_gateway
    ports = []
    dev_types = []
    usb_patterns = [(r'THINGY91', 'Thingy:91', False),
                    (r'PCA20035', 'Thingy:91', False),
                    (r'0009600',  'nRF9160-DK', False),
                    (r'0010509',  'nRF9161-DK', False),
                    (r'NRFBLEGW', 'nRF Cloud Gateway', True)]
    if selected_port == None and not list_all:
        pattern = r'SER=(' + r'|'.join(name[0] for name in usb_patterns) + r')'
        print(local_style('Available ports:'))
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

def write_line(line, hidden = False):
    global cmd_term_key
    if not hidden:
        print(send_style('-> {}'.format(line)))
    if ser:
        ser.write(bytes((line + CMD_TERM_DICT[cmd_term_key]).encode('utf-8')))
    elif rtt:
        rtt_interface.send_rtt(rtt, line + CMD_TERM_DICT[cmd_term_key])

def handle_login():
    global password
    ser.write('\r'.encode('utf-8'))
    while True:
        if wait_for_prompt(b'login: ', b'gateway:# ', 10)[0]:
            write_line(password, hidden=True)
            ser.flush()
            if not wait_for_prompt(val2=b'Incorrect password!')[0]:
                password = getpass.getpass('Enter correct password:')
            else:
                break
        else:
            break

def wait_for_prompt(val1=b'gateway:# ', val2=None, timeout=15, store=None):
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

        sys.stdout.write('<- ' + str(line, encoding=full_encoding))

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

    return retval, output

def check_if_device_exists_in_csv(csv_filename, dev_id):
    exists = False
    row_count = 0

    try:
        with open(csv_filename) as csvfile:
            csv_contents = csv.reader(csvfile, delimiter=',')

            for row in csv_contents:
                row_count += 1
                # First column is the device ID
                if row[0] == dev_id:
                    exists = True

            csvfile.close()
    except OSError:
        print(error_style('Error opening file {}'.format(csv_filename)))

    return exists, row_count

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

def save_devinfo_csv(csv_filename, append, dev_id, mfw_ver, imei):
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return

    row = str('{},{},{}\n'.format(dev_id, mfw_ver, imei))

    if mode == 'a':
        exists, row_count = check_if_device_exists_in_csv(csv_filename, dev_id)

        if exists:
            print(error_style('Device already exists in device info CSV, the following row was NOT added:'))
            print(local_style(','.join(row)))
            return

    try:
        with open(csv_filename, mode, newline='\n') as devinfo_file:
            devinfo_file.write(row)
        print(local_style('Device info CSV file saved'))

    except OSError:
        print(error_style('Error opening file {}'.format(csv_filename)))

def save_onboarding_csv(csv_filename, append, dev_id, sub_type, tags, fw_types, dev):
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return

    row = [dev_id, sub_type, tags, fw_types, str(dev, encoding=full_encoding)]

    if mode == 'a':
        do_not_write = False
        exists, row_count = check_if_device_exists_in_csv(csv_filename, dev_id)

        if verbose:
            print(local_style("Onboarding CSV row count [max {}]: {}".format(MAX_CSV_ROWS, row_count)))

        if row_count >= MAX_CSV_ROWS:
            print(error_style('Onboarding CSV file is full'))
            do_not_write = True

        if exists:
            print(error_style('Onboarding CSV file already contains device \'{}\''.format(dev_id)))
            do_not_write = True

        if do_not_write:
            print(error_style('The following row was NOT added to the onboarding CSV file:'))
            print(local_style(','.join(row)))
            return

    try:
        with open(csv_filename, mode, newline='\n') as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=',', lineterminator='\n',
                                    quoting=csv.QUOTE_MINIMAL)
            csv_writer.writerow(row)
        print(local_style('Onboarding CSV file saved'))
    except OSError:
        print(error_style('Error opening file {}'.format(csv_filename)))

def cleanup():
    if not is_gateway:
        return
    print(local_style('Restoring terminal...'))
    write_line('exit')
    wait_for_prompt()
    write_line('logout')
    wait_for_prompt(b'login:')
    print(local_style('\nDone.'))

def parse_mfw_ver(ver_str):
    global parsed_mfw_ver

    # example modem fw version formats:
    #   'mfw_nrf9160_1.3.0'
    #   'mfw_nrf9160_1.3.0-FOTA-TEST'
    #   'mfw_nrf9161_2.0.0'
    ver_list = ver_str.split('.')

    if len(ver_list) < 3:
        print(error_style('Unexpected modem firmware version format'))
        return None

    # major should have an underscore in front
    maj_list = ver_list[0].split('_')
    if not len(maj_list):
        return None

    # it will be the last item in the list
    maj = maj_list[-1]

    # minor should be the second item
    min = ver_list[1]

    # revision should be the third item
    rev = ver_list[2]
    # in case there is additional info after the revision
    if rev.isnumeric() == False:
        rev = re.split(r'\D+', rev)
        if not rev:
            return None
        rev = rev[0]

    parsed_mfw_ver = [int(maj), int(min), int(rev)]
    return parsed_mfw_ver

def check_ver(req, cur):
    if not req or not cur:
        return None

    # expect 3 values: major, minor, rev
    if (len(req) < 3) or (len(cur) < 3):
        return None

    # check major
    if (cur[0] > req[0]):
        return True
    # check minor
    elif (cur[0] == req[0]) and (cur[1] > req[1]):
        return True
    # check rev
    elif (cur[0] == req[0]) and (cur[1] == req[1]) and (cur[2] >= req[2]):
        return True

    return False

def check_mfw_version():
    # get the modem firmware version
    write_line('AT+CGMR')
    retval, output = wait_for_prompt(b'OK', b'ERROR', store=b'\r\n')
    if not retval:
        print(error_style('Failed to obtain modem FW version'))
        cleanup()
        sys.exit(8)

    # display version for reference
    ver = str(output.decode("utf-8")).rstrip('\r\n')
    print(hivis_style('Modem FW version: ' + ver))

    # check for required version
    check_res = check_ver(MIN_REQD_MFW_VER, parse_mfw_ver(ver))
    if check_res is False:
        print(error_style('Modem FW version must be >= {}.{}.{}'.format(MIN_REQD_MFW_VER[0],
                                                                        MIN_REQD_MFW_VER[1],
                                                                        MIN_REQD_MFW_VER[2])))
        cleanup()
        sys.exit(8)
    elif check_res is None:
        print(error_style('Unexpected modem FW version format... continuing'))

    return ver

# Ask a device with modem to generate CSR usint AT%KEYGEN. Returns the CSR as an X509Req object.
def get_device_csr_at(custom_dev_id = "", sectag = 0):
    # provide attributes parameter if a custom device ID is specified
    attr = f',"CN={custom_dev_id}"' if len(custom_dev_id) else ''

    write_line('AT%KEYGEN={},2,0{}'.format(sectag,attr))
    # include the CR in OK because 'OK' could be found in the CSR string
    retval, output = wait_for_prompt(b'OK\r', b'ERROR', store=b'%KEYGEN:')
    if not retval:
        print(error_style('Unable to generate private key; does it already exist for this sectag?'))
        cleanup()
        sys.exit(9)
    elif output == None:
        print(error_style('Unable to detect KEYGEN output'))
        cleanup()
        sys.exit(10)

    # convert the encoded blob to an actual cert
    csr_blob = str(output).split('"')[1]
    if verbose:
        print(local_style('CSR blob: {}'.format(csr_blob)))

    modem_credentials_parser.parse_keygen_output(csr_blob)

    # load and return the CSR
    csr_bytes = modem_credentials_parser.csr_pem_bytes
    try:
        return OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_bytes)
    except OpenSSL.crypto.Error:
        cleanup()
        raise RuntimeError("Error loading CSR")


# Get a CSR, either by generating one on-device, or generating it locally.
def get_csr(custom_dev_id = "", sectag = 0, local = False):
    local_priv_key = None

    if (local):
        csr, local_priv_key = create_local_csr(cn = custom_dev_id)
    else:
        # Use AT commands to request a CSR
        csr = get_device_csr_at(custom_dev_id, sectag)

    return csr, local_priv_key

def format_cred(cred, is_gateway = False):
    formatted = cred

    if not isinstance(cred, str):
        formatted = str(cred, encoding=full_encoding)

    if is_gateway:
        formatted = formatted.replace("\n", "\\n")

    return formatted

# Write a modem credential. Provided credential should be plaintext
def write_modem_cred(sectag, cred_type, cred_text):
    cred_type_name = ["CA cert(s)", "dev cert", "private key"][cred_type]
    print(local_style(f'Writing {cred_type_name} to modem...'))

    write_line(f'AT%CMNG=0,{sectag},{cred_type},"{cred_text}"')
    wait_for_prompt(b'OK', b'ERROR')
    time.sleep(1)

def main():
    global plain
    global ser
    global rtt
    global password
    global is_gateway
    global cmd_term_key

    # initialize arguments
    args = parse_args()
    plain = args.plain
    password = args.password

    rtt = None

    if args.term in CMD_TERM_DICT.keys():
        cmd_term_key = args.term
    else:
        print(error_style('Invalid --term value provided, using default'))

    id_len = len(args.id_str)
    if (id_len > DEV_ID_MAX_LEN) or (args.id_imei and ((id_len + IMEI_LEN) > DEV_ID_MAX_LEN)):
        print(error_style('Device ID must not exceed {} characters'.format(DEV_ID_MAX_LEN)))
        cleanup()
        sys.exit(0)

    # initialize colorama
    if is_windows:
        init(convert = not plain)

    if verbose:
        print(local_style('OS detect: Linux={}, MacOS={}, Windows={}'.
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

        # for gateways, get to the AT command prompt first
        if is_gateway:
            print(local_style('Getting to prompt...'))
            handle_login()

            print(local_style('Disabling logs...'))
            write_line('log disable')
            wait_for_prompt()

            print(local_style('Getting to AT mode...'))
            write_line('at enable')
            wait_for_prompt(b'to exit AT mode')

    # prepare modem so we can interact with security keys
    print(local_style('Disabling LTE and GNSS...'))
    write_line('AT+CFUN=4')

    retval = wait_for_prompt(b'OK')
    if not retval:
        print(error_style('Unable to communicate'))
        cleanup()
        sys.exit(6)

    # get the IMEI
    write_line('AT+CGSN')
    retval, output = wait_for_prompt(b'OK', b'ERROR', store=b'\r\n')
    if not retval:
        print(error_style('Failed to obtain IMEI'))
        cleanup()
        sys.exit(7)
    # display the IMEI for reference
    imei = str(output.decode("utf-8"))[:IMEI_LEN]
    print(hivis_style('Device IMEI: ' + imei))

    # get and verify the modem firmware version
    mfw_ver = check_mfw_version()

    # set custom device ID
    custom_dev_id = args.id_str
    if args.id_imei:
        custom_dev_id += imei

    # remove old keys if we are replacing existing ones;
    # it's ok if some or all of these error out -- the slots were empty already
    if args.delete:
        print(local_style('Deleting sectag {}...'.format(args.sectag)))
        write_line('AT%CMNG=3,{},0'.format(args.sectag))
        wait_for_prompt(b'OK', b'ERROR')
        write_line('AT%CMNG=3,{},1'.format(args.sectag))
        wait_for_prompt(b'OK', b'ERROR')
        write_line('AT%CMNG=3,{},2'.format(args.sectag))
        wait_for_prompt(b'OK', b'ERROR')

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
        prv_text = format_cred(prv_bytes, is_gateway)
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
    dev_text = format_cred(dev_bytes, is_gateway)

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

    # write CA cert(s) to modem
    nrf_ca_cert_text = format_cred(ca_certs.get_ca_certs(args.coap, stage=args.stage), is_gateway)
    write_modem_cred(args.sectag, 0, nrf_ca_cert_text)

    # write dev cert to modem
    write_modem_cred(args.sectag, 1, dev_text)

    # If the dev cert was locally generated, write it to the modem
    if args.local_cert and prv_text is not None:
        write_modem_cred(args.sectag, 2, prv_text)

    if args.verify:
        print(error_style('Verifying credentials...'))
        verify_res = verify_credentials(args.sectag, nrf_ca_cert_text, dev_text)
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
        save_onboarding_csv(args.csv, args.append, dev_id, sub_type, args.tags,
                            args.fwtypes, dev_bytes)

    # write device ID, modem firmware version, and IMEI to a file
    if args.devinfo:
        save_devinfo_csv(args.devinfo, args.devinfo_append, dev_id, mfw_ver, imei)

    if rtt:
        rtt.close()

    cleanup()

def verify_credentials(sec_tag, ca_cert, client_cert):
    global parsed_mfw_ver

    # SHA check has a modem firmware version requirement
    do_sha_check = check_ver(MIN_REQD_MFW_VER_FOR_VERIFY, parsed_mfw_ver)
    if not do_sha_check:
        print(error_style('Skipping SHA verification, modem FW version must be >= {}.{}.{}'.
                          format(MIN_REQD_MFW_VER_FOR_VERIFY[0],
                                 MIN_REQD_MFW_VER_FOR_VERIFY[1],
                                 MIN_REQD_MFW_VER_FOR_VERIFY[2])))

    # list the CA cert
    write_line('AT%CMNG=1,{},0'.format(sec_tag))
    retval, ca_res = wait_for_prompt(b'OK', b'ERROR', store=b'%CMNG')
    if retval and ca_res:
        retval = check_credential(do_sha_check, ca_res.decode(), ca_cert, 'CA Cert')

    if not retval or not ca_res:
        print(error_style('...CA cert verification failed'))
        return False

    # list the client cert
    write_line('AT%CMNG=1,{},1'.format(sec_tag))
    retval, client_res = wait_for_prompt(b'OK', b'ERROR', store=b'%CMNG')
    if retval and client_res:
        retval = check_credential(do_sha_check, client_res.decode(), client_cert, 'Client Cert')

    if not retval or not client_res:
        print(error_style('...Client cert verification failed'))
        return False

    prv_sha = None
    # list the private key
    write_line('AT%CMNG=1,{},2'.format(sec_tag))
    retval, prv_res = wait_for_prompt(b'OK', b'ERROR', store=b'%CMNG')
    if retval and prv_res:
        prv_sha = parse_sha(prv_res.decode())

    if not prv_sha:
        print(error_style('...Private key not found'))
        return False

    if do_sha_check:
        print(hivis_style('Private Key SHA: {}'.format(prv_sha)))
    else:
        print(hivis_style('Private Key exists, SHA not verified'))

    return True

def parse_sha(cmng_result_str):
    # Example AT%CMNG response:
    #   %CMNG: 123,0,"2C43952EE9E000FF2ACC4E2ED0897C0A72AD5FA72C3D934E81741CBD54F05BD1"
    # The first item in " is the SHA.
    try:
        return cmng_result_str.split('"')[1]
    except (ValueError, IndexError):
        return None

def check_credential(verify_sha, cmng_result_str, credential_str, credential_name='Credential'):

    if not credential_str:
        print(error_style('Invalid credential string'))
        return False

    calculated_sha = hashlib.sha256(credential_str.encode('utf-8')).hexdigest().upper()

    modem_sha = parse_sha(cmng_result_str)
    if not modem_sha:
        print(error_style(f'{credential_name} - Invalid modem result: {cmng_result_str}'))
        return False

    if not verify_sha:
        print(hivis_style(f'{credential_name} exists, SHA not verified'))
        return True

    if modem_sha != calculated_sha:
        print(error_style(f'{credential_name} - SHA mismatch:'))
        print(error_style(f'\tModem     : {modem_sha}'))
        print(error_style(f'\tCalculated: {calculated_sha}'))
        return False

    print(hivis_style(f'{credential_name} - SHA verified: {calculated_sha}'))
    return True

if __name__ == '__main__':
    main()
