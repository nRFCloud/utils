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
import getpass
import platform
import rtt_interface
import modem_credentials_parser
from modem_credentials_parser import write_file
import create_device_credentials
from create_device_credentials import create_device_cert
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
aws_ca  = "-----BEGIN CERTIFICATE-----\nMIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\nADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\nb24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\nMAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\nb3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\nca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\nIFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\nVOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\njgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\nA4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\nU5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\nN+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\no/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\nrqXRfboQnoZsG4q5WTP468SQvvG5\n-----END CERTIFICATE-----\n"
coap_ca = "-----BEGIN CERTIFICATE-----\nMIIBmzCCAUKgAwIBAgIUOdcovsGv94HR18N97qIgq6mfyXowCgYIKoZIzj0EAwIw\nGjEYMBYGA1UEAwwPblJGIENsb3VkIC0gRGV2MB4XDTIzMDMzMTEyMTM1NVoXDTQ4\nMTIzMTEyMTM1NVowGjEYMBYGA1UEAwwPblJGIENsb3VkIC0gRGV2MFkwEwYHKoZI\nzj0CAQYIKoZIzj0DAQcDQgAEsWwBJY6XL1tD+3qs62oHPzIR+gxAd2suL38kvJWP\nrxeEJjDqUBP2+UvAMpDuChG/aQ3x5bw9enFlN1EUJaJrt6NmMGQwHQYDVR0OBBYE\nFHJV6uiRFXRDMrIejIAbDRUkF2CAMB8GA1UdIwQYMBaAFHJV6uiRFXRDMrIejIAb\nDRUkF2CAMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqG\nSM49BAMCA0cAMEQCIDJdB0q6IVTSMBJCjgrdqsazeUbkxWG019X/yJTQyd2QAiA8\nAmLG/0x09X2Qm+30MgNxOE4BiybZuwH9NF8KQVqQlg==\n-----END CERTIFICATE-----\n"
prov_ca = "-----BEGIN CERTIFICATE-----\nMIIBUDCB96ADAgECAgkA/YgJ9vjCE48wCgYIKoZIzj0EAwIwIjEgMB4GA1UEAwwX\nZGV2LW5yZi1wcm92aXNpb25pbmctY2EwHhcNMjMwMTA5MTIwNDQ3WhcNMzMwMTA2\nMTIwNDQ3WjAiMSAwHgYDVQQDDBdkZXYtbnJmLXByb3Zpc2lvbmluZy1jYTBZMBMG\nByqGSM49AgEGCCqGSM49AwEHA0IABFfKcaEkRik+3dPO1yQRYQ/NzXgt6rxHr//D\nq4jDycMJx4x5VUWX65+50j9ebLGKwFlXI0uhfLrCI1ftOrrHfbujFjAUMBIGA1Ud\nEwEB/wQIMAYBAf8CAQEwCgYIKoZIzj0EAwIDSAAwRQIgVLCesd2h1XttBp6jKsx2\nnzlrvfWqkOUdOgk0Wfy93uUCIQCkE3HlEXbaV9HgALzFdIV1Vk0emb2+zpwA4VrH\nPDi0Aw==\n-----END CERTIFICATE-----\n"
IMEI_LEN = 15
DEV_ID_MAX_LEN = 64
MAX_CSV_ROWS = 1000

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
                        help="Filepath to provisioning CSV file",
                        default="provision.csv")
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
                        help="When saving provisioning CSV, append to it",
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
    parser.add_argument("--prov",
                        help="Install the nrf_provisioning root CA cert",
                        action='store_true', default=False)
    parser.add_argument("--devinfo", type=str,
                        help="Filepath for device info CSV file which will contain the device ID, installed modem FW version, and IMEI",
                        default=None)
    parser.add_argument("--devinfo_append",
                        help="When saving device info CSV, append to it",
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
        print(error_style('String {} not detected in line {}'.format(store,
                                                                    line)))

    if timeout == 0:
        print(error_style('Serial timeout'))

    return retval, output

def check_if_device_exists_in_csv(csv_filename, dev_id):
    exists = False
    row_count = 0

    try:
        with open(csv_filename) as csvfile:
            prov = csv.reader(csvfile, delimiter=',')

            for row in prov:
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

def save_provisioning_csv(csv_filename, append, dev_id, sub_type, tags, fw_types, dev):
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return

    row = [dev_id, sub_type, tags, fw_types, str(dev, encoding=full_encoding)]

    if mode == 'a':
        do_not_write = False
        exists, row_count = check_if_device_exists_in_csv(csv_filename, dev_id)

        if verbose:
            print(local_style("Provisioning CSV row count [max {}]: {}".format(MAX_CSV_ROWS, row_count)))

        if row_count >= MAX_CSV_ROWS:
            print(error_style('Provisioning CSV file is full'))
            do_not_write = True

        if exists:
            print(error_style('Provisioning CSV file already contains device \'{}\''.format(dev_id)))
            do_not_write = True

        if do_not_write:
            print(error_style('The following row was NOT added to the provisioning CSV file:'))
            print(local_style(','.join(row)))
            return

    try:
        with open(csv_filename, mode, newline='\n') as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=',', lineterminator='\n',
                                    quoting=csv.QUOTE_MINIMAL)
            csv_writer.writerow(row)
        print(local_style('Provisioning CSV file saved'))
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

def main():
    global plain
    global ser
    global rtt
    global password
    global is_gateway
    global cmd_term_key

    # initialize argumenst
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

    if args.coap and args.prov:
        print(error_style('The options --coap and --prov are mutually exclusive'))
        sys.exit(1)

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

    # get the modem firmware version
    write_line('AT+CGMR')
    retval, output = wait_for_prompt(b'OK', b'ERROR', store=b'\r\n')
    if not retval:
        print(error_style('Failed to obtain modem FW version'))
        cleanup()
        sys.exit(8)
    # display version for reference
    mfw_ver = str(output.decode("utf-8")).rstrip('\r\n')
    print(hivis_style('Modem FW Version: ' + mfw_ver))

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
    # provide attributes parameter if a custom device ID is specified
    attr = ''
    if len(custom_dev_id):
        attr = ',\"CN={}\"'.format(custom_dev_id)

    write_line('AT%KEYGEN={},2,0{}'.format(args.sectag,attr))
    # include the CRLF in OK because 'OK' could be found in the CSR string
    retval, output = wait_for_prompt(b'OK\r\n', b'ERROR', store=b'%KEYGEN:')
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
    if args.save:
        modem_credentials_parser.save_output(args.path, args.fileprefix)

    # get the public key from the CSR
    csr_bytes = modem_credentials_parser.csr_pem_bytes
    try:
        csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM,
                                                      csr_bytes)
        pub_key = csr.get_pubkey()
    except OpenSSL.crypto.Error:
        cleanup()
        raise RuntimeError("Error loading CSR")

    if len(csr.get_subject().CN) == 0:
        print(error_style('CSR\'s Common Name (CN) is empty'))
        cleanup()
        sys.exit(11)

    # display info we received for the CSR
    dev_id = csr.get_subject().CN
    print(hivis_style('Device ID: {}'.format(dev_id)))
    if verbose:
        pub_key_bytes = modem_credentials_parser.pub_key_bytes
        print(hivis_style('CSR PEM: {}'.format(csr_bytes)))
        print(hivis_style('Pub key: {}'.format(pub_key_bytes)))

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
    dev = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM,
                                          device_cert)
    if verbose:
        print(local_style('Dev cert: {}'.format(dev)))
    if args.save:
        print(local_style('Saving dev cert...'))
        write_file(args.path, args.fileprefix + dev_id + "_crt.pem", dev)

    # save public key and/or print it
    pub = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pub_key)
    if verbose:
        print(local_style('Pub key: {}'.format(pub)))
    if args.save:
        print(local_style('Saving pub key...'))
        write_file(args.path, args.fileprefix + dev_id + "_pub.pem", pub)

    # write to AWS CA modem
    print(local_style('Writing AWS CA to modem...'))
    if is_gateway:
        modem_ca = aws_ca.replace("\n", "\\n")
    elif args.coap and not args.prov:
        modem_ca = coap_ca + aws_ca
    elif args.prov and not args.coap:
        modem_ca = prov_ca
    else:
        modem_ca = aws_ca
    write_line('AT%CMNG=0,{},0,"{}"'.format(args.sectag, modem_ca))
    wait_for_prompt(b'OK', b'ERROR')
    time.sleep(1)

    # write dev cert to modem
    print(local_style('Writing dev cert to modem...'))
    modem_dev = str(dev, encoding=full_encoding)
    if is_gateway:
        modem_dev = modem_dev.replace("\n", "\\n")
    write_line('AT%CMNG=0,{},1,"{}"'.format(args.sectag, modem_dev))
    wait_for_prompt(b'OK', b'ERROR')
    time.sleep(1)

    # write provisioning information to csv if requested by user
    if len(args.csv) > 0:
        print(local_style('{} provisioning endpoint CSV file {}...'
                          .format('Appending' if args.append else 'Saving', args.csv)))
        sub_type = 'gateway' if is_gateway else ''
        if len(args.subtype) > 0:
            sub_type = args.subtype
        save_provisioning_csv(args.csv, args.append, dev_id, sub_type, args.tags,
                              args.fwtypes, dev)

    # write device ID, modem firmware version, and IMEI to a file
    if args.devinfo:
        save_devinfo_csv(args.devinfo, args.devinfo_append, dev_id, mfw_ver, imei)

    if rtt:
        rtt.close()

    cleanup()

if __name__ == '__main__':
    main()
