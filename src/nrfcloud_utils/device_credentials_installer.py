#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import re
import os
import sys
import csv
import serial
import getpass
import semver
from nrfcloud_utils import create_device_credentials, ca_certs, rtt_interface
from nrfcloud_utils.cli_helpers import error_style, local_style, send_style, hivis_style, init_colorama, cli_disable_styles, write_file, save_devinfo_csv, save_onboarding_csv, is_linux, is_windows, is_macos, full_encoding
from nrfcloud_utils.command_interface import ATCommandInterface, ATKeygenException, TLSCredShellInterface
from nrfcloud_utils.nordic_boards import usb_patterns

from serial.tools import list_ports
from cryptography import x509
from cryptography.hazmat.primitives import serialization

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
MIN_REQD_MFW_VER = "1.3.0"
MIN_REQD_MFW_VER_FOR_VERIFY = "1.3.2"

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="Device Credentials Installer",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--dv", type=int, help="Number of days cert is valid",
                        default=(10 * 365))
    parser.add_argument("--ca", type=str, help="Filepath to your CA cert PEM",
                        default="")
    parser.add_argument("--ca-key", type=str,
                        help="Filepath to your CA's private key PEM",
                        default="")
    parser.add_argument("--csv", type=str,
                        help="Filepath to onboarding CSV file",
                        default="onboard.csv")
    parser.add_argument("--port", type=str,
                        help="Specify which serial port to open, otherwise pick from list",
                        default=None)
    parser.add_argument("--id-str", type=str,
                        help="Device ID to use instead of UUID. Will be a prefix if used with --id-imei",
                        default="")
    parser.add_argument("--id-imei",
                        help="Use IMEI for device ID instead of UUID. Add a prefix with --id-str",
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
    parser.add_argument("--devinfo-append",
                        help="When saving device info CSV, append to it",
                        action='store_true', default=False)
    parser.add_argument("--replace",
                        help="When appending to onboarding or device info CSV files: if device ID exists in file, replace old data with current",
                        action='store_true', default=False)
    parser.add_argument("--local-cert",
                        help="Generate device cert and private key on the host machine, rather than on the device.",
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
    parser.add_argument("--term", type=str,
                        help="AT command termination:" + "".join([' {}'.format(k) for k, v in CMD_TERM_DICT.items()]),
                        default=cmd_term_key)
    parser.add_argument("--rtt",
                        help="Use RTT instead of serial. Requires device run Modem Shell sample application configured with RTT overlay",
                        action='store_true', default=False)
    parser.add_argument("--cmd-type", default=CMD_TYPE_AT, choices=[CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_TLS_SHELL], type=str.lower,
                    help=f"Specify the device command line type. '{CMD_TYPE_AT}' will use AT commands, '{CMD_TYPE_AT_SHELL}' will prefix AT commands with 'at ', and '{CMD_TYPE_TLS_SHELL}' will use TLS Credentials Shell commands.")
    parser.add_argument("--jlink-sn", type=int,
                        help="Serial number of J-Link device to use for RTT; optional",
                        default=None)
    parser.add_argument("--mosh-rtt-hex", type=str, help="Optional filepath to RTT enabled Modem Shell hex file. If provided, device will be erased and programmed",
                        default="")
    parser.add_argument("--verify",
                        help="Confirm credentials have been installed",
                        action='store_true', default=False)
    parser.add_argument("--stage", type=str,
                        help="For internal (Nordic) use only", default="")
    parser.add_argument("--local-cert-file", type=str,
                        help="Filepath to a local certificate (PEM) to use for the device",
                        default=None)
    parser.add_argument("--cert-type", type=int,
                        help="Certificate type to use for the device",
                        default=1)
    args = parser.parse_args(in_args)
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

def wait_for_prompt(val1='gateway:# ', val2=None, timeout=15, store=None):
    found = False
    retval = False
    output = None

    # Convert string arguments to bytes if needed.
    if isinstance(val1, str):
        val1=val1.encode()

    if isinstance(val2, str):
        val2=val2.encode()

    if isinstance(store, str):
        store=store.encode()

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

    if b'\n' not in line:
        sys.stdout.write('\n')

    if ser:
        ser.flush()
    if store != None and output == None:
        print(error_style('String {} not detected in line {}'.format(store, line)))

    if timeout == 0:
        print(error_style('Serial timeout'))

    return retval, output




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
        csr, local_priv_key = create_device_credentials.create_local_csr(cn = custom_dev_id)
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
        formatted = str(cred, encoding=full_encoding)

    if is_gateway:
        formatted = formatted.replace("\n", "\\n")

    return formatted

def get_existing_credentials(args, dev_id):
    files = [
        args.path + args.fileprefix + dev_id + "_prv.pem",
        args.path + args.fileprefix + dev_id + "_crt.pem",
    ]
    result = []
    if all(os.path.isfile(f) for f in files):
        for f in files:
            with open(f, "r") as file:
                result.append(file.read())
    else:
        result = [None, None]
    return result


def main(in_args):
    global ser
    global rtt
    global password
    global is_gateway
    global cmd_term_key
    global cred_if

    # initialize arguments
    args = parse_args(in_args)

    if args.plain:
        cli_disable_styles()

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
        init_colorama()

    if verbose:
        print(local_style('OS detect: Linux={}, MacOS={}, Windows={}'.
                          format(is_linux, is_macos, is_windows)))

    if args.cmd_type == CMD_TYPE_TLS_SHELL and not (args.local_cert or args.local_cert_file):
        # This check can be removed once the TLS Credential Shell supports CSR generation.
        print(error_style(f"cmd_type '{CMD_TYPE_TLS_SHELL}' currently requires --local_cert or --local_cert_file"))
        cleanup()
        sys.exit(0)

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

    cred_if = None
    if cmd_type_has_at:
        cred_if = ATCommandInterface(write_line, wait_for_prompt, verbose)
        if args.cmd_type == CMD_TYPE_AT_SHELL:
            cred_if.set_shell_mode(True)

    if args.cmd_type == CMD_TYPE_TLS_SHELL:
        cred_if = TLSCredShellInterface(write_line, wait_for_prompt, verbose)

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

    dev_id = custom_dev_id
    prv_bytes, dev_bytes = get_existing_credentials(args, dev_id)

    if prv_bytes is None and args.local_cert_file is None:
        # now get a new certificate signing request (CSR)
        print(local_style('Generating private key and requesting a CSR for sectag {}...'.format(args.sectag)))

        # Get a CSR
        csr, prv_key = get_csr(custom_dev_id, args.sectag, local=args.local_cert)

        # Collect or generate associated artifacts
        csr_bytes = csr.public_bytes(serialization.Encoding.PEM)
        prv_bytes = None
        prv_text = None
        if prv_key is not None:
            prv_bytes = prv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

        pub_key = csr.public_key()
        pub_bytes = pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

        cn_list = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)

        if len(cn_list) == 0:
            print(error_style('CSR\'s Common Name (CN) is empty'))
            cleanup()
            sys.exit(11)

        dev_id = cn_list[0].value

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
        device_cert = create_device_credentials.create_device_cert(args.dv, csr, ca_cert, ca_key)

        # save device cert and/or print it
        dev_bytes = device_cert.public_bytes(serialization.Encoding.PEM)
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
    elif args.local_cert_file:
        if not os.path.isfile(args.local_cert_file):
            print(error_style(f'Local certificate file {args.local_cert_file} does not exist'))
            cleanup()
            sys.exit(11)

        with open(args.local_cert_file, 'r') as f:
            dev_bytes = f.read()

        if args.delete:
            print(local_style('Deleting sectag {}...'.format(args.sectag)))
            cred_if.delete_credential(args.sectag, args.cert_type)
        cred_if.write_credential(args.sectag, args.cert_type, dev_bytes)
        if rtt:
            rtt.close()
        cleanup()
        sys.exit(0)
    else:
        print(local_style('Using existing private key and device certificate...'))

    if prv_bytes is not None:
        prv_text = format_cred(prv_bytes, has_shell)
    dev_text = format_cred(dev_bytes, has_shell)

    # write CA cert(s) to device
    nrf_ca_cert_text = format_cred(ca_certs.get_ca_certs(args.coap, stage=args.stage), has_shell)

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

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
