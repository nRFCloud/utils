#!/usr/bin/env python3
#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
import os
import sys
import time
import json
import serial
import argparse
import platform
import ca_certs
import rtt_interface
import nrf_cloud_provision
import modem_credentials_parser
import nrf_cloud_diap
import create_device_credentials
from create_device_credentials import create_device_cert
from serial.tools import list_ports
from colorama import init, Fore, Back, Style
from cryptography import x509
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

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
lf_done = False
plain = False
verbose = False
serial_timeout = 1
IMEI_LEN = 15
DEV_ID_MAX_LEN = 64
MAX_CSV_ROWS = 1000
args = None

def parse_args():
    global verbose

    parser = argparse.ArgumentParser(description="Device Credentials Installer",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--dv", type=int, help="Number of days cert is valid",
                        default=(10 * 365))
    parser.add_argument("--ca", type=str, help="Filepath to your CA cert PEM",
                        default="./ca.pem")
    parser.add_argument("--ca_key", type=str,
                        help="Filepath to your CA's private key PEM",
                        default="./ca_prv_key.pem")
    parser.add_argument("--csv", type=str,
                        help="Filepath to provisioning CSV file",
                        default="provision.csv")
    parser.add_argument("--port", type=str,
                        help="Specify which serial port to open, otherwise pick from list",
                        default=None)
    parser.add_argument("-A", "--all",
                        help="List ports of all types, not just Nordic devices",
                        action='store_true', default=False)
    parser.add_argument("-v", "--verbose",
                        help="bool: Make output verbose",
                        action='store_true', default=False)
    parser.add_argument("-S", "--sectag", type=int,
                        help="integer: Security tag to use", default=16842753)
    parser.add_argument("-P", "--plain",
                        help="bool: Plain output (no colors)",
                        action='store_true', default=False)
    parser.add_argument("-t", "--tags", type=str,
                        help="Pipe (|) delimited device tags; enclose in double quotes", default="")
    parser.add_argument("-T", "--subtype", type=str,
                        help="Custom device type", default='')
    parser.add_argument("-F", "--fwtypes", type=str,
                        help="""
                        Pipe (|) delimited firmware types for FOTA of the set
                        {APP MODEM BOOT SOFTDEVICE BOOTLOADER}; enclose in double quotes
                        """, default="APP|MODEM")
    parser.add_argument("--install_ca",
                        help="Install the AWS root CA cert",
                        action='store_true', default=False)
    parser.add_argument("--coap",
                        help="Install the CoAP server root CA cert in addition to the AWS root CA cert",
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
    parser.add_argument("--jlink_sn", type=int,
                        help="Serial number of J-Link device to use for RTT; optional",
                        default=None)
    parser.add_argument("--prov_hex", type=str, help="Filepath to nRF Provisioning sample hex file",
                        default="")
    parser.add_argument("--api_key", type=str,
                        help="API key",
                        default=None)
    parser.add_argument("--stage", type=str,
                        help="Deployment stage; default is prod (blank)", default="")
    parser.add_argument("--attest", type=str,
                        help="Attestation token base64 string (AT%%ATTESTTOKEN result)",
                        default=None)
    parser.add_argument("--unclaim",
                        help="Perform a call to the UnclaimDevice API before claiming and provisioning",
                        action='store_true', default=False)
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
    ports = []
    dev_types = []
    usb_patterns = [(r'THINGY91', 'Thingy:91', False),
                    (r'PCA20035', 'Thingy:91', False),
                    (r'0009600',  'nRF9160-DK', False),
                    (r'0010509',  'nRF9161-DK', False),
                    (r'NRFBLEGW', 'nRF Cloud Gateway', True)]
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
    ser.write(bytes((line + CMD_TERM_DICT[cmd_term_key]).encode('utf-8')))

def wait_for_prompt(val1=b'uart:~$: ', val2=None, timeout=15, store=None):
    global lf_done
    found = False
    retval = False
    output = None

    ser.flush()

    while not found and timeout != 0:
        line = ser.readline()

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
        print(error_style('String {} not detected in line {}'.format(store,
                                                                    line)))

    if timeout == 0:
        print(error_style('Serial timeout'))

    return retval, output

def cleanup():
    global ser
    if ser:
        ser.close()

def get_attestation_token():
    write_line('at AT%ATTESTTOKEN')
    # include the CRLF in OK because 'OK' could be found in the CSR string
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

def error_exit(err_msg):
    cleanup()
    if err_msg:
        sys.stderr.write(error_style(err_msg))
        sys.stderr.write('\n')
        sys.exit(1)
    else:
        sys.exit('Error... exiting.')

def wait_for_cmd_status(api_key, dev_id, cmd_id):
    global args
    prev_status = ''

    while True:

        time.sleep(5)

        api_res = nrf_cloud_diap.get_provisioning_cmd(api_key, dev_id, cmd_id)

        if api_res.status_code != 200:
            print(error_style('Failed to fetch provisioning cmd result'))
            return None

        api_result_json = api_res.json()

        curr_status = api_result_json.get('status')
        if prev_status != curr_status:
            prev_status = curr_status
            print(local_style('Command status: ' + curr_status))

        if curr_status == "PENDING" or curr_status == "IN_PROGRESS":
            continue

        nrf_cloud_diap.print_api_result("Provisioning cmd result", api_res, args.verbose)

        return api_result_json.get('response')

def main():
    global args
    global plain
    global ser
    global cmd_term_key

    # initialize arguments
    args = parse_args()
    plain = args.plain

    ser = None

    # Set to CRLF for interaction with provisioning sample
    cmd_term_key = 'CRLF'

    # initialize colorama
    if is_windows:
        init(convert = not plain)

    if args.verbose:
        print(send_style('OS detect: Linux={}, MacOS={}, Windows={}\n'.
                          format(is_linux, is_macos, is_windows)))

     # check for valid CA files...
    print(local_style('Loading CA and key...'))
    ca_cert = create_device_credentials.load_ca(args.ca)
    ca_key = create_device_credentials.load_ca_key(args.ca_key)

     # flash prov client
    if args.prov_hex:
        if not os.path.isfile(args.prov_hex):
            error_exit(f'nRF Provisioning sample hex file does not exist: {args.prov_hex}')
        print(local_style('Programming nRF Provisioning sample...'))
        prog_result = rtt_interface.connect_and_program(args.jlink_sn, args.prov_hex)
        if not prog_result:
            error_exit('Failed to program nRF Provisioning sample')
        time.sleep(3)

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
        ser.reset_input_buffer()
        ser.reset_output_buffer()
    except serial.serialutil.SerialException:
        error_exit('Port could not be opened; not a device, or open already')

    # disable modem, just so the provisioning client doesn't try to do anything...
    print(local_style('\nDisabling modem...'))
    write_line('at AT+CFUN=4')
    retval = wait_for_prompt(b'OK')
    if not retval:
        error_exit('Unable to communicate')

    # write CA cert(s) to modem
    if args.install_ca or args.coap:
        print(error_style('\n*** Installing CA certs currently not supported with provisioning sample ***\n'))
        if 0: # TODO: how to write certs via provisioning sample?
            print(local_style('Installing CA cert(s)...'))
            if args.coap:
                modem_ca = ca_certs.nrf_cloud_ca + ca_certs.aws_ca
            else:
                modem_ca = ca_certs.aws_ca

            write_line('at AT%CMNG=0,{},0,"{}"'.format(args.sectag, modem_ca))
            wait_for_prompt(b'OK', b'ERROR')
            time.sleep(1)

    attest_tok = args.attest
    if not attest_tok:
        # get attestation token
        attest_tok = get_attestation_token()
        if not attest_tok:
            error_exit('Failed to obtain attestation token')

    # get device UUID from attestation token
    dev_uuid = modem_credentials_parser.get_device_uuid(attest_tok)
    print(send_style('Device UUID: ' + dev_uuid))

    print(hivis_style('\nProvisioning API URL: ' + nrf_cloud_diap.set_dev_stage(args.stage)))

    if args.unclaim:
        print(local_style('Unclaiming device...'))
        api_res = nrf_cloud_diap.unclaim_device(args.api_key, dev_uuid)
        if api_res.status_code == 204:
            print(local_style(f'...success\n'))
        else:
            nrf_cloud_diap.print_api_result("Unclaim device response", api_res, True)

    # claim device
    print(local_style('Claiming device...'))
    api_res = nrf_cloud_diap.claim_device(args.api_key, attest_tok)
    nrf_cloud_diap.print_api_result("Claim device response", api_res, args.verbose)
    if api_res.status_code != 201:
        error_exit('ClaimDeviceOwnership API call failed')

    # create provisioning command to generate a CSR
    print(local_style('\nCreating provisioning command (CSR)...'))
    api_res = nrf_cloud_diap.create_provisioning_cmd_csr(args.api_key, dev_uuid, sec_tag=args.sectag)
    nrf_cloud_diap.print_api_result("Prov cmd CSR response", api_res, args.verbose)
    if api_res.status_code != 201:
        error_exit('CreateDeviceProvisioningCommand API call failed')

    # get the provisioning cmd ID from the response
    prov_id = None
    res_json = json.loads(api_res.text)
    if not res_json:
        error_exit('Unexpected CreateDeviceProvisioningCommand API response')

    prov_id = res_json.get('id')
    if not prov_id:
        error_exit('Failed to obtain provisioning cmd ID')

    print(hivis_style('\nProvisioning command (CSR) ID: ' + prov_id + '\n'))

    # reset the device since we disabled the modem
    print(send_style('Resetting device'))
    rtt_interface.reset_device(args.jlink_sn)
    # wait for device to boot and process the command
    print(local_style('Waiting for device to process command...'))
    cmd_response = wait_for_cmd_status(args.api_key, dev_uuid, prov_id)

    # get the CSR from the response
    csr_txt = cmd_response.get('certificateSigningRequest').get('csr')
    if csr_txt:
        print(hivis_style('CSR:\n' + csr_txt + '\n'))

    # process the CSR
    modem_credentials_parser.parse_keygen_output(csr_txt)

    # get the public key from the CSR
    csr_bytes = modem_credentials_parser.csr_pem_bytes
    try:
        csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM,
                                                      csr_bytes)
        pub_key = csr.get_pubkey()
    except OpenSSL.crypto.Error:
        cleanup()
        raise RuntimeError("Error loading CSR")

    # create a device cert
    print(local_style('Creating device certificate...'))
    device_cert = create_device_cert(args.dv, csr, pub_key, ca_cert, ca_key)
    dev_cert_pem_bytes = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, device_cert)
    dev_cert_pem_str = dev_cert_pem_bytes.decode()
    print(local_style('Dev cert: \n{}'.format(dev_cert_pem_str)))

    # create provisioning command to install device cert
    print(local_style('\nCreating provisioning command (client cert)...'))
    api_res = nrf_cloud_diap.create_provisioning_cmd_client_cert(args.api_key, dev_uuid,
                                                                 dev_cert_pem_str,
                                                                 sec_tag=args.sectag)
    nrf_cloud_diap.print_api_result("Prov cmd client cert response", api_res, args.verbose)
    if api_res.status_code != 201:
        error_exit('CreateDeviceProvisioningCommand API call failed')

    # get the provisioning cmd ID from the response
    res_json = json.loads(api_res.text)
    if not res_json:
        cleanup()
        error_exit('Unexpected CreateDeviceProvisioningCommand API response')

    prov_id = res_json.get('id')
    if not prov_id:
        error_exit('Failed to obtain provisioning cmd ID')

    # TODO: create provisioning command to install AWS root CA?

    # tell the device to check for commands
    write_line('nrf_provisioning now')
    retval = wait_for_prompt(b'nrf_provisioning: Externally initiated provisioning', b'ERROR',)
    if not retval:
        print(error_style('Did not receive expected response on serial port... continuing'))

    # wait for device to process the command
    print(hivis_style('\nProvisioning command (client cert) ID: ' + prov_id + '\n'))
    cmd_response = wait_for_cmd_status(args.api_key, dev_uuid, prov_id)

    # add the device to nrf cloud account
    print(hivis_style('\nnRF Cloud API URL: ' + nrf_cloud_provision.set_dev_stage(args.stage)))
    print(hivis_style('Adding device to cloud account...'))

    api_res = nrf_cloud_provision.provision_device(args.api_key, dev_uuid, '',
                                                   args.tags, args.fwtypes,
                                                   dev_cert_pem_str)
    nrf_cloud_provision.print_api_result("ProvisionDevices API call response", api_res, args.verbose)

    print(local_style('Done.'))
    cleanup()
    sys.exit(0)

if __name__ == '__main__':
    main()
