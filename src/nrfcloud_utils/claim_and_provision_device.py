#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import sys
import time
import json
import argparse
import platform
import coloredlogs, logging
from nrfcloud_utils import (
    ca_certs,
    rtt_interface,
    nrf_cloud_onboard,
    modem_credentials_parser,
    nrf_cloud_diap,
    create_device_credentials
)
from nrfcloud_utils.cli_helpers import is_linux, is_windows, is_macos
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from nrfcloud_utils.nordic_boards import ask_for_port, get_serial_port

logger = logging.getLogger(__name__)
full_encoding = 'mbcs' if is_windows else 'ascii'
serial_timeout = 1
IMEI_LEN = 15
DEV_ID_MAX_LEN = 64
CSR_ATTR_CN = 'CN='

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="nRF Cloud Claim and Provision",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--dv", type=int, help="Number of days cert is valid",
                        default=(10 * 365))
    parser.add_argument("--ca", type=str, help="Filepath to your CA cert PEM. Not used with '--provisioning-tags'.")
    parser.add_argument("--ca-key", type=str,
                        help="Filepath to your CA's private key PEM. Not used with '--provisioning-tags'.")
    parser.add_argument("--port", type=str,
                        help="Specify which serial port to open, otherwise pick from list",
                        default=None)
    parser.add_argument("--baud", type=int,
                        help="Baud rate for serial port",
                        default=115200)
    parser.add_argument("-A", "--all",
                        help="List ports of all types, not just Nordic devices",
                        action='store_true', default=False)
    parser.add_argument("-S", "--sectag", type=int,
                        help="integer: Security tag to use", default=16842753)
    parser.add_argument("-P", "--plain",
                        help="bool: Plain output (no colors)",
                        action='store_true', default=False)
    parser.add_argument("-t", "--tags", type=str,
                        help="Pipe (|) delimited device tags; enclose in double quotes", default="")
    parser.add_argument("--provisioning-tags", type=str,
                        help="Comma (,) delimited provisioning tags; enclose in double quotes. Example: use \"nrf-cloud-onboarding\" to onboard to nRF Cloud.",
                        default=None)
    parser.add_argument("-T", "--subtype", type=str,
                        help="Custom device type", default='')
    parser.add_argument("-F", "--fwtypes", type=str,
                        help="""
                        Pipe (|) delimited firmware types for FOTA of the set
                        {APP MODEM BOOT SOFTDEVICE BOOTLOADER}; enclose in double quotes
                        """, default="APP|MODEM")
    parser.add_argument("--id-str", type=str,
                        help="Device ID to use instead of UUID. Will be a prefix if used with --id-imei",
                        default="")
    parser.add_argument("--id-imei",
                        help="Use IMEI for device ID instead of UUID. Add a prefix with --id-str",
                        action='store_true', default=False)
    parser.add_argument("--csr-attr", type=str,
                        help="CSR attributes. Do not include CN (common name), the device ID will be used",
                        default="")
    parser.add_argument("--coap",
                        help="Install the CoAP server root CA cert in addition to the AWS root CA cert",
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
    parser.add_argument("--jlink-sn", type=int,
                        help="Serial number of J-Link device to use for RTT; optional",
                        default=None)
    parser.add_argument("--prov-hex", type=str, help="Filepath to nRF Provisioning sample hex file",
                        default="")
    parser.add_argument("--api-key", type=str,
                        help="API key", required=True)
    parser.add_argument("--stage", type=str, help="For internal (Nordic) use only", default="")
    parser.add_argument("--attest", type=str,
                        help="Attestation token base64 string (AT%%ATTESTTOKEN result)",
                        default=None)
    parser.add_argument("--unclaim",
                        help="Perform a call to the UnclaimDevice API before claiming and provisioning",
                        action='store_true', default=False)
    parser.add_argument("--noshell",
                        help="Assume raw AT commands OK -- not using provisioning shell",
                        action='store_true', default=False)
    parser.add_argument('--log-level',
                        default='info',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level'
    )
    args = parser.parse_args(in_args)
    level = getattr(logging, args.log_level.upper(), logging.INFO)
    fmt = '%(levelname)-8s %(message)s'
    coloredlogs.install(level=level, fmt=fmt)
    return args

def write_line(line, hidden = False):
    if not hidden:
        logger.debug('-> {}'.format(line))
    ser.write(bytes((line + '\r\n').encode('utf-8')))

def write_at_cmd(at_cmd_prefix, at_cmd):
    write_line(f'{at_cmd_prefix}{at_cmd}')

def wait_for_prompt(val1=b'uart:~$: ', val2=None, timeout=15, store=None):
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

        if val1 in line:
            found = True
            retval = True
        elif val2 != None and val2 in line:
            found = True
            retval = False
        elif store != None and (store in line or str(store) in str(line)):
            output = line

    if ser:
        ser.flush()
    if store != None and output == None:
        logger.error('String {} not detected in line {}'.format(store, line))

    if timeout == 0:
        logger.error('Serial timeout')
        retval = False

    return retval, output

def cleanup(ser):
    if ser:
        ser.close()

def get_attestation_token(verbose):
    write_at_cmd(at_cmd_prefix, 'AT%ATTESTTOKEN')
    # include the CRLF in OK because 'OK' could be found in the CSR string
    retval, output = wait_for_prompt(b'OK\r', b'ERROR', store=b'%ATTESTTOKEN: ')
    if not retval:
        error_exit(ser, 'ATTESTTOKEN command failed')
    elif output == None:
        error_exit(ser, 'Unable to detect ATTESTTOKEN output')

    # remove quotes
    attest_tok = str(output).split('"')[1]
    logger.info('Attestation token: {}'.format(attest_tok))

    if verbose:
        _, _ = modem_credentials_parser.parse_attesttoken_output(attest_tok)

    return attest_tok

def error_exit(ser, err_msg):
    cleanup(ser)
    if err_msg:
        logger.error(err_msg)
        sys.exit(1)
    else:
        sys.exit('Error... exiting.')

def wait_for_cmd_status(api_key, dev_uuid, cmd_id, verbose=False):
    prev_status = ''

    while True:

        time.sleep(5)

        api_res = nrf_cloud_diap.get_provisioning_cmd(api_key, dev_uuid, cmd_id)

        if api_res.status_code != 200:
            logger.error('Failed to fetch provisioning cmd result')
            return None

        api_result_json = api_res.json()

        curr_status = api_result_json.get('status')
        if prev_status != curr_status:
            prev_status = curr_status
            logger.info('Command status: ' + curr_status)

        if curr_status == "PENDING" or curr_status == "IN_PROGRESS":
            continue

        nrf_cloud_diap.print_api_result("Provisioning cmd result", api_res)

        return api_result_json.get('response')

def main(in_args):
    global ser
    global at_cmd_prefix
    # initialize arguments
    args = parse_args(in_args)

    if args.plain:
        logging.setLoggerClass(logging.Logger)

    ser = None

    # Adjust method to send an AT command
    at_cmd_prefix = '' if args.noshell else 'at '

    # check device ID length
    if args.id_str:
        id_len = len(args.id_str)
        if (id_len > DEV_ID_MAX_LEN) or (args.id_imei and ((id_len + IMEI_LEN) > DEV_ID_MAX_LEN)):
            error_exit(ser, f'Device ID must not exceed {DEV_ID_MAX_LEN} characters')

    if CSR_ATTR_CN in args.csr_attr:
        error_exit(ser, f'Do not include CN in --csr_attr. The device ID will be used as the CN')

    # load local CA cert and key if needed; assume not needed if using provisioning tags
    if args.provisioning_tags is None:
        if args.ca is None or args.ca_key is None:
            error_exit(ser, 'CA cert and key are required for device provisioning without provisioning tags')
         # check for valid CA files...
        logger.info('Loading CA and key...')
        ca_cert = create_device_credentials.load_ca(args.ca)
        ca_key = create_device_credentials.load_ca_key(args.ca_key)
    elif args.ca or args.ca_key:
        logger.info('Ignoring "ca" and "ca-key" because provisioning tags are used.')

     # flash prov client
    if args.prov_hex:
        if not os.path.isfile(args.prov_hex):
            error_exit(ser, f'nRF Provisioning sample hex file does not exist: {args.prov_hex}')
        logger.info('Programming nRF Provisioning sample...')
        prog_result = rtt_interface.connect_and_program(args.jlink_sn, args.prov_hex)
        if not prog_result:
            error_exit(ser, 'Failed to program nRF Provisioning sample')
        time.sleep(3)

    # get a serial port to use
    logger.info('Opening serial port...')
    if args.port:
        port = args.port
    else:
        port = ask_for_port(args.all)
    if port == None:
        sys.exit(1)

    logger.info('Selected serial port: {}'.format(port))

    # try to open the serial port
    ser = get_serial_port(port, args.baud, xonxoff= args.xonxoff, rtscts=(not args.rtscts_off),
                          dsrdtr=args.dsrdtr)

    # disable modem, just so the provisioning client doesn't try to do anything...
    logger.info('Disabling modem...')
    write_at_cmd(at_cmd_prefix, 'AT+CFUN=4')
    retval = wait_for_prompt(b'OK')
    if not retval:
        error_exit(ser, 'Unable to communicate')

    attest_tok = args.attest
    if not attest_tok:
        # get attestation token
        attest_tok = get_attestation_token(args.log_level == 'DEBUG')
        if not attest_tok:
            error_exit(ser, 'Failed to obtain attestation token')

    # get the IMEI
    write_at_cmd(at_cmd_prefix, 'AT+CGSN')
    retval, imei = wait_for_prompt(b'OK', b'ERROR', store=b'\r\n')
    if not retval:
        logger.error('Failed to obtain IMEI')
        imei = None

    if imei:
        # display the IMEI for reference
        imei = str(imei.decode("utf-8"))[:IMEI_LEN]
        logger.info('Device IMEI: ' + imei)
    elif args.id_imei:
        error_exit(ser, 'Cannot format device ID without IMEI')

    # get device UUID from attestation token
    dev_uuid = modem_credentials_parser.get_device_uuid(attest_tok)
    logger.info('Device UUID: ' + dev_uuid)

    logger.warning('Provisioning API URL: ' + nrf_cloud_diap.set_dev_stage(args.stage))

    if args.unclaim:
        logger.info(f'Unclaiming device {dev_uuid}...')
        api_res = nrf_cloud_diap.unclaim_device(args.api_key, dev_uuid)
        if api_res.status_code == 204:
            logger.info(f'...success')
        else:
            nrf_cloud_diap.print_api_result("Unclaim device response", api_res)
            error_exit(ser, 'Failed to unclaim device')

    # claim device
    logger.info('Claiming device...')
    if args.provisioning_tags is not None:
        logger.info(f'with provisioning tags: {args.provisioning_tags}')
    api_res = nrf_cloud_diap.claim_device(args.api_key, attest_tok, args.provisioning_tags)
    nrf_cloud_diap.print_api_result("Claim device response", api_res)
    if api_res.status_code != 201:
        error_exit(ser, 'ClaimDeviceOwnership API call failed')
    elif args.provisioning_tags is not None:
        logger.info('Done. It is assumed the provisioning tags complete the process over the air.')
        cleanup(ser)
        return

    # get the device ID
    device_id = ''
    if args.id_str:
        if args.id_imei:
            device_id = args.id_str + imei
        else:
            device_id = args.id_str
    elif args.id_imei:
        device_id = imei
    else:
        device_id = dev_uuid

    # add the device ID as the CN in the attributes
    csr_attr = f'{CSR_ATTR_CN}{device_id}'
    if args.csr_attr:
        csr_attr = f'{csr_attr},{args.csr_attr}'

    # create provisioning command to generate a CSR
    logger.info('Creating provisioning command (CSR)...')

    api_res = nrf_cloud_diap.create_provisioning_cmd_csr(args.api_key, dev_uuid,
                                                         attributes=csr_attr,
                                                         sec_tag=args.sectag)
    nrf_cloud_diap.print_api_result("Prov cmd CSR response", api_res)
    if api_res.status_code != 201:
        error_exit(ser, 'CreateDeviceProvisioningCommand API call failed')

    # get the provisioning cmd ID from the response
    prov_id = None
    res_json = json.loads(api_res.text)
    if not res_json:
        error_exit(ser, 'Unexpected CreateDeviceProvisioningCommand API response')

    prov_id = res_json.get('id')
    if not prov_id:
        error_exit(ser, 'Failed to obtain provisioning cmd ID')

    logger.warning('Provisioning command (CSR) ID: ' + prov_id)

    # reset the device since we disabled the modem
    logger.debug('Resetting device')
    if args.noshell:
        try:
            rtt_interface.reset_device(args.jlink_sn)
        except:
            logger.error('Failed to reset device using RTT interface')
    else:
        write_line('kernel reboot warm')

    # wait for device to boot and process the command
    logger.info('Waiting for device to process command...')
    cmd_response = wait_for_cmd_status(args.api_key, dev_uuid, prov_id, args.log_level == 'DEBUG')

    # get the CSR from the response
    csr_txt = cmd_response.get('certificateSigningRequest').get('csr')
    if csr_txt == None:
        csr_txt = cmd_response.get('certificateSigningRequest').get('message')
        if csr_txt == None:
            error_exit(ser, 'CSR response not found')
    if csr_txt:
        logger.warning('CSR:' + csr_txt.replace('\\n', '\n'))

    # process the CSR
    csr_bytes, pub_key_bytes, dev_uuid_hex_str, sec_tag_str = \
        modem_credentials_parser.parse_keygen_output(csr_txt)

    # import the CSR
    csr = x509.load_pem_x509_csr(csr_bytes)

    # create a device cert
    logger.info('Creating device certificate...')
    device_cert = create_device_credentials.create_device_cert(args.dv, csr, ca_cert, ca_key)
    dev_cert_pem_bytes = device_cert.public_bytes(serialization.Encoding.PEM)
    dev_cert_pem_str = dev_cert_pem_bytes.decode()
    logger.info('Dev cert: {}'.format(dev_cert_pem_str.replace('\\n', '\n')))

    # create provisioning command to install device cert
    logger.info('Creating provisioning command (client cert)...')
    api_res = nrf_cloud_diap.create_provisioning_cmd_client_cert(args.api_key, dev_uuid,
                                                                 dev_cert_pem_str,
                                                                 sec_tag=args.sectag)
    nrf_cloud_diap.print_api_result("Prov cmd client cert response", api_res)
    if api_res.status_code != 201:
        error_exit(ser, 'CreateDeviceProvisioningCommand API call failed')

    # get the provisioning cmd ID from the response
    res_json = json.loads(api_res.text)
    if not res_json:
        cleanup(ser)
        error_exit(ser, 'Unexpected CreateDeviceProvisioningCommand API response')

    prov_id = res_json.get('id')
    if not prov_id:
        error_exit(ser, 'Failed to obtain provisioning cmd ID')

    # create provisioning command to install server cert
    logger.info('Creating provisioning command (server cert)...')
    server_cert = ca_certs.get_ca_certs(args.coap, args.stage)
    api_res = nrf_cloud_diap.create_provisioning_cmd_server_cert(args.api_key, dev_uuid,
                                                                 server_cert,
                                                                 sec_tag=args.sectag)
    nrf_cloud_diap.print_api_result("Prov cmd client cert response", api_res)
    if api_res.status_code != 201:
        error_exit(ser, 'CreateDeviceProvisioningCommand API call failed')

    # create provisioning finished command
    logger.info('Creating provisioning command (finished)...')
    api_res = nrf_cloud_diap.create_provisioning_cmd_finished(args.api_key, dev_uuid)
    nrf_cloud_diap.print_api_result("Prov cmd finished response", api_res)
    if api_res.status_code != 201:
        error_exit(ser, 'CreateDeviceProvisioningCommand API call failed')

    # get the provisioning finished cmd ID from the response
    res_json = json.loads(api_res.text)
    if not res_json:
        cleanup(ser)
        error_exit(ser, 'Unexpected CreateDeviceProvisioningCommand API response')

    finished_id = res_json.get('id')
    if not finished_id:
        error_exit(ser, 'Failed to obtain provisioning finished cmd ID')

    # tell the device to check for commands
    if not args.noshell:
        write_line('nrf_provisioning now')
        retval = wait_for_prompt(b'nrf_provisioning: Externally initiated provisioning', b'ERROR',)
        if not retval:
            logger.error('Did not receive expected response on serial port... continuing')
    else:
        logger.info('Waiting for provisioning client to check for commands...')

    # wait for device to process the commands
    logger.warning('Provisioning command (client cert) ID: ' + prov_id)
    cmd_response = wait_for_cmd_status(args.api_key, dev_uuid, prov_id, args.log_level == 'DEBUG')

    logger.warning('Provisioning command (finished) ID: ' + finished_id)
    cmd_response = wait_for_cmd_status(args.api_key, dev_uuid, finished_id, args.log_level == 'DEBUG')

    # add the device to nrf cloud account
    logger.warning(f'nRF Cloud API URL: {nrf_cloud_onboard.set_dev_stage(args.stage)}')
    logger.warning(f'Onboarding device \'{device_id}\' to cloud account...')

    api_res = nrf_cloud_onboard.onboard_device(args.api_key, device_id, '',
                                               args.tags, args.fwtypes,
                                               dev_cert_pem_str)
    nrf_cloud_onboard.print_api_result("Onboarding API call response", api_res)

    logger.info('Done.')
    cleanup(ser)

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
