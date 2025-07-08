#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
import sys
import time
import json
import argparse
import coloredlogs, logging
from nrfcloud_utils import (
    ca_certs,
    nrf_cloud_onboard,
    modem_credentials_parser,
    nrf_cloud_diap,
    create_device_credentials
)
from nrfcloud_utils.cli_helpers import is_linux, is_windows, is_macos
from nrfcloud_utils.cli_helpers import CMD_TERM_DICT, CMD_TYPE_AUTO, CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_TLS_SHELL, parser_add_comms_args
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from nrfcredstore.comms import Comms
from nrfcredstore.command_interface import ATCommandInterface

logger = logging.getLogger(__name__)

IMEI_LEN = 15
DEV_ID_MAX_LEN = 64

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="nRF Cloud Claim and Provision",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser_add_comms_args(parser)
    parser.add_argument("--dv", type=int, help="Number of days cert is valid",
                        default=(10 * 365))
    parser.add_argument("--ca", type=str, help="Filepath to your CA cert PEM. Not used with '--provisioning-tags'.")
    parser.add_argument("--ca-key", type=str,
                        help="Filepath to your CA's private key PEM. Not used with '--provisioning-tags'.")
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
    parser.add_argument('--log-level',
                        default='info',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level'
    )
    args = parser.parse_args(in_args)
    if args.plain:
        logging.basicConfig(level=args.log_level.upper())
    else:
        coloredlogs.install(level=args.log_level.upper(), fmt='%(levelname)-8s %(message)s')
    return args

def error_exit(err_msg):
    if err_msg:
        logger.error(err_msg)
    sys.exit(1)

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

    # initialize arguments
    args = parse_args(in_args)

    # check device ID length
    if args.id_str:
        id_len = len(args.id_str)
        if (id_len > DEV_ID_MAX_LEN) or (args.id_imei and ((id_len + IMEI_LEN) > DEV_ID_MAX_LEN)):
            error_exit(f'Device ID must not exceed {DEV_ID_MAX_LEN} characters')

    if 'CN=' in args.csr_attr:
        error_exit(f'Do not include CN in --csr_attr. The device ID will be used as the CN')

    # load local CA cert and key if needed; assume not needed if using provisioning tags
    if args.provisioning_tags is None:
        if args.ca is None or args.ca_key is None:
            error_exit('CA cert and key are required for device provisioning without provisioning tags')
         # check for valid CA files...
        logger.info('Loading CA and key...')
        ca_cert = create_device_credentials.load_ca(args.ca)
        ca_key = create_device_credentials.load_ca_key(args.ca_key)
    elif args.ca or args.ca_key:
        logger.info('Ignoring "ca" and "ca-key" because provisioning tags are used.')

    if args.cmd_type not in (CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_AUTO):
        error_exit('Attestation tokens are only supported on devices with AT command support')

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

    cred_if = None
    cred_if = ATCommandInterface(serial_interface)
    if args.cmd_type == CMD_TYPE_AUTO:
        cred_if.detect_shell_mode()
    elif args.cmd_type == CMD_TYPE_AT_SHELL:
        cred_if.set_shell_mode(True)
    elif args.rtt:
        cred_if.write_raw('at at_cmd_mode start')

    attest_tok = args.attest
    if not attest_tok:
        # get attestation token
        attest_tok = cred_if.get_attestation_token()
        if not attest_tok:
            error_exit('Failed to obtain attestation token')

    # get the IMEI
    imei = cred_if.get_imei()

    if imei:
        # display the IMEI for reference
        logger.info('Device IMEI: ' + imei)
    elif args.id_imei:
        error_exit('Cannot format device ID without IMEI')

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
            logger.info("Device may not have been claimed before, continuing...")

    # claim device
    logger.info('Claiming device...')
    if args.provisioning_tags is not None:
        if args.provisioning_tags == "nrf-cloud-onboarding":
            nrf_cloud_diap.ensure_nrfcloud_provisioning_rule(args.api_key, args.sectag)
        logger.info(f'with provisioning tags: {args.provisioning_tags}')
    api_res = nrf_cloud_diap.claim_device(args.api_key, attest_tok, args.provisioning_tags)
    nrf_cloud_diap.print_api_result("Claim device response", api_res)
    if api_res.status_code != 201:
        error_exit('ClaimDeviceOwnership API call failed')
    elif args.provisioning_tags is not None:
        logger.info('Done. It is assumed the provisioning tags complete the process over the air.')
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
    csr_attr = f'CN={device_id}'
    if args.csr_attr:
        csr_attr = f'{csr_attr},{args.csr_attr}'

    # create provisioning command to generate a CSR
    logger.info('Creating provisioning command (CSR)...')

    api_res = nrf_cloud_diap.create_provisioning_cmd_csr(args.api_key, dev_uuid,
                                                         attributes=csr_attr,
                                                         sec_tag=args.sectag)
    nrf_cloud_diap.print_api_result("Prov cmd CSR response", api_res)
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

    logger.warning('Provisioning command (CSR) ID: ' + prov_id)

    # reset the device since we disabled the modem
    logger.debug('Resetting device')
    if args.rtt:
        serial_interface.reset_device()
    elif args.cmd_type == CMD_TYPE_AT_SHELL:
        cred_if.write_raw('kernel reboot warm')

    # wait for device to boot and process the command
    logger.info('Waiting for device to process command...')
    cmd_response = wait_for_cmd_status(args.api_key, dev_uuid, prov_id, args.log_level == 'DEBUG')

    # get the CSR from the response
    csr_txt = cmd_response.get('certificateSigningRequest').get('csr')
    if csr_txt == None:
        csr_txt = cmd_response.get('certificateSigningRequest').get('message')
        if csr_txt == None:
            error_exit('CSR response not found')
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
        error_exit('CreateDeviceProvisioningCommand API call failed')

    # get the provisioning cmd ID from the response
    res_json = json.loads(api_res.text)
    if not res_json:
        error_exit('Unexpected CreateDeviceProvisioningCommand API response')

    prov_id = res_json.get('id')
    if not prov_id:
        error_exit('Failed to obtain provisioning cmd ID')

    # create provisioning command to install server cert
    logger.info('Creating provisioning command (server cert)...')
    server_cert = ca_certs.get_ca_certs(args.coap, args.stage)
    api_res = nrf_cloud_diap.create_provisioning_cmd_server_cert(args.api_key, dev_uuid,
                                                                 server_cert,
                                                                 sec_tag=args.sectag)
    nrf_cloud_diap.print_api_result("Prov cmd client cert response", api_res)
    if api_res.status_code != 201:
        error_exit('CreateDeviceProvisioningCommand API call failed')

    # create provisioning finished command
    logger.info('Creating provisioning command (finished)...')
    api_res = nrf_cloud_diap.create_provisioning_cmd_finished(args.api_key, dev_uuid)
    nrf_cloud_diap.print_api_result("Prov cmd finished response", api_res)
    if api_res.status_code != 201:
        error_exit('CreateDeviceProvisioningCommand API call failed')

    # get the provisioning finished cmd ID from the response
    res_json = json.loads(api_res.text)
    if not res_json:
        error_exit('Unexpected CreateDeviceProvisioningCommand API response')

    finished_id = res_json.get('id')
    if not finished_id:
        error_exit('Failed to obtain provisioning finished cmd ID')

    # tell the device to check for commands
    if args.cmd_type == CMD_TYPE_AT_SHELL:
        cred_if.write_raw('nrf_provisioning now')
        retval = serial_interface.expect_response('nrf_provisioning: Externally initiated provisioning', 'ERROR')
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

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
