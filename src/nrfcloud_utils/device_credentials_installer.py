#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import re
import os
import sys
import semver
import coloredlogs, logging
from nrfcloud_utils import create_device_credentials, ca_certs, modem_credentials_parser
from nrfcloud_utils.cli_helpers import write_file, save_devinfo_csv, save_onboarding_csv, is_linux, is_windows, is_macos, full_encoding
from nrfcloud_utils.cli_helpers import CMD_TERM_DICT, CMD_TYPE_AUTO, CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_TLS_SHELL, parser_add_comms_args
from nrfcredstore.command_interface import ATCommandInterface, TLSCredShellInterface
from nrfcredstore.comms import Comms

from cryptography import x509
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger(__name__)

IMEI_LEN = 15
DEV_ID_MAX_LEN = 64
MIN_REQD_MFW_VER = "1.3.0"
MIN_REQD_MFW_VER_FOR_VERIFY = "1.3.2"

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="Device Credentials Installer",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser_add_comms_args(parser)
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
    parser.add_argument("--id-str", type=str,
                        help="Device ID to use instead of UUID. Will be a prefix if used with --id-imei",
                        default="")
    parser.add_argument("--id-imei",
                        help="Use IMEI for device ID instead of UUID. Add a prefix with --id-str",
                        action='store_true', default=False)
    parser.add_argument("-a", "--append",
                        help="When saving onboarding CSV, append to it",
                        action='store_true', default=False)
    parser.add_argument("-f", "--fileprefix", type=str,
                        help="Prefix for output files (<prefix><UUID>_<sec_tag>_<type>.pem). Selects -s",
                        default="")
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
        logger.error('Unexpected modem firmware version format')
        return None

    return matches[0]

def check_mfw_version(cred_if):
    # get the modem firmware version
    ver = cred_if.get_mfw_version()
    if not ver:
        logger.error('Failed to obtain modem FW version')
        sys.exit(8)

    # display version for reference
    logger.info('Modem FW version: ' + ver)

    # check for required version
    parsed_ver = parse_mfw_ver(ver)

    if parsed_ver is None:
        logger.error('Unexpected modem FW version format... continuing')
    elif semver.Version.parse(parsed_ver).compare(MIN_REQD_MFW_VER) < 0:
        logger.error(f'Modem FW version must be >= {MIN_REQD_MFW_VER}')
        sys.exit(8)
    return ver

# Get a CSR, either by generating one on-device, or generating it locally.
def get_csr(cred_if, custom_dev_id = "", sectag = 0, local = False):
    local_priv_key = None

    if (local):
        csr, local_priv_key = create_device_credentials.create_local_csr(cn = custom_dev_id)
    else:
        # Use AT commands to request a CSR.
        csr_blob = cred_if.get_csr(sectag, f"CN={custom_dev_id}")

        if csr_blob is None:
            logger.error('Failed to obtain CSR from device')
            sys.exit(9)

        csr_bytes, _, _, _ = modem_credentials_parser.parse_keygen_output(csr_blob)
        csr = x509.load_pem_x509_csr(csr_bytes)

    return csr, local_priv_key

def format_cred(cred):
    formatted = cred

    if not isinstance(cred, str):
        formatted = str(cred, encoding=full_encoding)

    formatted = formatted.replace('\r', '')
    formatted = formatted.replace('\n', '\r\n')

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
    # initialize arguments
    args = parse_args(in_args)

    id_len = len(args.id_str)
    if (id_len > DEV_ID_MAX_LEN) or (args.id_imei and ((id_len + IMEI_LEN) > DEV_ID_MAX_LEN)):
        logger.error('Device ID must not exceed {} characters'.format(DEV_ID_MAX_LEN))
        sys.exit(1)

    if args.cmd_type == CMD_TYPE_TLS_SHELL and not (args.local_cert or args.local_cert_file):
        # This check can be removed once the TLS Credential Shell supports CSR generation.
        logger.error(f"cmd_type '{CMD_TYPE_TLS_SHELL}' currently requires --local_cert or --local_cert_file")
        sys.exit(1)

    cmd_type_has_at = args.cmd_type in (CMD_TYPE_AT, CMD_TYPE_AT_SHELL, CMD_TYPE_AUTO)

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
    if cmd_type_has_at:
        cred_if = ATCommandInterface(serial_interface)
        if args.cmd_type == CMD_TYPE_AUTO:
            cred_if.detect_shell_mode()
            logger.debug(f'Detected shell mode: {cred_if.shell}')
        elif args.cmd_type == CMD_TYPE_AT_SHELL:
            cred_if.set_shell_mode(True)
        elif args.rtt:
            cred_if.write_raw('at at_cmd_mode start')

    has_shell = cred_if.shell

    if args.cmd_type == CMD_TYPE_TLS_SHELL:
        cred_if = TLSCredShellInterface(serial_interface)

    # prepare modem so we can interact with security keys
    if (cmd_type_has_at):
        logger.info('Disabling LTE and GNSS...')
        if not cred_if.go_offline():
            logger.error('Unable to communicate')

            sys.exit(6)

    # get the IMEI
    imei = None
    if (cmd_type_has_at):
        imei = cred_if.get_imei()

        if imei is None:
            logger.error('Failed to obtain IMEI')

            sys.exit(7)

        # display the IMEI for reference
        logger.info('Device IMEI: ' + imei)

    # get and verify the modem firmware version
    mfw_ver = None
    if (cmd_type_has_at):
        mfw_ver = check_mfw_version(cred_if)

    # set custom device ID
    custom_dev_id = args.id_str
    if args.id_imei and imei is not None:
        custom_dev_id += imei

    # remove old keys if we are replacing existing ones;
    # it's ok if some or all of these error out -- the slots were empty already
    if args.delete:
        logger.info('Deleting sectag {}...'.format(args.sectag))
        cred_if.delete_credential(args.sectag, 0)
        cred_if.delete_credential(args.sectag, 1)
        cred_if.delete_credential(args.sectag, 2)

    dev_id = custom_dev_id
    prv_bytes, dev_bytes = get_existing_credentials(args, dev_id)

    if prv_bytes is None and args.local_cert_file is None:
        # now get a new certificate signing request (CSR)
        logger.info('Generating private key and requesting a CSR for sectag {}...'.format(args.sectag))

        # Get a CSR
        csr, prv_key = get_csr(cred_if, custom_dev_id, args.sectag, local=args.local_cert)

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
            logger.error('CSR\'s Common Name (CN) is empty')

            sys.exit(11)

        dev_id = cn_list[0].value

        if args.save:
            # Save CSR if desired
            write_file(args.path, args.fileprefix + dev_id + "_csr.pem", csr_bytes)

            # Save private key if available
            if prv_key is not None:
                write_file(args.path, args.fileprefix + dev_id + "_prv.pem", prv_bytes)

        # display CSR info
        logger.info('Device ID: {}'.format(dev_id))
        logger.debug('CSR PEM: {}'.format(csr_bytes))
        logger.debug('Pub key: {}'.format(pub_bytes))

        # check if we have all we need to proceed
        if len(args.ca) == 0 or len(args.ca_key) == 0:
            logger.info('No CA or CA key provided; skipping creating dev cert')

            sys.exit(0)

        # load the user's certificate authority (CA)
        logger.info('Loading CA and key...')
        ca_cert = create_device_credentials.load_ca(args.ca)
        ca_key = create_device_credentials.load_ca_key(args.ca_key)

        # create a device cert
        logger.info('Creating device certificate...')
        device_cert = create_device_credentials.create_device_cert(args.dv, csr, ca_cert, ca_key)

        # save device cert and/or print it
        dev_bytes = device_cert.public_bytes(serialization.Encoding.PEM)

        logger.debug('Dev cert: {}'.format(dev_bytes))
        if args.save:
            logger.info('Saving dev cert...')
            write_file(args.path, args.fileprefix + dev_id + "_crt.pem", dev_bytes)

        # save public key and/or print it
        logger.debug('Pub key: {}'.format(pub_bytes))
        if args.save:
            logger.info('Saving pub key...')
            write_file(args.path, args.fileprefix + dev_id + "_pub.pem", pub_bytes)
    elif args.local_cert_file:
        if not os.path.isfile(args.local_cert_file):
            logger.error(f'Local certificate file {args.local_cert_file} does not exist')

            sys.exit(11)

        with open(args.local_cert_file, 'r') as f:
            dev_bytes = f.read()

        if args.delete:
            logger.info('Deleting sectag {}...'.format(args.sectag))
            cred_if.delete_credential(args.sectag, args.cert_type)
        cred_if.write_credential(args.sectag, args.cert_type, dev_bytes)
        sys.exit(0)
    else:
        logger.info('Using existing private key and device certificate...')

    if prv_bytes is not None:
        prv_text = format_cred(prv_bytes)
    dev_text = format_cred(dev_bytes)

    # write CA cert(s) to device
    nrf_ca_cert_text = format_cred(ca_certs.get_ca_certs(args.coap, stage=args.stage))

    logger.info(f'Writing CA cert(s) to device...')
    cred_if.write_credential(args.sectag, 0, nrf_ca_cert_text)

    # write dev cert to device
    logger.info(f'Writing dev cert to device...')
    cred_if.write_credential(args.sectag, 1, dev_text)

    # If the private key was locally generated, write it to the device
    if prv_text is not None:
        logger.info(f'Writing private key to device...')
        cred_if.write_credential(args.sectag, 2, prv_text)

    if args.verify:
        logger.info('Verifying credentials...')
        check_sha = True

        # AT-command-based SHA check has a modem firmware version requirement
        if (cmd_type_has_at):
            parsed_ver = parse_mfw_ver(mfw_ver)
            if parsed_ver and semver.Version.parse(parsed_ver).compare(MIN_REQD_MFW_VER_FOR_VERIFY) < 0:
                logger.error(f'Skipping SHA verification, modem FW version must be >= {MIN_REQD_MFW_VER_FOR_VERIFY}')
                check_sha = False

        verify_res = verify_credentials(cred_if, args.sectag, nrf_ca_cert_text, dev_text, prv_text,
                                        check_sha=check_sha)
        if not verify_res:
            logger.error('Credential verification: FAIL')

            sys.exit(12)

        logger.info('Credential verification: PASS')

    # write onboarding information to csv if requested by user
    if len(args.csv) > 0:
        logger.info('{} nRF Cloud device onboarding CSV file {}...'.format('Appending' if args.append else 'Saving', args.csv))
        sub_type = ''
        if len(args.subtype) > 0:
            sub_type = args.subtype
        save_onboarding_csv(args.csv, args.append, args.replace, dev_id, sub_type, args.tags,
                            args.fwtypes, dev_bytes)

    # write device ID, modem firmware version, and IMEI to a file
    if args.devinfo:
        save_devinfo_csv(args.devinfo, args.devinfo_append, args.replace, dev_id, mfw_ver, imei)

def verify_credentials(cred_if, sec_tag, ca_cert, client_cert, client_prv=None, check_sha=False):
    # verify the CA cert
    if not verify_credential(cred_if, sec_tag, 0, ca_cert, verify_hash = check_sha):
        return False

    # verify client cert
    if not verify_credential(cred_if, sec_tag, 1, client_cert, verify_hash = check_sha):
        return False

    if not verify_credential(cred_if, sec_tag, 2, client_prv, get_hash = check_sha,
                             verify_hash = (client_prv is not None) and check_sha):
        return False

    return True

def verify_credential(cred_if, sec_tag, cred_type, cred = None, get_hash = False, verify_hash = False):
    if (verify_hash):
        get_hash = True

    cred_type_name = ['CA Cert', 'Client Cert', 'Private Key'][cred_type]
    logger.info(f'Verifying {cred_type_name}')

    if verify_hash and not cred:
        logger.error('Invalid credential string')
        return False

    present, hash = cred_if.check_credential_exists(sec_tag, cred_type, get_hash = get_hash)

    if not present:
        logger.error(f'...{cred_type_name} not found')
        return False

    if get_hash and not hash:
        logger.error(f'...{cred_type_name} has invalid hash')
        return False

    if verify_hash:
        expected_hash = cred_if.calculate_expected_hash(cred)
        if hash != expected_hash:
                logger.error(f'{cred_type_name} - SHA mismatch:')
                logger.error(f'\tDevice    : {hash}')
                logger.error(f'\tCalculated: {expected_hash}')
                return False
    else:
        logger.warning(f'{cred_type_name} exists, SHA not verified')

    return True

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
