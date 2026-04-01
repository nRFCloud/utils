#!/usr/bin/env python3
#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import re
import sys
import logging
import requests
import coloredlogs
from nrfcredstore.comms import Comms
from nrfcredstore.command_interface import ATCommandInterface

logger = logging.getLogger(__name__)

_TAG_PATTERN = re.compile(r'^[a-zA-Z0-9_.,@\/:#-]{0,799}$')

def _valid_tag(value):
    if not _TAG_PATTERN.match(value):
        raise argparse.ArgumentTypeError(
            f"Invalid tag {value!r}. Must match /[a-zA-Z0-9_.,@\\/:#-]{{0,799}}/"
        )
    return value

DEV_STAGE_DICT = {'dev':     '.dev.',
                  'prod':    '.',
                  '':        '.'}
dev_stage_key = 'prod'

API_URL_START = 'https://api'
API_URL_END = 'nrfcloud.com/v1/'
api_url = API_URL_START + DEV_STAGE_DICT[dev_stage_key] + API_URL_END

def get_nrf93m1_uuid(cred_if):
    """Get or create device UUID for nRF93M1."""
    result = cred_if.at_command('AT%DEVICEUUID', wait_for_result=False)
    if not result:
        logger.error('Failed to send AT%DEVICEUUID command')
        return None

    # Expect response like: %DEVICEUUID: 988234bd-a066-a101-656e-684d6f5adad6
    retval, output = cred_if.comms.expect_response("OK", "ERROR", "%DEVICEUUID:")
    if not retval:
        logger.error('Failed to get device UUID from nRF93M1')
        return None

    # Parse UUID from output
    lines = [line.strip() for line in output.split("\n") if "%DEVICEUUID:" in line]
    if not lines:
        logger.error('UUID not found in response')
        return None

    # Extract UUID (format: "%DEVICEUUID: <uuid>" or "%DEVICEUUID: creating device uuid...")
    uuid_line = lines[-1]  # Get the last line with UUID
    if ':' in uuid_line:
        uuid_str = uuid_line.split(':', 1)[1].strip()
        # Check if it's not a status message
        if 'creating' not in uuid_str.lower() and len(uuid_str) > 30:
            logger.debug(f'Retrieved device UUID: {uuid_str}')
            return uuid_str

    logger.error('Failed to parse UUID from response')
    return None

def get_nrf93m1_identity_key(cred_if):
    """Get or create identity key for nRF93M1."""
    result = cred_if.at_command('AT%CLOUDACCESSKEY', wait_for_result=False)
    if not result:
        logger.error('Failed to send AT%CLOUDACCESSKEY command')
        return None

    # Expect response like: %CLOUDACCESSKEY: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
    retval, output = cred_if.comms.expect_response("OK", "ERROR", "%CLOUDACCESSKEY:")
    if not retval:
        logger.error('Failed to get identity key from nRF93M1')
        return None

    # Parse identity key from output
    lines = [line.strip() for line in output.split("\n") if "%CLOUDACCESSKEY:" in line]
    if not lines:
        logger.error('Identity key not found in response')
        return None

    # Extract identity key (format: "%CLOUDACCESSKEY: <base64_key>")
    identity_key_line = lines[-1]  # Get the last line with key
    if ':' in identity_key_line:
        identity_key_str = identity_key_line.split(':', 1)[1].strip()
        # Check if it's not a status message
        if 'creating' not in identity_key_str.lower() and len(identity_key_str) > 50:
            logger.debug(f'Retrieved device identity key: {identity_key_str}')
            return identity_key_str

    logger.error('Failed to parse identity key from response')
    return None

def parse_args(in_args):
    parser = argparse.ArgumentParser(
        description="nRF93M1 - Onboard Device using Registration token JWT",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--port", type=str, required=True,
                        help="Serial port for the nRF93M1 device (e.g., /dev/ttyACM0 or COM3)")
    parser.add_argument("--baudrate", type=int, help="Serial baudrate", default=115200)
    parser.add_argument("--api-key", type=str, required=True,
                        help="nRF Cloud API key", default="")
    parser.add_argument('--log-level', default='info',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level')
    parser.add_argument("--stage", type=str,
                        choices=['prod', 'dev'],
                        help="For internal (Nordic) use only", default="")
    parser.add_argument("--tags", type=_valid_tag, nargs="+", default=["nRF93M1-EK"],
                        metavar="TAG",
                        help="Tags to assign to the device on nRF Cloud. "
                             "Each tag must match /[a-zA-Z0-9_.,@\\/:#-]{0,799}/")

    args = parser.parse_args(in_args)

    # Setup logging
    if hasattr(args, 'log_level'):
        coloredlogs.install(level=args.log_level.upper(), fmt='%(levelname)-8s %(message)s')
    else:
        coloredlogs.install(level='INFO', fmt='%(levelname)-8s %(message)s')

    return args

def set_dev_stage(stage = ''):
    global api_url
    global dev_stage_key

    if stage in DEV_STAGE_DICT.keys():
        dev_stage_key = stage
        api_url = '{}{}{}'.format(API_URL_START, DEV_STAGE_DICT[dev_stage_key], API_URL_END)
    else:
        logger.error('Invalid stage')

    return api_url

def fetch_tenant_id(api_key):
    hdr = {'Authorization': 'Bearer ' + api_key}
    req = api_url + "account"
    response = requests.get(req, headers=hdr)
    if not response.ok:
        logger.error(f'Failed to fetch tenant ID: HTTP {response.status_code}')
        return None

    try:
        account_info = response.json()
    except ValueError:
        logger.error('Failed to parse account response JSON')
        return None

    tenant_id = account_info.get('team', {}).get('tenantId')
    if not tenant_id:
        logger.error('tenantId not found in account response')
        return None

    return tenant_id

def gen_registration_jwt(cred_if, tenant_id):
    result = cred_if.at_command(f'AT%REGJWT="{tenant_id}"', wait_for_result=False)
    if not result:
        logger.error('Failed to send AT%REGJWT command')
        return None

    retval, output = cred_if.comms.expect_response("OK", "ERROR", "%REGJWT:")
    if not retval:
        logger.error('Failed to get registration JWT from nRF93M1')
        return None

    lines = [line.strip() for line in output.split("\n") if line.strip().startswith("%REGJWT:")]
    if not lines:
        logger.error('Registration JWT not found in response')
        return None

    jwt_str = lines[-1].split(':', 1)[1].strip()
    if not jwt_str:
        logger.error('Registration JWT is empty')
        return None

    logger.debug('Retrieved registration JWT from device')
    return jwt_str

def onboard_device(api_key, dev_id, sub_type, tags, fw_types, onboarding_token):
    hdr = {
        'Authorization': 'Bearer ' + api_key,
        'Accept': 'application/json',
    }

    req = api_url + "devices/" + dev_id

    payload = {
        'onboardingToken': onboarding_token,
        'subType': sub_type,
        'tags': tags,
        'supportedFirmwareTypes': fw_types,
    }

    return requests.post(req, json=payload, headers=hdr)

def main(in_args):
    args = parse_args(in_args)

    if args.stage:
        set_dev_stage(args.stage)

    logger.info('nRF93M1 - Onboard Device using Registration token JWT')
    logger.info(f'Connecting to device on {args.port}...')

    # Initialize serial communication
    try:
        serial_interface = Comms(
            port=args.port,
            baudrate=args.baudrate,
        )
    except Exception as e:
        logger.error(f'Failed to open serial port: {e}')
        sys.exit(1)

    # Create AT command interface
    cred_if = ATCommandInterface(serial_interface)

    try:
        # Verify device is responsive
        logger.info('Checking device connectivity...')
        resp = cred_if.at_command('AT', wait_for_result=True)
        if not resp:
            logger.error('No response from device. Check connection and try again.')
            sys.exit(1)
        logger.info('Device is responsive')

        # Get device UUID
        logger.info('Retrieving device UUID...')
        dev_id = get_nrf93m1_uuid(cred_if)
        if not dev_id:
            logger.error('[Failed] Device UUID')
            sys.exit(2)
        logger.info('[OK] Device UUID')

        # Get identity key
        logger.info('Retrieving identity key...')
        identity_key_base64 = get_nrf93m1_identity_key(cred_if)
        if not identity_key_base64:
            logger.error('[Failed] Device identity key')
            sys.exit(3)
        logger.info('[OK] Device identity key')

        # Based on the stage specified, we query the tenantID from nRF Cloud using the user's API key.
        logger.info('Retrieving tenant ID from nRF Cloud account...')
        tenant_id = fetch_tenant_id(args.api_key)
        if not tenant_id:
            logger.error('[Failed] Tenant ID')
            sys.exit(4)
        logger.info(f'[OK] Tenant ID')

        # Generate the registration JWT on the device using the tenantId
        logger.info('Generating registration JWT...')
        registration_jwt = gen_registration_jwt(cred_if, tenant_id)
        if not registration_jwt:
            logger.error('[Failed] Registration JWT')
            sys.exit(5)
        logger.info('[OK] Registration JWT')

        # Onboard the device
        logger.info('Onboarding device to nRF Cloud...')
        sub_type = "nRF93M1"
        fw_types = ["MODEM"]
        onboard_response = onboard_device(args.api_key, dev_id, sub_type, args.tags, fw_types, registration_jwt)
        if not onboard_response.ok:
            logger.error(f'Failed to onboard device: HTTP {onboard_response.status_code} - {onboard_response.text}')
            sys.exit(6)
        logger.info('[OK] Device onboarded successfully')

    except KeyboardInterrupt:
        logger.warning('Interrupted by user')
        sys.exit(130)
    except Exception as e:
        logger.error(f'Unexpected error: {e}', exc_info=True)
        sys.exit(99)

def run():
    main(sys.argv[1:])


if __name__ == '__main__':
    run()
