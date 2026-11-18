#!/usr/bin/env python3
#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
import sys
import time
import logging
import requests
import coloredlogs
from urllib.parse import quote
from nrfcredstore.comms import Comms
from nrfcredstore.command_interface import ATCommandInterface
from nrfcloud_utils.cli_helpers import USER_AGENT, save_device_create_csv

logger = logging.getLogger(__name__)

API_URL = 'https://api.nrfcloud.com/v1/'
MEMFAULT_API_URL = 'https://api.memfault.com/api/v0/'
NICKNAME_MAX_LEN = 128
# A newly onboarded device takes a few seconds to appear in the project
NICKNAME_TIMEOUT_SECS = 30
NICKNAME_RETRY_SECS = 2

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

def get_parser():
    parser = argparse.ArgumentParser(
        description="nRF93M1 - Onboard Device using Registration token JWT",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        add_help=False
    )
    parser.add_argument("--port", type=str, required=True,
                        help="Serial port for the nRF93M1 device (e.g., /dev/ttyACM0 or COM3)")
    parser.add_argument("--baudrate", type=int, help="Serial baudrate", default=115200)
    parser.add_argument("--org-token", type=str,
                        default=os.environ.get("MEMFAULT_ORG_TOKEN"),
                        help="Organization auth token (OAT) with device:write permission "
                             "[env: MEMFAULT_ORG_TOKEN]")
    parser.add_argument("--org", type=str, default=os.environ.get("MEMFAULT_ORG"),
                        help="Organization slug [env: MEMFAULT_ORG]")
    parser.add_argument("--project", type=str, default=os.environ.get("MEMFAULT_PROJECT", "nrf-project"),
                        help="Project slug [env: MEMFAULT_PROJECT]")
    parser.add_argument("--csv", type=str, default=None,
                        help="Instead of onboarding the device, save its device ID and registration JWT "
                             "to this CSV file for `nrfcloud device create`. The device is added to "
                             "an existing file")
    parser.add_argument("--tenant-id", type=str, default=None,
                        help="nRF Cloud tenant ID (team ID) of your organization, to use instead of "
                             "looking it up with the OAT. With --csv, the script then works offline "
                             "and needs no OAT")
    parser.add_argument("--nickname", type=str, default=None,
                        help=f"Nickname to give the device in nRF Cloud once it is onboarded, at most "
                             f"{NICKNAME_MAX_LEN} characters. Cannot be used with --csv")
    parser.add_argument('--log-level', default='info',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level')
    return parser

def parse_args(in_args):
    _p = get_parser()
    parser = argparse.ArgumentParser(parents=[_p], description=_p.description, formatter_class=_p.formatter_class)
    args = parser.parse_args(in_args)
    # The OAT is used to look up the tenant ID and to onboard the device
    required = []
    if not (args.csv and args.tenant_id):
        required += [('--org-token', args.org_token), ('--org', args.org)]
    if not args.csv:
        required.append(('--project', args.project))
    missing = [n for n, v in required if not v]
    if missing:
        message = 'missing required argument(s): ' + ', '.join(missing)
        if args.csv:
            message += '; they are required to look up the tenant ID unless you pass --tenant-id'
        parser.error(message)

    if args.nickname is not None:
        if args.csv:
            parser.error('--nickname cannot be used with --csv, which does not onboard the device')
        if len(args.nickname) > NICKNAME_MAX_LEN:
            parser.error(f'--nickname must be at most {NICKNAME_MAX_LEN} characters')

    # Setup logging
    if hasattr(args, 'log_level'):
        coloredlogs.install(level=args.log_level.upper(), fmt='%(levelname)-8s %(message)s')
    else:
        coloredlogs.install(level='INFO', fmt='%(levelname)-8s %(message)s')

    return args

def fetch_tenant_id(org_token, org):
    hdr = {'Authorization': 'Bearer ' + org_token, 'User-Agent': USER_AGENT}
    req = MEMFAULT_API_URL + "organizations/" + org
    response = requests.get(req, headers=hdr)
    if not response.ok:
        logger.error(f'Failed to fetch tenant ID: HTTP {response.status_code}')
        return None

    try:
        org_info = response.json()
    except ValueError:
        logger.error('Failed to parse organization response JSON')
        return None

    tenant_id = (org_info.get('data') or {}).get('nrfcloud_team_id')
    if not tenant_id:
        logger.error('nrfcloud_team_id not found in organization response')
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

def save_registration_jwt_csv(csv_filename, dev_id, registration_jwt):
    """Add the device to a CSV for `nrfcloud device create`, replacing its row if it has one."""
    return save_device_create_csv(csv_filename, 'onboardingToken', dev_id, registration_jwt)

def onboard_device(org_token, org, project, onboarding_token):
    hdr = {
        'Authorization': 'Bearer ' + org_token,
        'Accept': 'application/json',
        'User-Agent': USER_AGENT,
    }

    req = f"{API_URL}organizations/{org}/projects/{project}/long-range/devices"

    # The API rejects any other field (subType, tags, ...) with 422.
    # deviceId is optional; nRF Cloud reads it from the token.
    payload = {'onboardingToken': onboarding_token}

    return requests.post(req, json=payload, headers=hdr)

def set_device_nickname(org_token, org, project, dev_id, nickname):
    hdr = {
        'Authorization': 'Bearer ' + org_token,
        'Accept': 'application/json',
        'User-Agent': USER_AGENT,
    }

    req = f"{MEMFAULT_API_URL}organizations/{org}/projects/{project}/devices/{quote(dev_id, safe='')}"

    deadline = time.monotonic() + NICKNAME_TIMEOUT_SECS
    while True:
        response = requests.patch(req, json={'nickname': nickname}, headers=hdr)
        if response.status_code != 404 or time.monotonic() >= deadline:
            return response
        logger.debug('Device not found yet, retrying...')
        time.sleep(NICKNAME_RETRY_SECS)

def main(in_args):
    args = parse_args(in_args)

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

        if args.tenant_id:
            tenant_id = args.tenant_id
        else:
            # Query the tenant ID (nRF Cloud team ID) of the organization using the OAT.
            logger.info('Retrieving tenant ID from organization...')
            tenant_id = fetch_tenant_id(args.org_token, args.org)
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

        if args.csv:
            # Collect the registration JWT; the devices are onboarded later, in bulk
            logger.info('Saving registration JWT...')
            if not save_registration_jwt_csv(args.csv, dev_id, registration_jwt):
                logger.error('[Failed] Registration JWT CSV')
                sys.exit(7)
            logger.info(f'[OK] Device not onboarded yet; run `nrfcloud device create --csv {args.csv}`')
            return

        # Onboard the device
        logger.info('Onboarding device to nRF Cloud...')
        onboard_response = onboard_device(args.org_token, args.org, args.project,
                                          registration_jwt)
        if not onboard_response.ok:
            logger.error(f'Failed to onboard device: HTTP {onboard_response.status_code} - {onboard_response.text}')
            sys.exit(6)
        logger.info('[OK] Device onboarded successfully')

        if args.nickname is not None:
            logger.info('Setting device nickname...')
            nickname_response = set_device_nickname(args.org_token, args.org, args.project,
                                                    dev_id, args.nickname)
            if not nickname_response.ok:
                logger.error(f'Device is onboarded, but setting its nickname failed: '
                             f'HTTP {nickname_response.status_code} - {nickname_response.text}')
                sys.exit(8)
            logger.info('[OK] Device nickname')

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
