#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import sys
import jwt
from datetime import datetime, timezone, timedelta
from os import path
import coloredlogs, logging

logger = logging.getLogger(__name__)

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="Create JWT for proxy (cloud-to-cloud) requests to nRF Cloud",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--key", type=str, required=True,
                        help="Required filepath to the ES256 private key PEM (Service Key) used for JWT signing. \
                              Obtained from https://nrfcloud.com/#/manage-services",
                        default=None)

    parser.add_argument("--team-id", type=str, required=True,
                        help="Required nRF Cloud Team ID; added to the aud claim. \
                              Your Team ID can be found at https://nrfcloud.com/#/teams",
                        default=None)

    parser.add_argument("--dev-id", type=str, required=False,
                        help="Optional Device ID; added to the sub claim. \
                              This can be added if the associated request is servicing a single device",
                        default=None)

    parser.add_argument("--days-valid", type=int, required=False,
                        help="The number of days for which the JWT will be valid. \
                              Zero indicates no expiration.",
                        default=30)

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

def create_nrf_cloud_jwt(prv_key_bytes, team_id, dev_id, days_valid):

    if not team_id:
        logger.error("Team ID not provided")
        return None

    if not prv_key_bytes:
        logger.error("Private key not provided")
        return None

    payload = {"aud" : team_id}

    if dev_id:
        payload["sub"] = dev_id

    if days_valid > 0:
        payload["exp"] = datetime.now(tz=timezone.utc) + timedelta(days=days_valid)

    try:
        encoded_jwt = jwt.encode(payload, prv_key_bytes, algorithm="ES256")
    except ValueError:
        logger.error("Exception encoding JWT. Verify that the provided key is ES256 and in PEM format.")
        return None

    return encoded_jwt

def read_private_key(key_path):
    key_abspath = path.abspath(key_path)

    if not path.isfile(key_abspath):
        logger.error("Private key not found: " + key_abspath)
        return None

    try:
        key_file = open(key_abspath, "rt")
    except OSError:
        logger.error("Error opening private key file: " + key_abspath)
        return None

    key_bytes = key_file.read()
    key_file.close()

    return key_bytes

def main(in_args):
    args = parse_args(in_args)

    # Read the private key PEM which will be used to sign the JWT
    key_bytes = read_private_key(args.key)

    # Encode the JWT
    encoded_jwt = create_nrf_cloud_jwt(key_bytes, args.team_id, args.dev_id, args.days_valid)
    if not encoded_jwt:
        logger.error("Error creating JWT")
        return

    # Print the header data
    logger.info(f"Header: {jwt.get_unverified_header(encoded_jwt)}")

    # Print the payload data
    logger.info("Payload: {}".format(jwt.decode(encoded_jwt, options={'verify_signature': False})))

    # Print the encoded JWT
    logger.info(f"JWT: {encoded_jwt}")

    return

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
