#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
import io
import sys
import csv
import argparse
import coloredlogs, logging
from nrfcloud_utils import nrf_cloud_diap
from nrfcloud_utils.cli_helpers import is_linux, is_windows, is_macos

logger = logging.getLogger(__name__)

args = None
IMEI_LEN = 15
MAX_CSV_ROWS = 1000

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="nRF Cloud Claim Devices",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--csv", type=str,
                        help="Filepath to attestation token CSV file",
                        default="attestation_tokens.csv")
    parser.add_argument("-P", "--plain",
                        help="bool: Plain output (no colors)",
                        action='store_true', default=False)
    parser.add_argument("--provisioning-tags", type=str,
                        help="Comma (,) delimited provisioning tags; enclose in double quotes. Example: use \"nrf-cloud-onboarding\" to onboard to nRF Cloud.",
                        default=None)
    parser.add_argument("--api-key", type=str,
                        help="API key",
                        default=None, required=True)
    parser.add_argument("--stage", type=str, help="For internal (Nordic) use only", default="")
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

def bulk_claim(api_key, array_of_claims):
    # convert arrays of claims to properly formatted csv string
    csv_out = io.StringIO()
    csv_writer = csv.writer(csv_out, lineterminator='\n', quoting=csv.QUOTE_ALL)
    csv_writer.writerows(array_of_claims)
    csv_str = csv_out.getvalue()
    logger.debug(f'Claim payload:\n{str(csv_str)}')

    # bulk claim then process response
    api_res = nrf_cloud_diap.bulk_claim_devices(api_key, csv_str)
    claimed = list()
    failed = list()
    try:
        json = api_res.json()
        if 'claimedIds' in json:
            claimed = json['claimedIds']
        if 'failed' in json:
            failed = json['failed']
    except:
        logger.error('Error accessing json')
        pass

    if api_res.status_code in {200, 201}:
        logger.info(f'--> Accepted; claimed {len(claimed)}:')
        logger.info(f'    {claimed}')
    else:
        logger.error(f'--> Error {api_res.status_code} on {len(failed)} rows:')
        logger.error(f'    {failed}')
        logger.error(f'    {api_res.text}')

    return len(claimed)

def main(in_args):
    # initialize arguments
    args = parse_args(in_args)

    logger.warning('Provisioning API URL: ' + nrf_cloud_diap.set_dev_stage(args.stage))

    try:
        with open(args.csv) as csvfile:
            csv_contents = csv.reader(csvfile, delimiter=',')

            row_count = 0
            pass_count = 0
            total_rows = 0
            bulk_prov_csv = list()
            for row in csv_contents:
                row_count += 1
                total_rows += 1

                # pull fields out of csv
                imei, uuid, attest_tok, date_time = row[:4]
                logger.info(f'{row_count}. Claiming {imei}, {uuid}, {date_time}, {attest_tok}, with tags: "{args.provisioning_tags}"')

                # build an array with the attestation token and any specified provisioning tags
                # provisioning tags must be enclosed in quotes so they are treated as one field later
                new_row = [attest_tok]
                if args.provisioning_tags is not None:
                    new_row.append(args.provisioning_tags)

                # build up array of rows
                bulk_prov_csv.append(new_row)

                # if we are at the limit, claim them
                if row_count == MAX_CSV_ROWS:
                    pass_count += bulk_claim(args.api_key, bulk_prov_csv)
                    bulk_prov_csv = list()
                    row_count = 0

            # claim and remaining devices
            if len(bulk_prov_csv) > 0:
                pass_count += bulk_claim(args.api_key, bulk_prov_csv)

            logger.warning(f'Done. {pass_count} of {total_rows} devices claimed.')
            csvfile.close()

    except OSError:
        logger.error(f'Error opening (read) file {args.csv}')

    sys.exit(0)

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
