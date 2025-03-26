#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import io
import sys
import csv
import time
import json
import argparse
import platform
from nrfcloud_utils import nrf_cloud_diap
from nrfcloud_utils.cli_helpers import error_style, local_style, send_style, hivis_style, init_colorama, cli_disable_styles, is_linux, is_windows, is_macos

verbose = False
args = None
IMEI_LEN = 15
MAX_CSV_ROWS = 1000

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="nRF Cloud Claim Devices",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("--csv", type=str,
                        help="Filepath to attestation token CSV file",
                        default="attestation_tokens.csv")
    parser.add_argument("-v", "--verbose",
                        help="bool: Make output verbose",
                        action='store_true', default=False)
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
    args = parser.parse_args(in_args)
    return args

def bulk_claim(api_key, array_of_claims, verbose):
    # convert arrays of claims to properly formatted csv string
    csv_out = io.StringIO()
    csv_writer = csv.writer(csv_out, lineterminator='\n', quoting=csv.QUOTE_ALL)
    csv_writer.writerows(array_of_claims)
    csv_str = csv_out.getvalue()
    if verbose:
        print(f'Claim payload:\n{str(csv_str)}')

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
        print(error_style('Error accessing json'))
        pass

    if api_res.status_code in {200, 201}:
        print(local_style(f'--> Accepted; claimed {len(claimed)}:'))
        print(local_style(f'    {claimed}'))
    else:
        print(error_style(f'--> Error {api_res.status_code} on {len(failed)} rows:'))
        print(error_style(f'    {failed}'))
        print(error_style(f'    {api_res.text}'))

    return len(claimed)

def error_exit(err_msg):
    cleanup()
    if err_msg:
        sys.stderr.write(error_style(err_msg))
        sys.stderr.write('\n')
        sys.exit(1)
    else:
        sys.exit('Error... exiting.')

def main(in_args):
    # initialize arguments
    args = parse_args(in_args)
    if args.plain:
        cli_disable_styles()

    # initialize colorama
    if is_windows:
        init_colorama()

    if args.verbose:
        print(send_style('OS detect: Linux={}, MacOS={}, Windows={}\n'.
                          format(is_linux, is_macos, is_windows)))

    print(hivis_style('\nProvisioning API URL: ' + nrf_cloud_diap.set_dev_stage(args.stage)))

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
                if not args.verbose:
                    print(local_style(f'{row_count}. Claiming {imei}, {uuid}'))
                else:
                    print(local_style(f'{row_count}. Claiming {imei}, {uuid}, {date_time}, {attest_tok}, with tags: "{args.provisioning_tags}"'))

                # build an array with the attestation token and any specified provisioning tags
                # provisioning tags must be enclosed in quotes so they are treated as one field later
                new_row = [attest_tok]
                if args.provisioning_tags is not None:
                    new_row.append(args.provisioning_tags)

                # build up array of rows
                bulk_prov_csv.append(new_row)

                # if we are at the limit, claim them
                if row_count == MAX_CSV_ROWS:
                    pass_count += bulk_claim(args.api_key, bulk_prov_csv, args.verbose)
                    bulk_prov_csv = list()
                    row_count = 0

            # claim and remaining devices
            if len(bulk_prov_csv) > 0:
                pass_count += bulk_claim(args.api_key, bulk_prov_csv, args.verbose)

            print(hivis_style(f'\nDone. {pass_count} of {total_rows} devices claimed.'))
            csvfile.close()

    except OSError:
        print(error_style(f'Error opening (read) file {args.csv}'))

    sys.exit(0)

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
