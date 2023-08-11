#!/usr/bin/env python3
#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

import argparse
import sys
import requests
import csv
import time
import json
import requests
import os
import io
from os import path
from os import makedirs
from ast import literal_eval
from enum import Enum

class ProvisionResult(Enum):
    PERFORMED_SUCCESSFULLY = 0
    PERFORMED_WITH_ERRORS = 1
    PERFORMED_RESULTS_NOT_CONFIRMED = 2
    NOT_PERFORMED_NO_API_KEY = 4
    NOT_PERFORMED_BAD_FILE_PATH = 5
    NOT_PERFORMED_INVALID_CSV_FORMAT = 6
    NOT_PERFORMED_DEVICE_EXISTS = 7
    NOT_PERFORMED_DEV_CHK_FAILED = 8
    NOT_PERFORMED_PROVDEV_CALL_FAILED = 9

from modem_credentials_parser import write_file

DEV_STAGE_DICT = {'dev':     '.dev.',
                  'beta':    '.beta.',
                  'prod':    '.',
                  '':        '.',
                  'feature': '.feature.'}
dev_stage_key = 'prod'

API_URL_START = 'https://api'
API_URL_END = 'nrfcloud.com/v1/'
api_url = API_URL_START + DEV_STAGE_DICT[dev_stage_key] + API_URL_END

ERR_FIND_FIRST_STR = "(1-based)]: "
ERR_FIND_END_STR = ".\"}"
MAX_CSV_ROWS = 1000
DEV_LIST_ID_IDX = 0
DEV_LIST_RES_IDX = 1
BULK_OP_REQ_ID = "bulkOpsRequestId"

def parse_args():
    parser = argparse.ArgumentParser(description="nRF Cloud Device Provisioning",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--apikey", type=str, required=True,
                        help="nRF Cloud API key", default="")
    parser.add_argument("--chk", action='store_true', default=False,
                        help="For single device provisioning, check if device exists before provisioning")
    parser.add_argument("--csv", type=str,
                        help="Filepath to provisioning CSV file", default="provision.csv")
    parser.add_argument("--res", type=str,
                        help="Filepath where the CSV-formatted provisioning result(s) will be saved", default="")
    parser.add_argument("--devinfo", type=str,
                        help="Optional filepath to device info CSV file containing device ID, installed modem FW version, and IMEI",
                        default=None)
    parser.add_argument("--set_mfwv",
                        help="Set the modem FW version in the device's shadow. Requires --devinfo.",
                        action='store_true', default=False)
    parser.add_argument("--name_imei",
                        help="Use the device's IMEI as the friendly name. Requires --devinfo.",
                        action='store_true', default=False)
    parser.add_argument("--name_prefix", type=str,
                        help="Prefix string for IMEI friendly name",
                        default=None)

    args = parser.parse_args()
    return args

def set_dev_stage(stage = ''):
    global api_url
    global dev_stage_key

    if stage in DEV_STAGE_DICT.keys():
        dev_stage_key = stage
        api_url = '{}{}{}'.format(API_URL_START, DEV_STAGE_DICT[dev_stage_key], API_URL_END)
    else:
        print('Invalid stage')

    return api_url

def get_bulk_ops_result(api_key, bulk_ops_req_id):
    hdr = {'Authorization': 'Bearer ' + api_key}
    req = api_url + "bulk-ops-requests/" + bulk_ops_req_id
    return requests.get(req, headers=hdr)

def update_device_shadow(api_key, device_id, json_payload):
    hdr = {'Authorization': 'Bearer ' + api_key}
    req = api_url + "devices/" + device_id + "/state"
    return requests.patch(req, json=json_payload, headers=hdr)

def fetch_device(api_key, device_id):
    hdr = {'Authorization': 'Bearer ' + api_key}
    req = api_url + "devices/" + device_id
    return requests.get(req, headers=hdr)

def update_device_name(api_key, device_id, name):
    hdr = {'Authorization': 'Bearer ' + api_key}
    req = api_url + "devices/" + device_id + "/name"
    json_payload = [name]
    return requests.put(req, json=json_payload, headers=hdr)

def provision_device(api_key, dev_id, sub_type, tags, fw_types, cert_pem_str):
    hdr = {'Authorization': 'Bearer ' + api_key,
           'content-type' : 'text/plain',
           'Accept-Encoding' : '*'}

    req = api_url + "devices"

    payload = f'{dev_id},{sub_type},{tags},{fw_types},\"{cert_pem_str}\"\n'

    return requests.post(req, data=payload, headers=hdr)

def provision_devices(api_key, csv_filepath):
    hdr = {'Authorization': 'Bearer ' + api_key,
           'content-type' : 'text/csv',
           'Accept-Encoding' : '*'}

    req = api_url + "devices"

    with open(csv_filepath,'rb') as payload:
        api_result = requests.post(req, data=payload, headers=hdr)
        payload.close()
        return api_result

def print_api_result(custom_text, api_result, print_response_txt):
    print("{}: {} - {}".format(custom_text, api_result.status_code, api_result.reason))
    if print_response_txt:
        print("Response: {}".format(api_result.text))

def get_provisioning_results(api_key, bulk_ops_req_id):

    print("Fetching results for {}: {}".format(BULK_OP_REQ_ID, bulk_ops_req_id))

    while True:
        print("Waiting 5s...")
        time.sleep(5)

        api_result = get_bulk_ops_result(api_key, bulk_ops_req_id)

        if api_result.status_code != 200:
            print("Failed to fetch provisioning result")
            return None

        api_result_json = api_result.json()

        print("Provisioning status: " + api_result_json["status"])

        if api_result_json["status"] == "IN_PROGRESS" or api_result_json["status"] == "PENDING":
            continue

        return api_result


def parse_err_msg(err_str):

    # Until the error msg is fixed by the cloud, we have to do some extra parsing...
    # See IRIS-3758

    # Search for the end of the first item, which is just a general error msg
    err_begin_idx = err_str.find(ERR_FIND_FIRST_STR)

    # Find the end of the detailed error list, which has escaped quotes
    err_end_idx = err_str.rfind(ERR_FIND_END_STR)

    if err_begin_idx == -1 or err_end_idx == -1:
        print("Unhandled error response format")
        return

    # Inspect the first item for total number of reported errors
    err_begin_str = err_str[:err_begin_idx]
    err_cnt = 0
    for s in err_begin_str.split():
        if s.isdigit():
            err_cnt = int(s)
            break

    if err_cnt == 0:
        print("Warning: no errors reported")

    # Get the start of the detailed error list, which is after the first item
    err_json_str = err_str[ (err_begin_idx + len(ERR_FIND_FIRST_STR)) : err_end_idx]

    # Fix the escaped quotes
    err_json_str = literal_eval("'%s'" % err_json_str)

    # Return the error count and the json formatted error dict
    return err_cnt, json.loads(err_json_str)

def update_device_list_err(dev_list, err_dict):

    list_sz = len(dev_list)

    # Loop through the dictionary of errors
    for err_item in err_dict:

        # The key is the error text and the value is a json array (python list)
        # of indicies into the provisioning CSV file, and also the device list
        idx_list = err_dict[err_item]

        # Use the indicies to access the device list
        for dev_idx in idx_list:
            i = dev_idx -1
            if i >= list_sz:
                print("Reported device index out of range: {}".format(dev_idx))
                continue

            # Add the error message to the device list
            if len(err_item) == 0 or err_item == ' ':
                # In case of an empty error message...
                dev_list[i][DEV_LIST_RES_IDX] = 'ERROR_UNKNOWN'
            else:
                err_item = err_item.strip()
                err_item = err_item.replace("\n", " ")
                err_item = err_item.replace("\r", "")
                dev_list[i][DEV_LIST_RES_IDX] = err_item

    # Set status for devices without an error
    dev_list = update_device_list_ok(dev_list)

    return dev_list

def update_device_list_ok(dev_list):

    # Go through the list and add 'OK' to any devices without an error
    for dev in dev_list:
        if len(dev[DEV_LIST_RES_IDX]) == 0:
            dev[DEV_LIST_RES_IDX] = 'OK'

    return dev_list

def read_prov_csv(csv_filepath):
    device_list = []
    with open(csv_filepath) as csvfile:
        prov = csv.reader(csvfile, delimiter=',')
        row_count = sum(1 for row in prov)

        if row_count > MAX_CSV_ROWS:
            print("CSV file contains {} rows; must not exceed {}".format(row_count, MAX_CSV_ROWS))
            csvfile.close()
            return None

        csvfile.seek(0)
        prov = csv.reader(csvfile, delimiter=',')

        for row_idx, row in enumerate(prov):
            # First column in each row is the device ID
            # Add a list to the list [ <device_id>, <result_string> ]
            try:
                device_list.append([row[0], ''])
            except IndexError:
                print("Error reading row {} of provisioning CSV file.".format(row_idx + 1   ))

    return device_list

def read_devinfo_csv(csv_filepath):
    devinfo_list = []
    with open(csv_filepath) as csvfile:
        devinfo = csv.reader(csvfile, delimiter=',')

        for row_idx, row in enumerate(devinfo):
            try:
                imei = row[2]
            except IndexError:
                imei = ''

            # First column in each row is the device ID
            # Add a list to the list [ <device_id>, <mfw_version>, <imei>]
            try:
                devinfo_list.append([row[0], row[1], imei])
            except IndexError:
                print("Error reading row {} of modem firmware CSV file.".format(row_idx + 1))

    return devinfo_list

def save_or_print(results, result_filepath, append):
    # Save to file or print to console
    if len(result_filepath):
        res_bytes = results.getvalue().encode('utf-8')
        if append and os.path.exists(result_filepath):
            try:
                with open(result_filepath, "ab") as f:
                    f.write(res_bytes)
            except EnvironmentError:
                print("Error opening file: " + result_filepath)
                return
        else:
            write_file(os.path.dirname(result_filepath),
                       os.path.basename(result_filepath),
                       res_bytes)
    else:
        print(results.getvalue())

def save_results(bulk_results_json, err_cnt, dev_list, result_filepath):
    results = io.StringIO()

    # Write the data from the bulk ops status
    for k, v in bulk_results_json.items():
        results.write(k + ',' + v + '\n')

    results.write('Error count,' + str(err_cnt) + '\n')
    results.write('\n')

    if dev_list is not None:
        results.write('Device ID,Result' + '\n')
        # Write the items in the device list
        for dev_entry in dev_list:
            results.write(dev_entry[DEV_LIST_ID_IDX] + ',' +
                          dev_entry[DEV_LIST_RES_IDX] + '\n')
    else:
        results.write('Error output could not be accessed\n')

    print("")
    if not len(result_filepath):
        print("CSV-formatted results:")

    save_or_print(results, result_filepath, False)

def save_bulk_ops_id(bulk_ops_req_id, result_filepath):
    results = io.StringIO()

    results.write('{},{}\n'.format(BULK_OP_REQ_ID, bulk_ops_req_id))
    results.write('Bulk operations result could not be accessed\n')

    save_or_print(results, result_filepath, False)

def check_file_path(file):
    if not file:
        return None

    file_path = os.path.abspath(file)
    path = os.path.dirname(file_path)

    if not os.path.exists(path):
        try:
            makedirs(path, exist_ok=True)
        except OSError as e:
            print("Error creating file path: " + path)
            return ''

    return file_path

def do_provisioning(api_key, csv_in, res_out, do_check):

    if len(api_key) < 1:
        print("API key must be provided")
        return ProvisionResult.NOT_PERFORMED_NO_API_KEY

    result_filepath = ''
    if len(res_out):
        result_filepath = check_file_path(res_out)
        if not result_filepath:
            return ProvisionResult.NOT_PERFORMED_BAD_FILE_PATH

    csv_filepath = os.path.abspath(csv_in)
    if not os.path.exists(csv_filepath):
        print("CSV file does not exist: " + csv_filepath)
        return ProvisionResult.NOT_PERFORMED_BAD_FILE_PATH

    device_list = read_prov_csv(csv_filepath)
    if device_list is None:
        print("CSV file is not valid")
        return ProvisionResult.NOT_PERFORMED_INVALID_CSV_FORMAT

    device_list_len = len(device_list)
    print("Devices to be provisioned: " + str(device_list_len))

    if do_check and device_list_len == 1:
         # Get the device ID of the first (only) item in the list
        dev_id = device_list[0][DEV_LIST_ID_IDX]
        result = fetch_device(api_key, dev_id)

        if result.status_code == 404:
            print("Device \"{}\" does not yet exist, provisioning...".format(dev_id))
        elif result.status_code == 200:
            print("Device \"{}\" already provisioned".format(dev_id))
            return ProvisionResult.NOT_PERFORMED_DEVICE_EXISTS
        else:
            print_api_result("FetchDevice API call failed", result, True)
            return ProvisionResult.NOT_PERFORMED_DEV_CHK_FAILED

    elif do_check:
        print("More than one device in CSV file, ignoring chk flag")

    # Call the ProvisionDevices endpoint
    prov_result = provision_devices(api_key, csv_filepath)
    print_api_result("ProvisionDevices API call result", prov_result, True)

    if prov_result.status_code != 202:
        print("Provisioning failed")
        return ProvisionResult.NOT_PERFORMED_PROVDEV_CALL_FAILED

    # The response to a successful ProvisionDevices call will contain a bulk operations request ID
    bulk_req_id = prov_result.json()[BULK_OP_REQ_ID]

    # The device provisioning status is obtained through the FetchBulkOpsRequest endpoint
    bulk_results = get_provisioning_results(api_key, bulk_req_id)
    if bulk_results is None:
        print("Could not get results for {}: {}".format(BULK_OP_REQ_ID, bulk_req_id))
        save_bulk_ops_id(bulk_req_id, result_filepath)
        return ProvisionResult.PERFORMED_RESULTS_NOT_CONFIRMED

    err_count = 0
    bulk_results_json = bulk_results.json()

    if bulk_results_json["status"] == "FAILED":
        print("Failure during provisioning, downloading error summary...")

        # Errors are detailed in a JSON file, which must be downloaded separately
        error_results = requests.get(bulk_results_json["errorSummaryUrl"])

        if error_results.status_code == 200:
            # Parse the error message and update the device list
            err_count, err_json = parse_err_msg(error_results.text)
            device_list = update_device_list_err(device_list, err_json)
        else:
            print("Could not access error output: " + error_results.text)
            device_list = None

    elif bulk_results_json["status"] == "SUCCEEDED":
        # No errors, mark the devices as OK
        device_list = update_device_list_ok(device_list)
    else:
        print("Unhandled bulk ops status: {}".format(bulk_results_json["status"]))

    save_results(bulk_results_json, err_count, device_list, result_filepath)

    if err_count == 0:
        return ProvisionResult.PERFORMED_SUCCESSFULLY
    else:
        return ProvisionResult.PERFORMED_WITH_ERRORS

def update_mfwv_in_shadow(api_key, devinfo_list, res_out):
    err_cnt = 0
    res_list = []
    res_file_exists = False
    result_filepath = ''

    if res_out:
        result_filepath = check_file_path(res_out)
        if not result_filepath:
            return
        res_file_exists = os.path.exists(result_filepath)

    print("Writing modem firmware version to shadow for {} devices...".format(len(devinfo_list)))

    # Update each device's shadow with its installed modem firmware version
    for dev in devinfo_list:
        id = dev[0]
        ver = dev[1]
        shadow_json = {"reported": {"device": {"deviceInfo": {"modemFirmware": ver}}}}

        res_text = 'OK'
        res = update_device_shadow(api_key, id, shadow_json)
        if res.status_code != 202:
            print_api_result("Failed to update shadow for {}: ".format(id), res, True)
            res_text = res.text
            err_cnt = err_cnt + 1

        # Add result to list
        res_list.append([id, ver, res_text])

    # Compile the results and save to file or print
    results = io.StringIO()
    if res_file_exists:
        results.write('\n')
    results.write('Modem Firmware Version Shadow Update:\n')
    results.write('Error count,' + str(err_cnt) + '\n')
    results.write('\n')

    if len(res_list):
        results.write('Device ID,Modem Firmware Version,Result' + '\n')
        for res in res_list:
            results.write(res[0] + ',' +
                          res[1] + ',' +
                          res[2] + '\n')
    else:
        results.write('No results\n')

    if not len(result_filepath):
        print("CSV-formatted results:")

    save_or_print(results, result_filepath, True)

def set_friendly_name(api_key, devinfo_list, name_prefix):
    for dev in devinfo_list:
        id = dev[0]
        # Update each device's friendly name
        try:
            imei = dev[2]
        except IndexError:
            imei = ''

        if not imei:
            print("Friendly name not set, IMEI not found for device ID: {}".format(id))
            continue

        if name_prefix:
            imei = name_prefix + imei
        res = update_device_name(api_key, id, imei)
        if res.status_code != 202:
            print_api_result("Failed to update friendly name for {}: ".format(id), res, True)

def process_device_info_csv(api_key, csv_in, res_out, set_mfwv, set_name, name_prefix):
    if not csv_in:
        return

    devinfo_list = read_devinfo_csv(csv_in)

    if len(devinfo_list) == 0:
        print("Device info CSV file is empty")
        return

    if set_mfwv:
        update_mfwv_in_shadow(api_key, devinfo_list, res_out)

    if set_name:
        set_friendly_name(api_key, devinfo_list, name_prefix)

def main():

    if not len(sys.argv) > 1:
        raise RuntimeError("No input provided")

    args = parse_args()

    if not len(args.csv):
        raise RuntimeError("Invalid provisioning CSV file")

    prov_res = do_provisioning(args.apikey, args.csv, args.res, args.chk)

    if prov_res is ProvisionResult.PERFORMED_SUCCESSFULLY or \
       prov_res is ProvisionResult.PERFORMED_RESULTS_NOT_CONFIRMED or \
       prov_res is ProvisionResult.PERFORMED_WITH_ERRORS:
        process_device_info_csv(args.apikey, args.devinfo, args.res,
                              args.set_mfwv, args.name_imei, args.name_prefix)

    return

if __name__ == '__main__':
    main()
