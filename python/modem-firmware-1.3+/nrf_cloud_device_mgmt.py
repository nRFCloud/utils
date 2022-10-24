#!/usr/bin/env python3
#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

import argparse
import sys
import requests
import requests
import urllib
from datetime import datetime
from os import makedirs
from ast import literal_eval
from enum import Enum
import textwrap
from modem_credentials_parser import write_file

API_URL = "https://api.nrfcloud.com/v1/"

GET_DEVICES_BASE = API_URL + 'devices?includeState=false&includeStateMeta=false&pageSort=desc'
GET_DEVICES_PAGE_LIMIT = 20

GET_BUNDLES_BASE = API_URL + 'firmwares'
GET_BUNDLES_PAGE_LIMIT = 20

FOTA_JOBS_BASE = API_URL + 'fota-jobs'

FOTA_JOB_NAME_MAX_LEN = 64
FOTA_JOB_NAME_DESC_LEN = 1024

FOTA_JOB_DEV_ID_LIST_MAX = 100

class updateBy(Enum):
        TAG = 0
        BASE_FW_VER = 1
        DEV_ID = 2

class updateBundle:

    class fotaType(Enum):
        APP = 0
        MODEM = 1
        BOOT = 2

    id = ''
    name = ''
    desc = ''
    ver = ''
    date = datetime(2000,1,1)
    size = 0
    type = ''

    def __repr__(self):
        bundle_str = '[{}], {}, {} bytes, {}'.format(
            self.id, self.name, self.size, self.date.date())
        return bundle_str

    def __init__(self, id):
       self.id = id

    def __init__(self, list_item):
        try:
            self.id = list_item['bundleId']
        except:
            self.id = ''

        try:
            self.name = list_item['name']
        except:
            self.name = None

        try:
            self.desc = list_item['description']
        except:
            self.desc = None

        try:
            self.type = list_item['type']
        except:
            self.type = None

        try:
            self.ver = list_item['version']
        except:
            self.ver = None

        try:
            self.size = list_item['size']
        except:
            self.size = 0

        try:
            self.date = datetime.strptime(list_item['lastModified'], '%Y-%m-%dT%H:%M:%S.%fZ')
        except:
            self.date = None


class nRFCloudDevice:

    id = ''
    name = ''

    tags = []

    mfw_ver = ''
    mfw_fota = False

    boot_ver = ''
    boot_fota = False

    app_name = ''
    app_ver = ''
    app_fota = False

    type = ''
    sub_type = ''

    def __repr__(self):
        dev_str = '{}, {}, App[{}, {}, {}], Modem[{}, {}], Boot[{}, {}], Tags{}'.format(
            self.id, self.name,
            self.app_name, self.app_ver, self.app_fota,
            self.mfw_ver, self.mfw_fota,
            self.boot_ver, self.boot_fota,
            self.tags)
        return dev_str

    def __init__(self, id):
       self.id = id

    def __init__(self, list_item):
        try:
            self.id = list_item['id']
        except:
            self.id = ''

        try:
            self.name = list_item['name']
        except:
            self.name = None

        try:
            self.tags = list_item['tags']
        except:
            self.tags.clear()

        try:
            self.type = list_item['type']
        except:
            self.type = None

        try:
            self.sub_type = list_item['subType']
        except:
            self.sub_type = None

        try:
            self.mfw_ver = list_item['firmware']['modem']
        except:
            self.mfw_ver = None

        try:
            self.boot_ver = list_item['firmware']['boot']
        except:
            self.boot_ver = None

        try:
            self.app_ver = list_item['firmware']['app']['version']
        except:
            self.app_ver = None

        try:
            self.app_name = list_item['firmware']['app']['name']
        except:
            self.app_name = None

        try:
            for supported_type in list_item['firmware']['supports']:
                if supported_type == 'APP':
                    self.app_fota = True
                elif supported_type == 'BOOT':
                    self.boot_fota = True
                elif supported_type == 'MODEM':
                    self.mfw_fota = True
        except:
            self.app_fota = False
            self.boot_fota = False
            self.mfw_fota = False

def url_encode(token):
    return urllib.parse.quote_plus(token)

def parse_args():
    parser = argparse.ArgumentParser(description="nRF Cloud Device Provisioning",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--apikey",
                        help="nRF Cloud API key",
                        type=str, required=True, default="")
    parser.add_argument("--type",
                        help="FOTA update type: APP, MODEM, or BOOT",
                        type=str, required=False, default="MODEM")
    parser.add_argument("--apply",
                        help="Apply job upon creation; this starts the job. If not enabled, the job must be applied using the ApplyFOTAJob endpoint.",
                        action='store_true', default=False)
    parser.add_argument("--rd",
                        help="Display only devices that support the requested FOTA type",
                        action='store_true', default=False)
    parser.add_argument("--ad",
                        help="Display all devices. Only specified device is displayed if used with --dev_id. Overrides --rd.",
                        action='store_true', default=False)
    parser.add_argument("--tag_list",
                        help="Display all tags (device groups) and prompt to select tag to use. Enabled for non-MODEM updates.",
                        action='store_true', default=False)
    parser.add_argument("--tag",
                        help="Create an update for the specified device tag (device group). Overrides --tag_list.",
                        type=str, default="")
    parser.add_argument("--dev_id",
                        help="Create an update for the specified device ID. Overrides --tag and --tag_list.",
                        type=str, required=False, default="")
    parser.add_argument("--bundle_id",
                        help="Create an update using the specified bundle ID.",
                        type=str, required=False, default="")
    parser.add_argument("--name",
                        help="The name to be used for the created update.",
                        type=str, required=False, default="")
    parser.add_argument("--desc",
                        help="The description of the created updated.",
                        type=str, required=False, default="")

    args = parser.parse_args()
    return args

def get_bundle_list(api_key, modem_only):

    hdr = {'Authorization': 'Bearer ' + api_key}
    req_base = GET_BUNDLES_BASE + '?pageLimit={}'.format(GET_BUNDLES_PAGE_LIMIT)

    if modem_only:
        req_base = req_base + '&modemOnly=true'

    bundle_list = []
    next_tok = ''

    while True:

        req = req_base

        if next_tok:
            req = req + '&pageNextToken={}'.format(next_tok)

        api_res = requests.get(req, headers=hdr)
        if api_res.status_code != 200:
            print_api_result("ListFirmware API call failed", api_res, True)
            break

        api_res_json = api_res.json()

        if 'items' in api_res_json.keys():
            items = api_res_json['items']
            for i in items:
                bundle_list.append(updateBundle(i))

        if 'pageNextToken' in api_res_json.keys():
            next_tok = url_encode(api_res_json['pageNextToken'])
        else:
            next_tok = ''
            break

    return sorted(bundle_list, key=lambda bundle : bundle.date)

def get_requested_bundles(api_key, fota_type):
    bundles = get_bundle_list(api_key, fota_type == updateBundle.fotaType.MODEM.name)
    return [i for i in bundles if i.type == fota_type]

def get_device_list(api_key, fota_types_list, device_id):
    hdr = {'Authorization': 'Bearer ' + api_key}
    req_base = GET_DEVICES_BASE + '&pageLimit={}'.format(GET_DEVICES_PAGE_LIMIT)

    if fota_types_list:
        for type in fota_types_list:
            req_base = req_base + '&firmwareSupport={}'.format(type)

    if device_id:
        req_base = req_base + '&deviceIds={}'.format(device_id)

    next_tok = ''
    dev_list = []

    while True:

        req = req_base

        if next_tok:
            req = req + '&pageNextToken={}'.format(next_tok)

        api_res = requests.get(req, headers=hdr)

        if api_res.status_code != 200:
            print_api_result("ListDevices API call failed", api_res, True)
            break

        api_res_json = api_res.json()

        if 'items' in api_res_json.keys():
            items = api_res_json['items']
            for i in items:
                dev_list.append(nRFCloudDevice(i))

        if 'pageNextToken' in api_res_json.keys():
            next_tok = url_encode(api_res_json['pageNextToken'])
        else:
            next_tok = ''
            break

    return sorted(dev_list,  key=lambda dev : dev.id)

def print_api_result(custom_text, api_result, print_response_txt):
    print("{}: {} - {}".format(custom_text, api_result.status_code, api_result.reason))
    if print_response_txt:
        print("Response: {}".format(api_result.text))

def create_fota_job(api_key, json_payload_obj):
    jobId = None
    hdr = {'Authorization': 'Bearer ' + api_key}
    req = FOTA_JOBS_BASE

    api_res = requests.post(req, json=json_payload_obj, headers=hdr)
    if api_res.status_code != 200:
            print_api_result("CreateFOTAJob API call failed", api_res, True)
    else:
        api_res_json = api_res.json()

        if 'jobId' in api_res_json.keys():
            jobId = api_res_json['jobId']

    return jobId

def get_fota_job_payload_common(bundle_id, update_name, update_desc, apply):
    payload = {}
    payload['bundleId'] = bundle_id
    if not apply:
        # param defaults to "true"
        payload['autoApply'] = "false"
    payload['name'] = update_name
    payload['description'] = update_desc
    return payload

def create_fota_job_by_tag(api_key, bundle_id, update_name, update_desc, tag_list, apply):

    payload = get_fota_job_payload_common(bundle_id, update_name, update_desc, apply)
    payload['tags'] = tag_list

    return create_fota_job(api_key, payload)

def create_fota_job_by_device_id(api_key, bundle_id, update_name, update_desc, device_id_list, apply):

    if len(device_id_list) > FOTA_JOB_DEV_ID_LIST_MAX:
        print('Error: device ID list size of {} exceeds limit of {}'.format(len(device_id_list), FOTA_JOB_DEV_ID_LIST_MAX))
        return None

    payload = get_fota_job_payload_common(bundle_id, update_name, update_desc, apply)
    payload['deviceIds'] = device_id_list

    return create_fota_job(api_key, payload)

def user_select_from_list(list_size):
    selected_idx = 0
    while True:
        try:
            selected_idx = int(input('Enter a number [1-{}]: '.format(list_size)))
        except ValueError:
            continue
        else:
            if 1 <= selected_idx <= list_size:
                return selected_idx - 1
                break
            else:
                continue

def user_request_string(request, max_len):
    while True:
        try:
            user_input = input(request + ': ')
        except ValueError:
            continue
        else:
            if not user_input:
                continue
            if len(user_input) > max_len:
                print('Input must not exceed {} characters'.format(max_len))
                continue
            else:
                return user_input

def user_select_yn():
    selected_idx = 0
    while True:
        try:
            user_val = input('Enter y or n: ')
        except ValueError:
            continue
        else:
            if not user_val:
                continue
            elif user_val[0] == 'y':
                return True
            elif user_val[0] == 'n':
                return False
            else:
                continue

def user_select_job_name_and_desc(name, desc):

    if not name:
        name = user_request_string("Enter a name for the update", FOTA_JOB_NAME_MAX_LEN)

    if not desc:
        desc = user_request_string("Enter a description of the update", FOTA_JOB_NAME_DESC_LEN)

    return name, desc

def get_tag_list(device_list):
    # create a set to get unique tags across all devices
    tag_set = set()
    for dev in device_list:
        for tag in dev.tags:
                tag_set.add(tag)

    if not len(tag_set):
        print('No tags found')
        return None

    tag_list = sorted(tag_set)
    return tag_list

def user_select_tag(tag_list, device_list):
    # display each tag and the number of tagged devices
    print('\nAvailable tags:')
    for tag in tag_list:
        tag_cnt = 0
        for dev in device_list:
            if tag in dev.tags:
                tag_cnt = tag_cnt + 1
        print('{}.) \'{}\' contains {} device(s)'.format(tag_list.index(tag) + 1, tag, tag_cnt))

    # get user selection
    print('Select the tag to update...')
    tag_idx = user_select_from_list(len(tag_list))

    # return the tag list and selected index
    return tag_list, tag_idx

def check_tagged_modem_fw_versions(device_list, tag_list, tag_idx, prompt):
    # check mfw ver in selected tag, alert user if they are different
    tagged_mfw_ver = ''
    for dev in device_list:
        if tag_list[tag_idx] in dev.tags:
            if not tagged_mfw_ver:
                tagged_mfw_ver = dev.mfw_ver
                continue
            elif tagged_mfw_ver != dev.mfw_ver:
                print('Warning: Devices in tag \'{}\' do not have the same modem firmware version installed'.format(tag_list[tag_idx]))
                if prompt:
                    print('Continue creating an update for this tag?'.format(tag_list[tag_idx]))
                    if user_select_yn():
                        break
                    else:
                        return None
                else:
                    return None

    return tag_idx

def handle_modem_updates(api_key, bundle_list, device_list, update_by, tag, bundle_id, name, desc, apply):
    job_id = ''
    new_mfw_list = []
    cur_mfw_list = []
    cur_mfw_idx = 0
    tag_list = get_tag_list(device_list)
    tag_idx = 0

    if update_by == updateBy.TAG:
        if not tag_list:
            return None

        tag_idx = None

        if tag:
            try:
                tag_idx = tag_list.index(tag)
                # print warning if tagged devices have different mfw versions installed
                check_tagged_modem_fw_versions(device_list, tag_list, tag_idx, False)
            except ValueError:
                print('Tag list: {}'.format(tag_list))
                print('Error: No devices found with tag \'{}\''.format(tag))
                return None

        # ask user to select a tag and then check the mfw version(s) associated with that tag
        while not tag_idx:
            tag_list, tag_idx = user_select_tag(device_list)
            if not tag_list:
                # no tags, exit
                return None

            # check the version, if a tag index is returned the user wishes to proceed
            tag_idx = check_tagged_modem_fw_versions(device_list, tag_list, tag_idx, True)

            # no tag index... try again or exit
            if not tag_idx:
                print('Select a different tag?')
                if user_select_yn():
                    continue
                else:
                    return None
    elif update_by == updateBy.BASE_FW_VER:
        # create a set of the currently installed mfw versions
        mfw_set = set()
        for dev in device_list:
            if dev.mfw_ver:
                mfw_set.add(dev.mfw_ver)
            else:
                print('Warning: device \'{}\' does not have a modem firmware version listed'.format(dev.id))

        if not len(mfw_set):
            print('No valid target devices')
            return None

        # display the unique mfw version and get user selection
        cur_mfw_list = sorted(mfw_set)
        print('\nCurrently installed modem firmware versions:')
        for ver in cur_mfw_list:
            dev_cnt = 0
            for dev in device_list:
                if dev.mfw_ver == ver:
                    dev_cnt = dev_cnt + 1
            print('{}.) {} on {} device(s)'.format(cur_mfw_list.index(ver) + 1, ver, dev_cnt))

        print('Select CURRENT modem firmware version to update FROM...')
        cur_mfw_idx = user_select_from_list(len(cur_mfw_list))
    elif update_by == updateBy.DEV_ID:
        dev = device_list[0]
        cur_mfw = 'N/A'
        if dev.mfw_ver:
            cur_mfw = dev.mfw_ver
            print('Device \'{}\' has the following modem firmware version: {}'.format(dev.id, cur_mfw))
        else:
            print('Device \'{}\' does not have a modem firmware version listed'.format(dev.id))

        cur_mfw_list.append(cur_mfw)
        cur_mfw_idx = 0
    else:
        print('Invalid update_by parameter specified: {}'.format(update_by))
        return None

    # create a list of the MODEM bundles
    for bund in bundle_list:
        if bund.type == updateBundle.fotaType.MODEM.name:
            new_mfw_list.append(bund)

    mfw_new_idx = -1
    if bundle_id:
        for bund in new_mfw_list:
            if bund.id == bundle_id:
                mfw_new_idx = new_mfw_list.index(bund)
                break
        if mfw_new_idx < 0:
            print('Error: Bundle ID \'{}\' was not found'.format(bundle_id))
            return None
    else:
        # display the available modem fw bundles and get user selection
        print('Available modem firmware versions:')
        for new in new_mfw_list:
            print('{}.) {}\n\tBundle ID: {}\n\tModified:  {}'.format(new_mfw_list.index(new) + 1, new.ver, new.id, new.date))
            desc_list = textwrap.wrap('\"{}\"'.format(new.desc),initial_indent='\t',subsequent_indent='\t',width=99)
            for line in desc_list:
                print(line)

        print('Select NEW modem firmware version to update TO...')
        mfw_new_idx = user_select_from_list(len(new_mfw_list))

    # get user input for job name and description
    job_name, job_desc = user_select_job_name_and_desc(name, desc)

    # build a list of devices to update or the number of devices with the user selected tag
    devices_to_update = []
    update_cnt = 0
    for dev in device_list:
        if update_by == updateBy.TAG:
            if tag_list[tag_idx] in dev.tags:
                update_cnt = update_cnt + 1
        elif update_by == updateBy.BASE_FW_VER:
            if cur_mfw_list[cur_mfw_idx] == dev.mfw_ver:
                devices_to_update.append(dev.id)
        else:
            devices_to_update.append(dev.id)

    if update_by != updateBy.TAG:
        update_cnt = len(devices_to_update)

    if (update_by == updateBy.BASE_FW_VER) and (update_cnt > FOTA_JOB_DEV_ID_LIST_MAX):
        print('Creating a FOTA job using this method has a limit of {} devices'.format(FOTA_JOB_DEV_ID_LIST_MAX))
        print('Use a device tag to create an update for a larger number of devices.')
        print('Truncate device list and proceed?')
        if user_select_yn():
            del devices_to_update[FOTA_JOB_DEV_ID_LIST_MAX:]
        else:
            return None

    # display update details and ask user for confirmation
    if update_by == updateBy.DEV_ID:
        print('The following update will be created for device: {}'.format(devices_to_update[0]))
    else:
        print('The following update will be created for {} device(s):'.format(update_cnt))

    print('\tName: {}'.format(job_name))
    print('\tDescription: {}'.format(job_desc))

    if update_by == updateBy.TAG:
        print('\tVersion: Tag[\'{}\'] --> {}'.format(tag_list[tag_idx], new_mfw_list[mfw_new_idx].ver))
    else:
        print('\tVersion: {} --> {}'.format(cur_mfw_list[cur_mfw_idx], new_mfw_list[mfw_new_idx].ver))

    # if user provides all info via cmd params, do not ask for confirmation
    if not((update_by == update_by.TAG and tag) or (update_by == update_by.DEV_ID) and
           name and desc):
        print('Proceed?')
        if not user_select_yn():
            return None

    if update_by == updateBy.TAG:
        # creating updates for multiple tags is supported, but for simplicity this script allows only one
        job_id = create_fota_job_by_tag(api_key, new_mfw_list[mfw_new_idx].id, job_name, job_desc, [tag_list[tag_idx]], apply)
    else:
        job_id = create_fota_job_by_device_id(api_key, new_mfw_list[mfw_new_idx].id, job_name, job_desc, devices_to_update, apply)

    if job_id:
        print('Created job: {}'.format(job_id))

    return job_id

def print_device_list(device_list):
    if len(device_list) == 0:
        return

    print("\nName,   ID,   App[Name, Version, FOTA support],   Modem[Version, FOTA support],   BOOT[Version, FOTA support],   Tags[]")
    print("-----------------------------------------------------------------------------------------------------------------------")
    for dev in device_list:
        print(dev)
    print("")

def main():

    if not len(sys.argv) > 1:
        raise RuntimeError("No input provided")

    args = parse_args()

    # determine requested FOTA type
    fota_type = None
    for type in updateBundle.fotaType:
        if type.name.casefold() == args.type.casefold():
            fota_type = type
            break

    if fota_type is None:
        raise RuntimeError('Invalid FOTA update type specified: \'{}\''.format(args.type))
    elif fota_type is not updateBundle.fotaType.MODEM:
        args.tag_list = True

    # get update bundles of the requested FOTA type
    print('Getting \'{}\' update bundles...'.format(fota_type.name))
    bundles = get_requested_bundles(args.apikey, fota_type.name)

    if len(bundles) == 0:
        print('No \'{}\' bundles found'.format(fota_type.name))
        return

    print('Obtained {} \'{}\' update bundles'.format(len(bundles), fota_type.name))

    update_by = updateBy.BASE_FW_VER

    if args.dev_id:
        print('Getting device {}...'.format(args.dev_id))
        update_by = updateBy.DEV_ID
    else:
        print('Getting all devices...')
        if args.tag_list or args.tag:
            update_by = updateBy.TAG

    devices = get_device_list(args.apikey, None, args.dev_id)
    if len(devices) == 0:
        print('No devices found')
        return

    # get a list of devices that support the requested FOTA type
    requested_devices = []
    if fota_type == updateBundle.fotaType.APP:
        requested_devices = [d for d in devices if d.app_fota]
    elif fota_type == updateBundle.fotaType.BOOT:
        requested_devices = [d for d in devices if d.boot_fota]
    elif fota_type == updateBundle.fotaType.MODEM:
        requested_devices = [d for d in devices if d.mfw_fota]

    # display devices if requested
    if args.ad:
        print_device_list(devices)
    elif args.rd:
        print_device_list(requested_devices)

    print('{} of {} devices support \'{}\' FOTA updates'.format(len(requested_devices), len(devices), fota_type.name))

    if len(requested_devices) == 0:
        return

    if fota_type == updateBundle.fotaType.MODEM:
        handle_modem_updates(args.apikey, bundles, requested_devices, update_by,
                             args.tag, args.bundle_id, args.name, args.desc, args.apply)
    elif fota_type == updateBundle.fotaType.APP:
        print('APP FOTA update creation not yet implemented')
    elif fota_type == updateBundle.fotaType.BOOT:
        print('BOOT FOTA update creation not yet implemented')

    return

if __name__ == '__main__':
    main()
