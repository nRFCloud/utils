#!/usr/bin/env python3
#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

import argparse
import sys
import requests
import textwrap
import urllib
from urllib.parse import quote_plus as url_encode
from datetime import datetime
from enum import Enum

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

        # name is optional
        try:
            self.name = list_item['name']
        except:
            self.name = 'N/A'

        # description is optional
        try:
            self.desc = list_item['description']
        except:
            self.desc = 'N/A'

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
        return f'{self.id}, {self.name}, ' \
               f'App[{self.app_name}, {self.app_ver}, {self.app_fota}], ' \
               f'Modem[{self.mfw_ver}, {self.mfw_fota}], ' \
               f'Boot[{self.boot_ver}, {self.boot_fota}], ' \
               f'Tags{self.tags}'

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

        supported = list_item.get('firmware', {}).get('supports', [])
        self.app_fota       = 'APP' in supported
        self.boot_fota      = 'BOOT' in supported
        self.mfw_fota       = 'MODEM' in supported

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
    bundles = get_bundle_list(api_key, fota_type == updateBundle.fotaType.MODEM)
    return [i for i in bundles if i.type == fota_type.name]

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

def get_selected_bundle_index(bundle_list, bundle_id, fota_type):
    idx = -1

    if bundle_id:
        # locate the provided bundle id
        for bund in bundle_list:
            if bund.id == bundle_id:
                idx = bundle_list.index(bund)
                break

        if idx < 0:
            print('Error: Bundle ID \'{}\' was not found'.format(bundle_id))

    else:
        # bundle id not provided
        # display the available bundles and get user selection
        print('Available {} firmware bundles:'.format(fota_type.name))
        for bund in bundle_list:
             # some modem bundle names may include a tenant id, trim it off
            bund_name = bund.name
            tenant_idx = bund_name.rfind("TenantId:")
            if tenant_idx > 0: # in case bundle name only has a tenant id
                bund_name = bund.name[0:tenant_idx]
            # print a numbered list with useful bundle info
            print('{}.) {}'.format(bundle_list.index(bund) + 1, bund_name))
            print('\tVersion:   {}\n\tBundle ID: {}\n\tModified:  {}'.format(bund.ver, bund.id, bund.date))
            # format and print the bundle description
            desc_list = textwrap.wrap('\"{}\"'.format(bund.desc),initial_indent='\t',subsequent_indent='\t',width=99)
            for line in desc_list:
                print(line)

        print('Select {} firmware bundle for the update...'.format(fota_type.name))
        idx = user_select_from_list(len(bundle_list))

    return idx

def print_current_fw_info(device, fota_type):
    ver = 'N/A'
    name = 'N/A'

    if fota_type == updateBundle.fotaType.APP:
        if device.app_ver:
            ver = device.app_ver
        if device.app_name:
            name = device.app_name
    elif fota_type == updateBundle.fotaType.BOOT and device.boot_ver:
        ver = device.boot_ver
    elif fota_type == updateBundle.fotaType.MODEM and device.mfw_ver:
        ver = device.mfw_ver

    print('\nDevice \'{}\' current {} info:\n\tName: {}\n\tVersion: {}\n'
            .format(device.id, fota_type.name, name, ver))

    return ver

def print_update_summary(update_by, fota_type, job_name, job_desc, cur_ver, new_ver, devices_to_update, tag_to_update):

    update_summary = 'The following update will be created for '

    if update_by == updateBy.DEV_ID:
        update_summary = update_summary + 'device {}:'.format(devices_to_update[0])
    else:
        update_summary = update_summary + '{} device(s):'.format(len(devices_to_update))

    print(update_summary)

    print('\tName: {}'.format(job_name))
    print('\tDescription: {}'.format(job_desc))
    print('\tType: {}'.format(fota_type.name))

    if update_by == updateBy.TAG:
        print('\tVersion: Tag[\'{}\'] --> {}'.format(tag_to_update, new_ver))
    else:
        print('\tVersion: {} --> {}'.format(cur_ver, new_ver))

def get_device_ids_to_update(device_list, update_by, tag_to_update, cur_fw_ver):
    list_out = []

    for dev in device_list:
        if update_by == updateBy.TAG:
            if tag_to_update in dev.tags:
                list_out.append(dev.id)
        elif update_by == updateBy.BASE_FW_VER:
            # only supported for modem fw types
            if cur_fw_ver == dev.mfw_ver:
                list_out.append(dev.id)
        else: # updateBy.DEV_ID:
            list_out.append(dev.id)

    return list_out

def find_or_select_tag(device_list, tag, fota_type):
    tag_list = get_tag_list(device_list)

    if not tag_list:
            return None

    if tag:
        if tag in tag_list:
            if fota_type == updateBundle.fotaType.MODEM:
                # print warning if tagged devices have different mfw versions installed
                tag = check_tagged_modem_fw_versions(device_list, tag, False)
            return tag
        else:
            print('Tag list: {}'.format(tag_list))
            print('Error: No devices found with tag \'{}\''.format(tag))
            return None

    # ask user to select a tag
    while True:
        tag_idx = user_select_tag(tag_list, device_list)
        if tag_idx < 0:
            return None

        tag = tag_list[tag_idx]

        if fota_type == updateBundle.fotaType.MODEM:
            # check the version, if a tag is returned the user wishes to proceed
            tag = check_tagged_modem_fw_versions(device_list, tag, True)

        # no tag... try again or exit
        if tag is None:
            print('Select a different tag?')
            if user_select_yn():
                continue
            else:
                return None

        return tag

def confirm_before_create(name, desc, bundle_id, tag_to_update, update_by):
    if (name and desc and bundle_id and
        ((update_by == update_by.TAG and tag_to_update) or (update_by == update_by.DEV_ID))):
        # if user provides all info via cmd params, do not ask for confirmation
        print('Creating update with supplied parameters...')
        return True

    # otherwise, confirm
    print('Proceed?')
    return user_select_yn()

def do_job_creation(api_key, bundle_list, device_list, update_by, tag, bundle_id, name, desc, apply, fota_type):
    tag_to_update = ''
    cur_fw_ver = ''

    if update_by == updateBy.TAG:
        tag_to_update = find_or_select_tag(device_list, tag, fota_type)
        if not tag_to_update:
            return None
    elif update_by == updateBy.DEV_ID:
        cur_fw_ver = print_current_fw_info(device_list[0], fota_type)
    elif update_by == updateBy.BASE_FW_VER:
        if fota_type != updateBundle.fotaType.MODEM:
            print('Updating by installed FW version is not supported for {} FW'.format(fota_type))
            return None

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
        for idx, ver in enumerate(cur_mfw_list):
            # count the number of devices that have each mfw version
            dev_cnt = len(list(dev for dev in device_list if dev.mfw_ver == ver))
            print('{}.) {} on {} device(s)'.format(idx + 1, ver, dev_cnt))

        print('Select CURRENT modem firmware version to update FROM...')
        cur_mfw_idx = user_select_from_list(len(cur_mfw_list))
        if cur_mfw_idx < 0:
            print('Could not obtain current modem firmware version')
            return None

        cur_fw_ver = cur_mfw_list[cur_mfw_idx]
    else:
        print('Invalid update_by parameter specified: {}'.format(update_by))
        return None

    # create a list of bundles of the desired type
    filtered_bund_list = [bund for bund in bundle_list if bund.type == fota_type.name]

    # get a bundle
    selected_bund_idx = get_selected_bundle_index(filtered_bund_list, bundle_id, fota_type)
    if selected_bund_idx < 0:
        print('Error: failed to obtain bundle')
        return None

    # get user input for job name and description
    job_name, job_desc = user_select_job_name_and_desc(name, desc)

    # get list of devices to update
    dev_ids_to_update = get_device_ids_to_update(device_list, update_by, tag_to_update, cur_fw_ver)

    if (update_by == updateBy.BASE_FW_VER) and (len(dev_ids_to_update) > FOTA_JOB_DEV_ID_LIST_MAX):
        print('Creating a FOTA job using this method has a limit of {} devices'.format(FOTA_JOB_DEV_ID_LIST_MAX))
        print('Use a device tag to create an update for a larger number of devices.')
        print('Truncate device list and proceed?')
        if user_select_yn():
            del dev_ids_to_update[FOTA_JOB_DEV_ID_LIST_MAX:]
        else:
            return None

    # display update details and ask user for confirmation
    print_update_summary(update_by, fota_type, job_name, job_desc,
                         cur_fw_ver, filtered_bund_list[selected_bund_idx].ver,
                         dev_ids_to_update, tag_to_update)

    if confirm_before_create(name, desc, bundle_id, tag_to_update, update_by) == False:
        return None

    if update_by == updateBy.TAG:
        # creating updates for multiple tags is supported, but for simplicity this script allows only one
        job_id = create_fota_job_by_tag(api_key, filtered_bund_list[selected_bund_idx].id,
                                        job_name, job_desc, [tag_to_update], apply)
    else:
        job_id = create_fota_job_by_device_id(api_key, filtered_bund_list[selected_bund_idx].id,
                                              job_name, job_desc, dev_ids_to_update, apply)

    if job_id:
        print('Created job: {}'.format(job_id))

    return job_id

def user_select_from_list(list_size):
    if list_size < 1:
        return -1

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
    return user_select_from_list(len(tag_list))

def check_tagged_modem_fw_versions(device_list, tag, prompt):
    # check mfw ver in selected tag, alert user if they are different
    tagged_mfw_ver = ''
    for dev in device_list:
        if tag in dev.tags:
            if not tagged_mfw_ver:
                tagged_mfw_ver = dev.mfw_ver
                continue
            elif tagged_mfw_ver != dev.mfw_ver:
                print('Warning: Devices in tag \'{}\' do not have the same modem firmware version installed'.format(tag))
                if prompt:
                    print('Continue creating an update for tag \'{}\'?'.format(tag))
                    if user_select_yn():
                        break
                    else:
                        return None
                else:
                    return None

    return tag

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
    bundles = get_requested_bundles(args.apikey, fota_type)

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
        if args.tag_list or args.tag or fota_type != updateBundle.fotaType.MODEM:
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

    do_job_creation(args.apikey, bundles, requested_devices, update_by,
                    args.tag, args.bundle_id, args.name, args.desc, args.apply,
                    fota_type)

    return

if __name__ == '__main__':
    main()
