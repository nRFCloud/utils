#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import requests
import coloredlogs, logging
from nrfcloud_utils import ca_certs

DEV_STAGE_DICT = {'dev':     '.dev.',
                  'beta':    '.beta.',
                  'prod':    '.',
                  '':        '.',
                  'feature': '.feature.'}
dev_stage_key = 'prod'

API_URL_START = 'https://api.provisioning'
API_URL_END = 'nrfcloud.com/v1/'
api_url = API_URL_START + DEV_STAGE_DICT[dev_stage_key] + API_URL_END

AUTH = 'Authorization'
BEARER = 'Bearer '
CLAIMED_DEV = 'claimed-devices'
PROV = 'provisioning'
CLAIM_TOK = 'claimToken'
CLAIM_TAGS = 'tags'
CONTENT_TYPE = 'contentType'

logger = logging.getLogger(__name__)

def set_dev_stage(stage = ''):
    global api_url
    global dev_stage_key

    if stage in DEV_STAGE_DICT.keys():
        dev_stage_key = stage
        api_url = f'{API_URL_START}{DEV_STAGE_DICT[dev_stage_key]}{API_URL_END}'
    else:
        logger.error('Invalid stage')

    return api_url

def get_auth_header(api_key):
    if not api_key:
        return None
    return  { AUTH : BEARER + api_key}

def claim_device(api_key, claim_token, tags = None):
    global api_url
    req = f'{api_url}{CLAIMED_DEV}'
    if tags is None:
        payload = {CLAIM_TOK : claim_token}
    else:
        payload = {CLAIM_TOK : claim_token, CLAIM_TAGS : [tags]}

    return requests.post(req, json=payload, headers=get_auth_header(api_key))

def bulk_claim_devices(api_key, csv_rows):
    global api_url
    req = f'{api_url}{CLAIMED_DEV}'
    h = get_auth_header(api_key)
    h[CONTENT_TYPE] = 'text/csv'
    return requests.post(req, data=csv_rows, headers=h)

def unclaim_device(api_key, dev_uuid):
    global api_url

    req = f'{api_url}{CLAIMED_DEV}/{dev_uuid}'

    return requests.delete(req, headers=get_auth_header(api_key))

def get_create_prov_cmd_req(dev_uuid):
    global api_url
    return f'{api_url}{CLAIMED_DEV}/{dev_uuid}/{PROV}'

def create_provisioning_cmd_cert(api_key, dev_uuid, cert_pem, description, cert_type,
                                 sec_tag=16842753):
    global api_url

    payload = {}
    request = {}
    cert_obj = {}

    req = get_create_prov_cmd_req(dev_uuid)

    cert_obj['content'] = cert_pem
    cert_obj['secTag'] = sec_tag

    request[cert_type] = cert_obj

    payload['description'] = description
    payload['request'] = request

    return requests.post(req, json=payload, headers=get_auth_header(api_key))

def create_provisioning_cmd_client_cert(api_key, dev_uuid, cert_pem,
                                        description='Update client cert',
                                        sec_tag=16842753):
    return create_provisioning_cmd_cert(api_key, dev_uuid, cert_pem,
                                        description, 'clientCertificate',
                                        sec_tag)

def create_provisioning_cmd_server_cert(api_key, dev_uuid, cert_pem,
                                        description='Update server cert',
                                        sec_tag=16842753):
    return create_provisioning_cmd_cert(api_key, dev_uuid, cert_pem,
                                        description, 'serverCertificate',
                                        sec_tag)

def create_provisioning_cmd_finished(api_key, dev_uuid, description='Provisioning complete'):
    global api_url

    payload = {}
    request = {}

    req = get_create_prov_cmd_req(dev_uuid)

    request['finished'] = {}

    payload['description'] = description
    payload['request'] = request

    return requests.post(req, json=payload, headers=get_auth_header(api_key))

def create_provisioning_cmd_csr(api_key, dev_uuid, description='Generate CSR',
                                attributes='',
                                key_usage='101010000', sec_tag=16842753):
    global api_url

    payload = {}
    request = {}
    csr_obj = {}

    req = get_create_prov_cmd_req(dev_uuid)

    csr_obj['attributes'] = attributes
    csr_obj['keyUsage'] = key_usage
    csr_obj['secTag'] = sec_tag

    request['certificateSigningRequest'] = csr_obj

    payload['description'] = description
    payload['request'] = request

    return requests.post(req, json=payload, headers=get_auth_header(api_key))

def get_provisioning_cmd(api_key, dev_uuid, cmd_id):
    global api_url
    req = f'{api_url}{CLAIMED_DEV}/{dev_uuid}/{PROV}/{cmd_id}'

    return requests.get(req, headers=get_auth_header(api_key))

def print_api_result(custom_text, api_result):
    logger.info(f"{custom_text}: {api_result.status_code} - {api_result.reason}")
    logger.debug(f"Response: {api_result.text}")

def create_provisioning_rule(api_key, name="nRF Cloud Onboarding", coap=True, sec_tag=16842753, tags=["nrf-cloud-onboarding"]):
    global api_url

    payload = {
        "name": name,
        "description": "Onboarding rule for nRF Cloud",
        "active": True,
        "commands": [
            {"request": {"clientPrivateKeyGeneration": {"secTag": sec_tag}},},
            {"request": {"cloudAccessKeyGeneration": {"secTag": sec_tag}},},
            {"request": {"serverCertificate": {"secTag": sec_tag, "content": ca_certs.get_ca_certs(coap=coap)}},},
        ],
        "tags": tags,
    }

    req = f"{api_url}provisioning-rules"

    return requests.post(req, json=payload, headers=get_auth_header(api_key))


def list_provisioning_rules(api_key):
    global api_url

    req = f"{api_url}provisioning-rules"

    return requests.get(req, headers=get_auth_header(api_key))


def list_provisioning_tags(api_key):
    global api_url

    req = f"{api_url}provisioning/tags"

    return requests.get(req, headers=get_auth_header(api_key))


def create_provisioning_tag(api_key, tag_name, description=""):
    global api_url

    payload = {
        "tag": tag_name,
        "description": description,
    }

    req = f"{api_url}provisioning/tags"

    return requests.post(req, json=payload, headers=get_auth_header(api_key))


def ensure_nrfcloud_provisioning_rule(api_key, sec_tag):
    # Check if the nRF Cloud Onboarding provisioning rule already exists
    found_rule = False
    existing_rules = list_provisioning_rules(api_key)
    if existing_rules.status_code != 200:
        raise RuntimeError('Failed to list existing provisioning rules')
    existing_rules_json = existing_rules.json()
    if existing_rules_json:
        for rule in existing_rules_json["items"]:
            if "nrf-cloud-onboarding" in rule["tags"]:
                found_rule = True
                break

    create_tag_result = create_provisioning_tag(api_key, "nrf-cloud-onboarding", "Generated tag for rule: nRF Cloud Onboarding")

    if not found_rule:
        logger.info('Creating nRF Cloud Onboarding provisioning rule...')
        api_res = create_provisioning_rule(api_key, sec_tag=sec_tag)
        print_api_result("Create provisioning rule response", api_res)
        if api_res.status_code != 201:
            raise RuntimeError('Failed to create nRF Cloud Onboarding provisioning rule')
