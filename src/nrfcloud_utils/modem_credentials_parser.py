#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import sys
from os import path
from os import makedirs
from cbor2 import loads
import base64
import hashlib
import coloredlogs, logging
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from nrfcloud_utils.cli_helpers import write_file

logger = logging.getLogger(__name__)

msg_type_dict = {
    1: 'Device identity message v1',
    2: 'Public key message v1',
    3: 'CSR message v1',
    5: 'Provisioning response v1'
}
device_type_dict = {
    1: 'nRF9160 SIAA',
    2: 'nRF9160 SIBA',
    3: 'NRF9160 SIAA',
    4: 'nRF9161 LACA',
    5: 'nRF9131 LACA',
    6: 'nRF9151 LACA',
}
payload_id_dict = {
    8: 'pubkey_msg_v2',
    9: 'CSR_msg_v1'
}
header_key_type_dict = {
    -7: 'ECDSA w/ SHA-256',
    -2: 'identity_key',
    -4: 'nordic_base_production_key',
    -5: 'nordic_base_rd_key'
}

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="Modem Credentials Parser")
    parser.add_argument("-k", "--keygen", type=str, help="base64url string: KEYGEN output", default="")
    parser.add_argument("-a", "--attest", type=str, help="base64url string: ATTESTTOKEN output", default="")
    parser.add_argument("-s", "--save", action='store_true', help="Save PEM file(s): <UUID>_<sec_tag>_<type>.pem")
    parser.add_argument("-p", "--path", type=str, help="Path to save PEM file.  Selects -s", default="")
    parser.add_argument("-f", "--fileprefix", type=str, help="Prefix for output files (<prefix><UUID>_<sec_tag>_<type>.pem). Selects -s", default="")
    parser.add_argument('--log-level',
                        default='info',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level'
    )
    parser.add_argument("-P", "--plain",
                        help="bool: Plain output (no colors)",
                        action='store_true', default=False)
    args = parser.parse_args(in_args)
    if args.plain:
        logging.basicConfig(level=args.log_level.upper())
    else:
        coloredlogs.install(level=args.log_level.upper(), fmt='%(levelname)-8s %(message)s')
    return args

def base64_decode(string):
    """
    add padding before decoding.
    """
    padding = 4 - (len(string) % 4)
    string = string + ("=" * padding)
    return base64.urlsafe_b64decode(string)

def format_uuid(hex_str):
    return '{0}-{1}-{2}-{3}-{4}'.format(hex_str[:8],    hex_str[8:12],
                                        hex_str[12:16], hex_str[16:20],
                                        hex_str[20:]).lower()

def parse_cose(cose_str, payload_digest=""):
    """
    parse COSE payload.
    """
    if len(cose_str) == 0:
        return None, None

    dev_uuid_hex_str = None
    sec_tag_str = None

    # Decode to binary and parse cbor
    cose_bytes = base64_decode(cose_str)
    cose_obj = loads(cose_bytes)

    logger.info("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
    logger.info("COSE:")

    # print protected header info
    phdr_obj = loads(cose_obj.value[0])
    for key in phdr_obj.keys():
        logger.info("  Prot Hdr:   " + str(key) + " : " +
              str(phdr_obj[key]) + " (" +
              header_key_type_dict.get(phdr_obj[key]) + ")")

    # the unprotected header contains a map (and another cose object)
    for key in cose_obj.value[1].keys():
        unphdr_obj = loads(cose_obj.value[1].get(key))
        logger.info("  Unprot Hdr: " + str(key)  + " : " +
              str(unphdr_obj) + " (" +
              header_key_type_dict.get(unphdr_obj) + ")")

    # The COSE payload may contain a cbor attestation payload
    # If present, decode the cbor and print
    logger.info("  ---------------")
    logger.info("  Attestation:")
    if str(cose_obj.value[2]) != "None":
        attest_obj = loads(cose_obj.value[2])
        logger.info("    Payload ID: " + payload_id_dict.get(attest_obj[0]))
        dev_uuid_hex_str = format_uuid(attest_obj[1].hex())
        logger.info("    Dev UUID:   " + dev_uuid_hex_str)
        # sec_tag is another cbor object
        sec_tag = loads(attest_obj[2])
        if sec_tag < 0:
            # sec_tag was encoded as a negative integer, convert it to unsigned
            sec_tag = (-sec_tag ^ 0xFFFFFFFF) + 1
        sec_tag_str = str(sec_tag)
        logger.info("    sec_tag:    " + sec_tag_str)
        # SHA256 digest of cert/key in the payload
        logger.info("    SHA256:     " + attest_obj[3].hex())
        logger.info("    Nonce:      " + attest_obj[4].hex())
    else:
        logger.info("    Not present")
    logger.info("  ---------------")

    # print the 64-bit signature
    logger.info("  Sig:")
    logger.info("      " + cose_obj.value[3].hex())

    if len(payload_digest) > 0:
        if attest_obj[3].hex() == payload_digest:
            logger.info("COSE digest matches payload")
        else:
            logger.info("COSE digest does NOT match payload")
    logger.info("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")

    return dev_uuid_hex_str, sec_tag_str

def save_output(dev_uuid_hex_str, sec_tag_str, csr_pem_bytes, pub_key_bytes, path, prefix):
    """
    save CSR/key data to PEM file(s)
    """

    if (len(dev_uuid_hex_str) <= 0):
        raise RuntimeError("Device UUID not found. Full KEYGEN output must be provided.")

    filename = prefix + dev_uuid_hex_str + "_" + sec_tag_str

    if(len(csr_pem_bytes)):
        write_file(path, filename + "_csr.pem", csr_pem_bytes)

    if(len(pub_key_bytes)):
        write_file(path, filename + "_pub.pem", pub_key_bytes)

    return

def parse_keygen_output(keygen_str):
    """
    parse keygen output.
    """
    logger.info("Parsing AT%KEYGEN output:")

    csr_pem_bytes = None
    pub_key_bytes = None

    # Input format: <base64url_body>.<base64url_cose>
    #               cose portion is optional
    body_cose = keygen_str.split('.')
    body = body_cose[0]

    # Decode base64url to binary
    body_bytes = base64_decode(body)

    # This can be either a CSR or device public key
    try:
        # Try to load CSR, if it fails, assume public key
        csr = x509.load_der_x509_csr(body_bytes)

    except ValueError:
        # Handle public key only
        pub_key = serialization.load_der_public_key(body_bytes)
        pub_key_bytes = pub_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    else:
        # CSR loaded, logger.info it
        csr_pem_bytes = csr.public_bytes(serialization.Encoding.PEM)
        csr_pem_list = str(csr_pem_bytes.decode()).split('\n')
        logger.info(csr_pem_bytes.decode().replace('\n', '\\n'))

        # Extract public key
        pub_key_bytes = csr.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    logger.info("Device public key: {}".format(pub_key_bytes.decode().replace('\n', '\\n')))

    payload_digest = hashlib.sha256(body_bytes).hexdigest()
    logger.info(f"SHA256 Digest: {payload_digest}")

    # Get optional cose
    cose = ""
    if len(body_cose) > 1:
        cose = body_cose[1]

    dev_uuid_hex_str, sec_tag_str = parse_cose(cose, payload_digest)

    return csr_pem_bytes, pub_key_bytes, dev_uuid_hex_str, sec_tag_str

def parse_attesttoken_output(atokout_str):
    logger.info("Parsing AT%ATTESTTOKEN output:")

    # Input format: <base64url_body>.<base64url_cose>
    #               cose portion is optional
    body_cose = atokout_str.split('.')
    body = body_cose[0]

    # Decode base64url to binary
    body_bytes = base64_decode(body)
    # Load into CBOR parser
    body_obj = loads(body_bytes)

    dev_type = device_type_dict.get(body_obj[2])
    if not dev_type:
        dev_type = f"Unknown:{body_obj[2]}"

    # print parsed CBOR
    logger.info("---------------")
    logger.info("Msg Type:    " + msg_type_dict[body_obj[0]])
    logger.info("Dev UUID:    " + format_uuid(body_obj[1].hex()))
    logger.info("Dev Type:    " + dev_type)
    logger.info("FW UUID:     " + format_uuid(body_obj[3].hex()))
    logger.info("---------------")

    # Get optional cose
    cose = ""
    if len(body_cose) > 1:
        cose = body_cose[1]

    return parse_cose(cose)

def get_device_uuid(attest_tok):

    # Input format: <base64url_body>.<base64url_cose>
    #               cose portion is optional
    body_cose = attest_tok.split('.')
    body = body_cose[0]

    # Decode base64url to binary
    body_bytes = base64_decode(body)
    # Load into CBOR parser
    body_obj = loads(body_bytes)

    return format_uuid(body_obj[1].hex())

def main(in_args):
    args = parse_args(in_args)

    if len(args.keygen) > 0:
        csr_pem_bytes, pub_key_bytes, dev_uuid_hex_str, sec_tag_str = \
            parse_keygen_output(args.keygen)
    elif len(args.attest) > 0:
        dev_uuid_hex_str, sec_tag_str = parse_attesttoken_output(args.attest)
    else:
        raise RuntimeError("No input data provided")

    if (args.save == False) and ((len(args.path) > 0) or (len(args.fileprefix) > 0)):
        args.save = True
        logger.info("Argument -s has been selected since path/fileprefix was specified")

    if (args.save) and (len(args.keygen) > 0):
        if (len(args.path) == 0):
            args.path = "./"
        save_output(dev_uuid_hex_str, sec_tag_str, csr_pem_bytes, pub_key_bytes,
            args.path, args.fileprefix)

    return

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
