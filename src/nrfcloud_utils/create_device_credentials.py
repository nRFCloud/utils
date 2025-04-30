#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import sys
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography import x509
import uuid
from cryptography.x509 import (
    Name,
    NameAttribute,
    BasicConstraints,
    KeyUsage,
    AuthorityKeyIdentifier,
    SubjectKeyIdentifier,
)

from nrfcloud_utils.cli_helpers import write_file, save_onboarding_csv
from nrfcloud_utils import ca_certs
import coloredlogs, logging

logger = logging.getLogger(__name__)

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="Create Device Credentials")
    parser.add_argument("--ca", type=str, required=True, help="Filepath to your CA cert PEM", default="")
    parser.add_argument("--ca-key", type=str, required=True, help="Filepath to your CA's private key PEM", default="")
    parser.add_argument("-c", type=str, help="2 character country code; required if CSR is not provided", default="NO")
    parser.add_argument("--st", type=str, help="State or Province; ignored if CSR is provided", default="")
    parser.add_argument("-l", type=str, help="Locality; ignored if CSR is provided", default="")
    parser.add_argument("-o", type=str, help="Organization; ignored if CSR is provided", default="")
    parser.add_argument("--ou", type=str, help="Organizational Unit; ignored if CSR is provided", default="")
    parser.add_argument("--cn", type=str, help="Common Name; use nRF Cloud device ID/MQTT client ID; ignored if CSR is provided", default="")
    parser.add_argument("-e", "--email", type=str, help="E-mail address; ignored if CSR is provided", default="")
    parser.add_argument("--dv", type=int, help="Number of days cert is valid", default=(10 * 365))
    parser.add_argument("-p", "--path", type=str, help="Path to save PEM files.", default="./")
    parser.add_argument("-f", "--fileprefix", type=str, help="Prefix for output files", default="")
    parser.add_argument("--csr", type=str, help="Filepath to CSR PEM from device", default="")
    parser.add_argument("--embed-save", action='store_true',
                        help="Save PEM files (client-cert.pem, private-key.pem, and ca-cert.pem) \
                              formatted to be used with the Kconfig option CONFIG_NRF_CLOUD_PROVISION_CERTIFICATES")
    parser.add_argument("--csv", type=str,
                        help="File path to store onboarding CSV file",
                        default="onboard.csv")
    parser.add_argument("--coap",
                        help="Install the CoAP server root CA cert in addition to the AWS root CA cert",
                        action='store_true', default=False)
    parser.add_argument("--stage", type=str,
                        help="For internal (Nordic) use only", default="")
    parser.add_argument('--log-level',
                        default='info',
                        choices=['debug', 'info', 'warning', 'error', 'critical'],
                        help='Set the logging level'
    )
    args = parser.parse_args(in_args)
    level = getattr(logging, args.log_level.upper(), logging.INFO)
    fmt = '%(levelname)-8s %(message)s'
    coloredlogs.install(level=level, fmt=fmt)
    if len(args.csr) == 0 and len(args.cn) == 0:
        args.cn = str(uuid.uuid4())
    return args

def load_csr(csr_pem_filepath):
    with open(csr_pem_filepath, "rb") as f:
        csr_data = f.read()

    return x509.load_pem_x509_csr(csr_data)

def load_ca(ca_pem_filepath):
    with open(ca_pem_filepath, "rb") as f:
        ca_data = f.read()

    return x509.load_pem_x509_certificate(ca_data)

def load_ca_key(ca_key_filepath):
    with open(ca_key_filepath, "rb") as f:
        key_data = f.read()

    return serialization.load_pem_private_key(key_data, password=None)

def csr_get_cn(csr):
    cn_list = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(cn_list) == 0:
        return ""
    return cn_list[0].value

def create_device_cert(dv, csr, ca_cert, ca_key):
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=dv)
    ).sign(ca_key, hashes.SHA256())

    return cert


def embed_save_convert(cred_bytes):
    converted = ''
    for line in cred_bytes.decode().splitlines():
        converted += '\"' + line + '\\n\"\n'
    return converted.encode('utf-8')

# Locally generate a device credential CSR.
# (As opposed requesting one from a modem)
# Also generates local public/private keypair.
def create_local_csr(c = "", st = "", l = "", o = "", ou = "", cn = "", email = ""):
    logger.warning("Generating private key locally is not recommended. Private keys should never leave the device.")
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    name_attributes = [
        (NameOID.COUNTRY_NAME, c),
        (NameOID.STATE_OR_PROVINCE_NAME, st),
        (NameOID.LOCALITY_NAME, l),
        (NameOID.ORGANIZATION_NAME, o),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, ou),
        (NameOID.COMMON_NAME, cn),
        (NameOID.EMAIL_ADDRESS, email),
    ]
    name_attributes = [x509.NameAttribute(oid, value) for oid, value in name_attributes if value]

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(name_attributes)
    ).add_extension(
        KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                key_agreement=True,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
        ),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    return csr, private_key

def main(in_args):
    args = parse_args(in_args)

    ca_cert = load_ca(args.ca)
    ca_key = load_ca_key(args.ca_key)

    logger.info("Creating device credentials...")

    local_priv_key = None

    if (len(args.csr)):
        # load CSR from provided file
        csr = load_csr(args.csr)
    else:
        csr, local_priv_key = create_local_csr(
            c       = args.c,
            st      = args.st,
            l       = args.l,
            o       = args.o,
            ou      = args.ou,
            cn      = args.cn,
            email   = args.email
        )

    # create a device cert
    device_cert = create_device_cert(args.dv, csr, ca_cert, ca_key)

    common_name = csr_get_cn(csr)

    if common_name == "":
        common_name = str(hex(device_cert.serial_number))

    # save device cert
    dev   = device_cert.public_bytes(serialization.Encoding.PEM)
    if args.embed_save:
        write_file(args.path, "client-cert.pem", embed_save_convert(dev))
    else:
        write_file(args.path, args.fileprefix + common_name + "_crt.pem", dev)

    # save public key
    pub  = csr.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    if not args.embed_save:
        write_file(args.path, args.fileprefix + common_name + "_pub.pem", pub)

    # If we generated a local private key, save that to disk too, so it can be installed to the
    # device.
    if local_priv_key is not None:
        priv = local_priv_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        if args.embed_save:
            write_file(args.path, "private-key.pem", embed_save_convert(priv))
        else:
            write_file(args.path, args.fileprefix + common_name + "_prv.pem", priv)


    if args.embed_save:
        # save the AWS CA cert
        write_file(args.path, "ca-cert.pem",
                   embed_save_convert(ca_certs.get_ca_certs(args.coap, stage=args.stage).encode('utf-8')))

    if len(args.csv) > 0:
        save_onboarding_csv(args.csv,
        append=True, replace=False,
        dev_id=common_name,
        sub_type='', tags='', fw_types='',
        dev=dev)

    return

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
