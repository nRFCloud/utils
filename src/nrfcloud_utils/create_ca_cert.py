#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import datetime
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import (
    Name,
    NameAttribute,
    BasicConstraints,
    KeyUsage,
    AuthorityKeyIdentifier,
    SubjectKeyIdentifier,
)

from nrfcloud_utils.cli_helpers import write_file
import coloredlogs, logging

logger = logging.getLogger(__name__)

def parse_args(in_args):
    parser = argparse.ArgumentParser(description="Create CA Certificate")
    parser.add_argument("-c", type=str, help="2 character country code", default="NO")
    parser.add_argument("--st", type=str, help="State or Province", default="")
    parser.add_argument("-l", type=str, help="Locality", default="")
    parser.add_argument("-o", type=str, help="Organization", default="")
    parser.add_argument("--ou", type=str, help="Organizational Unit", default="")
    parser.add_argument("--cn", type=str, help="Common Name", default="example.com")
    parser.add_argument(
        "--dv", type=int, help="Number of days valid", default=(10 * 365)
    )
    parser.add_argument("-e", "--email", type=str, help="E-mail address", default="")
    parser.add_argument(
        "-p", "--path", type=str, help="Path to save PEM files.", default="./"
    )
    parser.add_argument(
        "-f", "--fileprefix", type=str, help="Prefix for output files", default=""
    )
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


def main(in_args):

    args = parse_args(in_args)

    logger.info("Creating self-signed CA certificate...")

    # create EC keypair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # create a self-signed cert
    subject = issuer = Name(
        [
            NameAttribute(NameOID.COUNTRY_NAME, args.c),
            NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, args.st),
            NameAttribute(NameOID.LOCALITY_NAME, args.l),
            NameAttribute(NameOID.ORGANIZATION_NAME, args.o),
            NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, args.ou),
            NameAttribute(NameOID.COMMON_NAME, args.cn),
            NameAttribute(NameOID.EMAIL_ADDRESS, args.email),
        ]
    )

    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=args.dv)
        )
        .add_extension(
            BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .add_extension(
            AuthorityKeyIdentifier.from_issuer_public_key(public_key),
            critical=False,
        )
    )

    cert = cert_builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend()
    )

    ca = cert.public_bytes(serialization.Encoding.PEM)
    priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    write_file(
        args.path, args.fileprefix + str(hex(cert.serial_number)) + "_ca.pem", ca
    )
    write_file(
        args.path, args.fileprefix + str(hex(cert.serial_number)) + "_prv.pem", priv
    )
    write_file(
        args.path, args.fileprefix + str(hex(cert.serial_number)) + "_pub.pem", pub
    )

    return

def run():
    main(sys.argv[1:])

if __name__ == '__main__':
    run()
