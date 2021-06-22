#!/usr/bin/env python3
#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

import argparse
import sys
from os import path
from os import makedirs
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM

from modem_credentials_parser import write_file

def parse_args():
    parser = argparse.ArgumentParser(description="Create CA Certificate")
    parser.add_argument("-c", type=str, required=True, help="2 character country code", default="")
    parser.add_argument("-st", type=str, help="State or Province", default="")
    parser.add_argument("-l", type=str, help="Locality", default="")
    parser.add_argument("-o", type=str, help="Organization", default="")
    parser.add_argument("-ou", type=str, help="Organizational Unit", default="")
    parser.add_argument("-cn", type=str, help="Common Name", default="")
    parser.add_argument("-dv", type=int, help="Number of days valid", default=(10 * 365))
    parser.add_argument("-e", "--email", type=str, help="E-mail address", default="")
    parser.add_argument("-p", "--path", type=str, help="Path to save PEM files.", default="./")
    parser.add_argument("-f", "--fileprefix", type=str, help="Prefix for output files", default="")
    args = parser.parse_args()
    return args

def main():

    if not len(sys.argv) > 1:
        raise RuntimeError("No input provided")

    args = parse_args()
    if len(args.c) != 2:
        raise RuntimeError("Country code must be 2 characters")

    print("Creating self-signed CA certificate...")

    # create EC keypair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # format to DER for loading into OpenSSL
    priv_der = private_key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pub_der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # load into OpenSSL
    priv_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_ASN1, priv_der)
    pub_key = OpenSSL.crypto.load_publickey(OpenSSL.crypto.FILETYPE_ASN1, pub_der)

    # create a self-signed cert
    cert = OpenSSL.crypto.X509()

    cert.set_version(2)
    cert.add_extensions(
        [OpenSSL.crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert),])
    cert.add_extensions([
        OpenSSL.crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=cert),])
    cert.add_extensions([
        OpenSSL.crypto.X509Extension(b'basicConstraints', False, b'CA:TRUE'),
        OpenSSL.crypto.X509Extension(b'keyUsage', True, b'cRLSign, digitalSignature, keyCertSign'),])

    # add subject info
    if len(args.c):
        cert.get_subject().C = args.c

    if len(args.st):
        cert.get_subject().ST = args.st

    if len(args.l):
        cert.get_subject().L = args.l

    if len(args.o):
        cert.get_subject().O = args.o

    if len(args.ou):
        cert.get_subject().OU = args.ou

    if len(args.cn):
        cert.get_subject().CN = args.cn

    if len(args.email):
        cert.get_subject().emailAddress = args.email

    # set validity time
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(args.dv * 24 * 60 * 60)

    # self-signed... issuer == subject
    cert.set_issuer(cert.get_subject())

    cert.set_pubkey(pub_key)

    sn = x509.random_serial_number()
    cert.set_serial_number(sn)

    cert.sign(priv_key, 'sha256')

    ca   = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    priv = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, priv_key)
    pub  = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pub_key)

    write_file(args.path, args.fileprefix + str(hex(sn)) + "_ca.pem", ca)
    write_file(args.path, args.fileprefix + str(hex(sn)) + "_prv.pem", priv)
    write_file(args.path, args.fileprefix + str(hex(sn)) + "_pub.pem", pub)

    return

if __name__ == '__main__':
    main()
