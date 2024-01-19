#!/usr/bin/env python3
#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause

import argparse
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_PEM
from modem_credentials_parser import write_file
import ca_certs

def parse_args():
    parser = argparse.ArgumentParser(description="Create Device Credentials")
    parser.add_argument("-ca", type=str, required=True, help="Filepath to your CA cert PEM", default="")
    parser.add_argument("-ca_key", type=str, required=True, help="Filepath to your CA's private key PEM", default="")
    parser.add_argument("-c", type=str, help="2 character country code; required if CSR is not provided", default="")
    parser.add_argument("-st", type=str, help="State or Province; ignored if CSR is provided", default="")
    parser.add_argument("-l", type=str, help="Locality; ignored if CSR is provided", default="")
    parser.add_argument("-o", type=str, help="Organization; ignored if CSR is provided", default="")
    parser.add_argument("-ou", type=str, help="Organizational Unit; ignored if CSR is provided", default="")
    parser.add_argument("-cn", type=str, help="Common Name; use nRF Cloud device ID/MQTT client ID; ignored if CSR is provided", default="")
    parser.add_argument("-e", "--email", type=str, help="E-mail address; ignored if CSR is provided", default="")
    parser.add_argument("-dv", type=int, help="Number of days cert is valid", default=(10 * 365))
    parser.add_argument("-p", "--path", type=str, help="Path to save PEM files.", default="./")
    parser.add_argument("-f", "--fileprefix", type=str, help="Prefix for output files", default="")
    parser.add_argument("-csr", type=str, help="Filepath to CSR PEM from device", default="")
    parser.add_argument("-embed_save", action='store_true',
                        help="Save PEM files (client-cert.pem, private-key.pem, and ca-cert.pem) \
                              formatted to be used with the Kconfig option CONFIG_NRF_CLOUD_PROVISION_CERTIFICATES")
    args = parser.parse_args()
    return args

def load_csr(csr_pem_filepath):

    try:
        csr_file = open(csr_pem_filepath, "rt")
    except OSError:
        raise RuntimeError("Error opening file: " + csr_pem_filepath)

    file_bytes  = csr_file.read()
    csr_file.close()

    try:
        csr_out = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, file_bytes)

    except OpenSSL.crypto.Error:
        raise RuntimeError("Error loading PEM file " + csr_pem_filepath)

    return csr_out

def load_ca(ca_pem_filepath):

    try:
        ca_file = open(ca_pem_filepath, "rt")
    except OSError:
        raise RuntimeError("Error opening file: " + ca_pem_filepath)

    file_bytes  = ca_file.read()
    ca_file.close()

    try:
        ca_out = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, file_bytes)

    except OpenSSL.crypto.Error:
        raise RuntimeError("Error loading PEM file " + ca_pem_filepath)

    return ca_out

def load_ca_key(ca_key_filepath):

    try:
        ca_key_file = open(ca_key_filepath, "rt")
    except OSError:
        raise RuntimeError("Error opening file: " + ca_key_filepath)

    file_bytes  = ca_key_file.read()
    ca_key_file.close()

    key_out = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, file_bytes)

    return key_out

def create_device_cert(dv, csr, pub_key, ca_cert, ca_key):
    device_cert = OpenSSL.crypto.X509()
    serial_no = x509.random_serial_number()
    device_cert.set_serial_number(serial_no)
    device_cert.gmtime_adj_notBefore(0)
    device_cert.gmtime_adj_notAfter(dv * 24 * 60 * 60)
    # use subject and public key from CSR
    device_cert.set_subject(csr.get_subject())
    device_cert.set_pubkey(pub_key)
    # sign with the CA
    device_cert.set_issuer(ca_cert.get_subject())
    device_cert.sign(ca_key, "sha256")
    return device_cert

def embed_save_convert(cred_bytes):
    converted = ''
    for line in cred_bytes.decode().splitlines():
        converted += '\"' + line + '\\n\"\n'
    return converted.encode('utf-8')

# Locally generate a device credential CSR.
# (As opposed requesting one from a modem)
# Also generates local public/private keypair.
def create_local_csr(c = "", st = "", l = "", o = "", ou = "", cn = "", email = ""):
    # create EC keypair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    # format to DER for loading into OpenSSL
    priv_der = private_key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pub_der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # load into OpenSSL
    priv_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_ASN1, priv_der)
    pub_key = OpenSSL.crypto.load_publickey(OpenSSL.crypto.FILETYPE_ASN1, pub_der)

    # create a CSR
    csr = OpenSSL.crypto.X509Req()

    csr.set_version(0)
    csr.add_extensions([OpenSSL.crypto.X509Extension(b'keyUsage', True, b'digitalSignature, nonRepudiation, keyEncipherment, keyAgreement'),])

    # add subject info
    subject = csr.get_subject()

    if len(c):
        subject.C = c

    if len(st):
        subject.ST = st

    if len(l):
        subject.L = l

    if len(o):
        subject.O = o

    if len(ou):
        subject.OU = ou

    if len(cn):
        subject.CN = cn

    if len(email):
        subject.emailAddress = email

    csr.set_pubkey(pub_key)
    csr.sign(priv_key, 'sha256')

    return csr, priv_key

def main():

    if not len(sys.argv) > 1:
        raise RuntimeError("No input provided")

    args = parse_args()
    if (len(args.csr) == 0) and (len(args.c) != 2):
        raise RuntimeError("Required country code must be 2 characters")

    if (len(args.csr) == 0) and (len(args.cn) == 0):
        raise RuntimeError("CN required; use nRF Cloud device ID/MQTT client ID")

    ca_cert = load_ca(args.ca)
    ca_key = load_ca_key(args.ca_key)

    print("Creating device credentials...")

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

    pub_key = csr.get_pubkey()

    # create a device cert
    device_cert = create_device_cert(args.dv, csr, pub_key, ca_cert, ca_key)

    if (csr.get_subject().CN is None) or (len(csr.get_subject().CN) == 0):
        common_name = str(hex(device_cert.get_serial_number()))
    else:
        common_name = csr.get_subject().CN

    # save device cert
    dev   = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, device_cert)
    write_file(args.path, args.fileprefix + common_name + "_crt.pem", dev)
    if args.embed_save:
        write_file(args.path, "client-cert.pem", embed_save_convert(dev))

    # save public key
    pub  = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pub_key)
    write_file(args.path, args.fileprefix + common_name + "_pub.pem", pub)

    # If we generated a local private key, save that to disk too, so it can be installed to the
    # device.
    if local_priv_key is not None:
        priv = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, local_priv_key)
        write_file(args.path, args.fileprefix + common_name + "_prv.pem", priv)
        if args.embed_save:
            write_file(args.path, "private-key.pem", embed_save_convert(priv))

    if args.embed_save:
        # save the AWS CA cert
        write_file(args.path, "ca-cert.pem",
                   embed_save_convert(ca_certs.aws_ca.encode('utf-8')))

    return

if __name__ == '__main__':
    main()
