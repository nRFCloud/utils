"""
Test for create_device_credentials.py
"""

import pytest

from unittest.mock import Mock
from nrfcloud_utils import create_device_credentials
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import os
import datetime

CA_FILE = "tests/fixtures/test_ca.pem"
CA_KEY_FILE = "tests/fixtures/test_ca_prv.pem"
CA_CN = "nrfcloud.com"

CSR_FILE = "tests/fixtures/example-id_csr.pem"
CSR_CN = "example-id"

def import_result_files(tmp_dir, expect_private_key):
    files = os.listdir(tmp_dir)
    cert_file = os.path.join(tmp_dir, [x for x in files if x.endswith("_crt.pem")][0])
    public_key_file = os.path.join(tmp_dir, [x for x in files if x.endswith("_pub.pem")][0])

    with open(cert_file, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(public_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    if expect_private_key:
        private_key_file = os.path.join(tmp_dir, [x for x in files if x.endswith("_prv.pem")][0])
        with open(private_key_file, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        private_key = None

    return cert, private_key, public_key

class TestCreateCACert:
    def test_minimal_args(self):
        with TemporaryDirectory() as tmp_dir:
            create_device_credentials.main([
            "--ca", CA_FILE,
            "--ca-key", CA_KEY_FILE,
            "--cn", "test",
            "--path", tmp_dir
            ])
            files = os.listdir(tmp_dir)
            files = [x for x in files if x.startswith("test")]
            assert len(files) == 3

            # load files
            cert, private_key, public_key = import_result_files(tmp_dir, expect_private_key=True)

            # check the subject contents
            assert cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == CA_CN
            assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "test"

    def test_full_args(self):
        with TemporaryDirectory() as tmp_dir:
            create_device_credentials.main([
                "--ca", CA_FILE,
                "--ca-key", CA_KEY_FILE,
                "-c", "NO",
                "--st", "Trondheim",
                "-l", "Trøndelag",
                "-o", "Nordic Semiconductor",
                "--ou", "nRF Cloud",
                "--cn", "test",
                "-e", "bar@nrfcloud.com",
                "--dv", "365",
                "-f", "prefix-",
                "--path", tmp_dir
            ])
            files = os.listdir(tmp_dir)
            files = [x for x in files if x.startswith("prefix-test")]
            assert len(files) == 3

            # load files
            cert, private_key, public_key = import_result_files(tmp_dir, expect_private_key=True)

            # check the subject contents
            assert cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == CA_CN
            assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "test"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Trondheim"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)[0].value == "Trøndelag"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value == "Nordic Semiconductor"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "nRF Cloud"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value == "bar@nrfcloud.com"

            # check the times
            assert cert.not_valid_after - cert.not_valid_before == datetime.timedelta(days=365)
            # not_valid_before should be in the past and not longer than an hour ago
            not_valid_before_utc = datetime.datetime(
                cert.not_valid_before.year,
                cert.not_valid_before.month,
                cert.not_valid_before.day,
                cert.not_valid_before.hour,
                cert.not_valid_before.minute,
                cert.not_valid_before.second,
                tzinfo=datetime.timezone.utc
            )
            assert not_valid_before_utc < datetime.datetime.now(datetime.timezone.utc)
            assert not_valid_before_utc > (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1))

            # check the keys
            assert cert.public_key().public_numbers() == public_key.public_numbers()
            assert private_key.public_key().public_numbers() == public_key.public_numbers()


    def test_with_csr(self):
        with TemporaryDirectory() as tmp_dir:
            create_device_credentials.main([
                "--ca", CA_FILE,
                "--ca-key", CA_KEY_FILE,
                "--csr", CSR_FILE,
                "--path", tmp_dir
            ])
            files = os.listdir(tmp_dir)
            files = [x for x in files if x.startswith(CSR_CN)]
            assert len(files) == 2

            # load files
            cert, _, public_key = import_result_files(tmp_dir, expect_private_key=False)

            # check the subject contents
            assert cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == CA_CN
            assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == CSR_CN
