"""
Test for create_ca_cert.py
"""

import pytest

from unittest.mock import Mock
from nrfcloud_utils import create_ca_cert
from tempfile import TemporaryDirectory
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import os
import datetime

def import_result_files(tmp_dir):
    files = os.listdir(tmp_dir)
    assert len(files) == 3
    cert_file = os.path.join(tmp_dir, [x for x in files if x.endswith("_ca.pem")][0])
    private_key_file = os.path.join(tmp_dir, [x for x in files if x.endswith("_prv.pem")][0])
    public_key_file = os.path.join(tmp_dir, [x for x in files if x.endswith("_pub.pem")][0])

    with open(cert_file, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    with open(private_key_file, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(public_key_file, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    return cert, private_key, public_key

class TestCreateCACert:
    def test_minimal_args(self):
        with TemporaryDirectory() as tmp_dir:
            create_ca_cert.main(["-p", tmp_dir])
            cert, private_key, public_key = import_result_files(tmp_dir)

    def test_full_args(self):
        with TemporaryDirectory() as tmp_dir:
            create_ca_cert.main([
                "-c", "NO",
                "--st", "Trondheim",
                "-l", "Trøndelag",
                "-o", "Nordic Semiconductor",
                "--ou", "nRF Cloud",
                "--cn", "nrfcloud.com",
                "--dv", "365",
                "-e", "foo@nrfcloud.com",
                "-p", tmp_dir,
                "-f", "test"
            ])
            # check that the prefix is used
            files = os.listdir(tmp_dir)
            files = [x for x in files if x.startswith("test")]
            assert len(files) == 3

            # load files
            cert, private_key, public_key = import_result_files(tmp_dir)

            # check the subject contents
            assert cert.subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value == "NO"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.STATE_OR_PROVINCE_NAME)[0].value == "Trondheim"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.LOCALITY_NAME)[0].value == "Trøndelag"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value == "Nordic Semiconductor"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value == "nRF Cloud"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "nrfcloud.com"
            assert cert.subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value == "foo@nrfcloud.com"

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
            assert cert.issuer == cert.subject
            assert cert.public_key().public_numbers() == public_key.public_numbers()
            assert private_key.public_key().public_numbers() == public_key.public_numbers()



