"""
Test for device_credentials_installer.py
"""

from unittest.mock import patch, Mock
from serial import Serial
import pytest
from nrfcloud_utils import device_credentials_installer
from tempfile import TemporaryDirectory
import os
from collections import namedtuple

TEST_KEYGEN_UUID = [b"OK\r\n", b"%KEYGEN: \"MIIBCzCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2Mzk1My0zMjM0LTQ3MjMtODBiOS0xNTAzZDg4MjcxYmYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ37lDghqs2kF2iiH8lYRDDxNMiziQRPPdw9Meb1iHfTEZNdlB1xZzMV-oK6i52p1GHYQszjoDzUAZF2zU2MTGGoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANJADBGAiEAzaMPi5NcWFYZBJGBMk0tU-TBoNDVlQUzhHWJzXKRTWsCIQCWYpYqjccA281F5Geb8SwOP3tnjS_ZbAXUgVWhTVNuvg.0oRDoQEmoQRBIVhM2dn3hQlQUDY5UzI0RyOAuRUD2IJxv0IYNFggTaa7Z9K-8bQPz3YG5o_h32quNr0FHEtnX5VpEZ-8gflQY8D67v4xx32mF0L3-mbuuVhAfY3TgibaimIVPaN1C3Sz_oWj6JPf8sEOV2XNBDUNCV3sD3WdNOjgv32-rLXAx_vBIvpk1DTCb3Y97zqFhhdKlw\"\r\n"]
TEST_KEYGEN_IMEI = [b"OK\r\n", b"%KEYGEN: \"MIH4MIGeAgEAMB4xHDAaBgNVBAMME25yZi0zNTUwMjU5MzAwMDAwMDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATYRrWI0v6LJWciuTlscw8E1TcOBJoygkALKecquhe-fr_QT_tcjC2DgmDyX1cjTubp7n_mUaf5ZJ1s-Ke-ABBuoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANHADBEAiBDTS-I_ye8nJpB7vtO6FQWvnUhJnG6QsjRPo56nBFh2gIgPB5NW16dANAMmn0VLMBXGeRPTtoxOs5Ld1Z7JW46_8s.0oRDoQEmoQRBIVhM2dn3hQlQUDQ5VjA3RziADR8p4KD3v0IYNFggl3ygk__l-pZ9jtlsf0AyuFJlRaaEouhzYgau2zOcHwBQp2eEbVMiHVcHrE9R2670dlhA1a7jaKq3ALRx2h-h2TIkxxh82oyr4c4LqzraUecL8SFek-IbvEBfv30695FKOt3FXEk7y5G_JW3yaRQGczL3TQ\"\r\n"]
TEST_CA_FILE = "tests/fixtures/test_ca.pem"
TEST_CA_KEY_FILE = "tests/fixtures/test_ca_prv.pem"
TEST_CGSN = [b"OK\r\n", b"355025930000000\r\n"]

class FakeSerial(Mock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = []
    def write(self, data):
        data_str = data.decode('utf-8')
        if data_str.strip() == ('AT%KEYGEN=52,2,0'):
            self.response = TEST_KEYGEN_UUID.copy()
        elif data_str.strip() == ('AT%KEYGEN=52,2,0,"CN=nrf-355025930000000"'):
            self.response = TEST_KEYGEN_IMEI.copy()
        elif data_str.strip() == "AT+CGSN":
            self.response = TEST_CGSN.copy()
        elif data_str.strip() == "AT+CFUN=4":
            self.response = [b"OK\r\n"]
        elif data_str.strip() == "AT+CGMR":
            self.response = [b"OK\r\n", b"mfw_nrf91x1_2.0.2\r\n"]
        elif data_str.strip().startswith("AT%CMNG=0,52,0,\""):
            self.response = [b"OK\r\n"]
        elif data_str.strip().startswith("AT%CMNG=0,52,1,\""):
            self.response = [b"OK\r\n"]
        elif len(data_str.strip()) == 0:
            self.response = [b"OK\r\n"]
        else:
            self.response = [b"ERROR\r\n"]
    def readline(self):
        if len(self.response) == 0:
            return b""
        response = self.response.pop()
        return response

FakeSerialPort = namedtuple("FakeSerialPort", ["device"])

class TestDeviceCredentialsInstaller:
    @patch("nrfcredstore.comms.select_device", return_value=(FakeSerialPort("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcredstore.comms.serial.Serial", return_value=FakeSerial())
    def test_minimal_case(self, ser, select_device):
        with TemporaryDirectory() as tmp_dir:
            csv_file = os.path.join(tmp_dir, 'onboard.csv')
            args = f"--port /not/a/real/device --log-level debug --cmd-type at --ca {TEST_CA_FILE} --ca-key {TEST_CA_KEY_FILE} --csv {csv_file} --term CRLF --sectag 52".split()
            # call DUT
            device_credentials_installer.main(args)
            # check that the file was created
            assert os.path.exists(csv_file)
            # check that the file has the expected contents
            with open(csv_file, "r") as f:
                content = f.read().strip()
            device_id, sub_type, tags, fw_types, cert_pem = content.split(",")
            cert_pem = cert_pem.replace("\"", "").strip()
            assert device_id == "50363953-3234-4723-80b9-1503d88271bf"
            assert fw_types == "APP|MODEM"
            assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
            assert cert_pem.endswith("-----END CERTIFICATE-----")

    @patch("nrfcredstore.comms.select_device", return_value=(FakeSerialPort("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcredstore.comms.serial.Serial", return_value=FakeSerial())
    def test_nrf_prefix(self, ser, select_device):
        with TemporaryDirectory() as tmp_dir:
            csv_file = os.path.join(tmp_dir, 'onboard.csv')
            args = f"--port /not/a/real/device --log-level debug --id-imei --id-str nrf- --cmd-type at --ca {TEST_CA_FILE} --ca-key {TEST_CA_KEY_FILE} --csv {csv_file} --term CRLF --sectag 52".split()
            # call DUT
            device_credentials_installer.main(args)
            # check that the file was created
            assert os.path.exists(csv_file)
            # check that the file has the expected contents
            with open(csv_file, "r") as f:
                content = f.read().strip()
            device_id, sub_type, tags, fw_types, cert_pem = content.split(",")
            cert_pem = cert_pem.replace("\"", "").strip()
            assert device_id == "nrf-355025930000000"
            assert fw_types == "APP|MODEM"
            assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
            assert cert_pem.endswith("-----END CERTIFICATE-----")
