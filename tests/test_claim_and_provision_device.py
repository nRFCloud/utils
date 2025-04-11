"""
Test for claim_and_provision_device.py
"""

from unittest.mock import patch, Mock
from serial import Serial
import pytest
from nrfcloud_utils import claim_and_provision_device
from tempfile import TemporaryDirectory
from requests import Response

TEST_ATTESTTOKEN = [b"OK\r\n", b"%ATTESTTOKEN: \"2dn3hQFQUDYxVDkxRPCAIhIbZAFifQNQGv86y_GmR2SiY0wmRsHGVFDT791_BPH8YOWFiyCHND1q.0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY\"\r\n"]
TEST_CGSN = [b"OK\r\n", b"355025930000000\r\n"]
TEST_RESPONSE = Response()
TEST_RESPONSE.status_code = 201
class FakeSerial(Mock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = []
    def write(self, data):
        print(data.__repr__())
        data_str = data.decode('utf-8')
        if data_str.strip().startswith('AT%ATTESTTOKEN'):
            self.response = TEST_ATTESTTOKEN
        elif data_str.strip() == "AT+CGSN":
            self.response = TEST_CGSN
        elif data_str.strip() == "AT+CFUN=4":
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
class TestClaimAndProvisionDevice:
    @patch("nrfcloud_utils.claim_and_provision_device.nrf_cloud_diap")
    @patch("nrfcloud_utils.claim_and_provision_device.get_serial_port", return_value=FakeSerial())
    def test_provisioning_tags(self, ser, diap):
        diap.claim_device = Mock(return_value=TEST_RESPONSE)
        args = f"--port /not/a/real/device --api-key NOTAKEY --noshell --provisioning-tags nrf-cloud-onboarding".split()
        # call DUT
        claim_and_provision_device.main(args)
        diap.claim_device.assert_called_once()

# TODO: test with local CA
