"""
Test for gather_attestation_tokens.py
"""

from unittest.mock import patch, Mock
from serial import Serial
import pytest
from nrfcloud_utils import gather_attestation_tokens
from tempfile import TemporaryDirectory
import os
import datetime

TEST_ATTESTTOKEN = [b"OK\r\n", b"%ATTESTTOKEN: \"2dn3hQFQUDYxVDkxRPCAIhIbZAFifQNQGv86y_GmR2SiY0wmRsHGVFDT791_BPH8YOWFiyCHND1q.0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY\"\r\n"]
TEST_CGSN = [b"OK\r\n", b"355025930000000\r\n"]

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
        elif len(data_str.strip()) == 0:
            self.response = [b"OK\r\n"]
        else:
            self.response = [b"ERROR\r\n"]
    def readline(self):
        if len(self.response) == 0:
            return b""
        response = self.response.pop()
        return response

class TestGatherAttestationTokens:
    @patch("nrfcloud_utils.gather_attestation_tokens.get_serial_port", return_value=FakeSerial())
    def test_minimal_case(self, ser):
        with TemporaryDirectory() as tmp_dir:
            csv_file = os.path.join(tmp_dir, 'tokens.csv')
            args = f"--port /not/a/real/device --csv {csv_file}".split()
            # call DUT
            gather_attestation_tokens.main(args)
            # check that the file was created
            assert os.path.exists(csv_file)
            # check that the file has the expected contents
            with open(csv_file, "r") as f:
                content = f.read().strip()
                imei, uuid, token, readout_time = content.split(",")
                assert imei == "355025930000000"
                assert uuid == "50363154-3931-44f0-8022-121b6401627d"
                assert datetime.datetime.fromisoformat(readout_time).date() == datetime.datetime.now().date()



