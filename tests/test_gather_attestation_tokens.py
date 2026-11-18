"""
Test for gather_attestation_tokens.py
"""

from unittest.mock import patch, Mock
from nrfcloud_utils import gather_attestation_tokens
import sys
import pytest
from collections import namedtuple

TEST_UUID = "50363154-3931-44f0-8022-121b6401627d"
TEST_TOKEN = "2dn3hQFQUDYxVDkxRPCAIhIbZAFifQNQGv86y_GmR2SiY0wmRsHGVFDT791_BPH8YOWFiyCHND1q.0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY"
TEST_ATTESTTOKEN = [b"OK\r\n", f'%ATTESTTOKEN: "{TEST_TOKEN}"\r\n'.encode()]
TEST_CGSN = [b"OK\r\n", b"355025930000000\r\n"]
TEST_CGMM = [b"OK\r\n", b"nRF9151-LACA\r\n"]
CSV_HEADER = "deviceId,attestationToken\n"
OTHER_ROW = "cafe0001-0000-0000-0000-000000000001,other-token\n"

class FakeSerial(Mock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = []
    def write(self, data):
        print(data.__repr__())
        data_str = data.decode('utf-8')
        if data_str.strip().startswith('AT%ATTESTTOKEN'):
            self.response = TEST_ATTESTTOKEN.copy()
        elif data_str.strip() == "AT+CGSN":
            self.response = TEST_CGSN.copy()
        elif data_str.strip() == "AT+CGMM":
            self.response = TEST_CGMM.copy()
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

def _gather(csv_file, extra_args=""):
    args = f"--port /not/a/real/device --cmd-type at --csv {csv_file} {extra_args}".split()
    with patch("nrfcredstore.comms.select_device", return_value=(FakeSerialPort("/not/a/real/device"), "TEST_DEVICE")), \
         patch("nrfcredstore.comms.serial.Serial", return_value=FakeSerial()):
        gather_attestation_tokens.main(args)

class TestGatherAttestationTokens:
    def test_minimal_case(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        _gather(csv_file)
        assert csv_file.read_text() == CSV_HEADER + f"{TEST_UUID},{TEST_TOKEN}\n"

    def test_replaces_token_of_known_device(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        csv_file.write_text(CSV_HEADER + f"{TEST_UUID},old-token\n" + OTHER_ROW)
        _gather(csv_file)
        assert csv_file.read_text() == CSV_HEADER + OTHER_ROW + f"{TEST_UUID},{TEST_TOKEN}\n"

    def test_keep(self, tmp_path):
        csv_file = tmp_path / "tokens.csv"
        content = CSV_HEADER + f"{TEST_UUID},old-token\n" + OTHER_ROW
        csv_file.write_text(content)
        _gather(csv_file, "--keep")
        assert csv_file.read_text() == content

    def test_rejects_file_from_earlier_version(self, tmp_path):
        # earlier versions wrote imei,uuid,token,timestamp rows without a header row
        csv_file = tmp_path / "tokens.csv"
        content = f"355025930000000,{TEST_UUID},{TEST_TOKEN},2026-01-01T00:00:00+00:00\n"
        csv_file.write_text(content)
        with pytest.raises(SystemExit) as e:
            _gather(csv_file)
        assert e.value.code == 1
        assert csv_file.read_text() == content

    def test_rtt_without_pynrfjprog(self, caplog):
        # pynrfjprog is only installed with the 'rtt' extra
        with patch.dict(sys.modules, {"pynrfjprog": None}), pytest.raises(SystemExit) as e:
            gather_attestation_tokens.main("--rtt --cmd-type at".split())
        assert e.value.code == 1
        assert 'pip install "nrfcloud-utils[rtt]"' in caplog.text



