"""
Tests for nrf91_gather_self_signed_certs.py
"""

import os
import csv
from collections import namedtuple
from tempfile import TemporaryDirectory
from unittest.mock import patch, Mock, MagicMock

import pytest

from nrfcloud_utils import nrf91_gather_self_signed_certs as dut


TEST_UUID = "50363154-3931-44f0-8022-121b6401627d"
TEST_KEYGEN_BLOB = (
    "MIIBCzCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0xMjFiNjQwMTYyN2Q"
    ".0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY"
)
TEST_MFW_VERSION_OK = "mfw_nrf91x1_2.0.4"
TEST_MFW_VERSION_TOO_OLD = "mfw_nrf91x1_2.0.1"


def make_cred_if(at_command_retval=True, expect_retval=True, expect_output=""):
    cred_if = Mock()
    cred_if.at_command.return_value = at_command_retval
    cred_if.comms.expect_response.return_value = (expect_retval, expect_output)
    return cred_if


# ---------------------------------------------------------------------------
# get_device_uuid
# ---------------------------------------------------------------------------

class TestGetDeviceUuid:
    def test_success(self):
        output = f"%DEVICEUUID: {TEST_UUID}\nOK\n"
        cred_if = make_cred_if(expect_output=output)
        assert dut.get_device_uuid(cred_if) == TEST_UUID
        cred_if.at_command.assert_called_once_with("AT%DEVICEUUID", wait_for_result=False)

    def test_at_command_fails(self):
        cred_if = make_cred_if(at_command_retval=False)
        assert dut.get_device_uuid(cred_if) is None

    def test_expect_response_fails(self):
        cred_if = make_cred_if(expect_retval=False)
        assert dut.get_device_uuid(cred_if) is None

    def test_uuid_not_in_response(self):
        cred_if = make_cred_if(expect_output="OK\n")
        assert dut.get_device_uuid(cred_if) is None

    def test_empty_uuid_value_rejected(self):
        cred_if = make_cred_if(expect_output="%DEVICEUUID: \nOK\n")
        assert dut.get_device_uuid(cred_if) is None


# ---------------------------------------------------------------------------
# gen_self_signed_cert
# ---------------------------------------------------------------------------

class TestGenSelfSignedCert:
    def test_success_strips_quotes(self):
        output = f'%KEYGEN: "{TEST_KEYGEN_BLOB}"\nOK\n'
        cred_if = make_cred_if(expect_output=output)
        result = dut.gen_self_signed_cert(cred_if, dut.DEFAULT_SECTAG)
        assert result == TEST_KEYGEN_BLOB

    def test_command_uses_14_2_params(self):
        # Lock in the AT%KEYGEN parameters (sectag,14,2 for self-signed cert,
        # NOT sectag,2,0 which is for CSR).
        cred_if = make_cred_if(expect_output=f'%KEYGEN: "{TEST_KEYGEN_BLOB}"\nOK\n')
        dut.gen_self_signed_cert(cred_if, 16842753)
        cred_if.at_command.assert_called_once_with(
            "AT%KEYGEN=16842753,14,2", wait_for_result=False
        )

    def test_custom_sectag_in_command(self):
        cred_if = make_cred_if(expect_output=f'%KEYGEN: "{TEST_KEYGEN_BLOB}"\nOK\n')
        dut.gen_self_signed_cert(cred_if, 12345)
        assert cred_if.at_command.call_args[0][0] == "AT%KEYGEN=12345,14,2"

    def test_at_command_fails(self):
        cred_if = make_cred_if(at_command_retval=False)
        assert dut.gen_self_signed_cert(cred_if, dut.DEFAULT_SECTAG) is None

    def test_expect_response_fails(self):
        cred_if = make_cred_if(expect_retval=False)
        assert dut.gen_self_signed_cert(cred_if, dut.DEFAULT_SECTAG) is None

    def test_keygen_not_in_response(self):
        cred_if = make_cred_if(expect_output="OK\n")
        assert dut.gen_self_signed_cert(cred_if, dut.DEFAULT_SECTAG) is None

    def test_uses_long_timeout(self):
        cred_if = make_cred_if(expect_output=f'%KEYGEN: "{TEST_KEYGEN_BLOB}"\nOK\n')
        dut.gen_self_signed_cert(cred_if, dut.DEFAULT_SECTAG)
        kwargs = cred_if.comms.expect_response.call_args.kwargs
        assert kwargs.get("timeout", 0) >= dut.KEYGEN_TIMEOUT_S


# ---------------------------------------------------------------------------
# check_mfw_version
# ---------------------------------------------------------------------------

class TestCheckMfwVersion:
    def test_accepts_minimum_version(self):
        cred_if = Mock()
        cred_if.get_mfw_version.return_value = "mfw_nrf91x1_2.0.2"
        assert dut.check_mfw_version(cred_if) == "mfw_nrf91x1_2.0.2"

    def test_accepts_newer_version(self):
        cred_if = Mock()
        cred_if.get_mfw_version.return_value = TEST_MFW_VERSION_OK
        assert dut.check_mfw_version(cred_if) == TEST_MFW_VERSION_OK

    def test_rejects_older_version(self):
        cred_if = Mock()
        cred_if.get_mfw_version.return_value = TEST_MFW_VERSION_TOO_OLD
        with pytest.raises(SystemExit):
            dut.check_mfw_version(cred_if)

    def test_rejects_legacy_1_3(self):
        cred_if = Mock()
        cred_if.get_mfw_version.return_value = "mfw_nrf9160_1.3.5"
        with pytest.raises(SystemExit):
            dut.check_mfw_version(cred_if)

    def test_no_version_returned_exits(self):
        cred_if = Mock()
        cred_if.get_mfw_version.return_value = None
        with pytest.raises(SystemExit):
            dut.check_mfw_version(cred_if)

    def test_unparseable_version_exits(self):
        cred_if = Mock()
        cred_if.get_mfw_version.return_value = "garbage"
        with pytest.raises(SystemExit):
            dut.check_mfw_version(cred_if)


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

class TestSaveCsv:
    def test_writes_header_and_row_when_creating(self):
        with TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.csv")
            dut.save_csv(path, append=True, replace=False,
                         dev_id=TEST_UUID, attestation=TEST_KEYGEN_BLOB)
            with open(path) as f:
                rows = list(csv.reader(f))
            assert rows[0] == dut.CSV_HEADERS
            assert rows[1] == [TEST_UUID, TEST_KEYGEN_BLOB]

    def test_overwrite_replaces_file(self):
        with TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.csv")
            with open(path, "w") as f:
                f.write("garbage\n")
            with patch("builtins.input", return_value="y"):
                dut.save_csv(path, append=False, replace=False,
                             dev_id=TEST_UUID, attestation=TEST_KEYGEN_BLOB)
            with open(path) as f:
                rows = list(csv.reader(f))
            assert rows[0] == dut.CSV_HEADERS
            assert rows[1] == [TEST_UUID, TEST_KEYGEN_BLOB]
            assert len(rows) == 2

    def test_overwrite_quit_leaves_file_untouched(self):
        with TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.csv")
            with open(path, "w") as f:
                f.write("garbage\n")
            with patch("builtins.input", return_value="n"):
                dut.save_csv(path, append=False, replace=False,
                             dev_id=TEST_UUID, attestation=TEST_KEYGEN_BLOB)
            with open(path) as f:
                assert f.read() == "garbage\n"

    def test_append_adds_row_without_duplicate_header(self):
        with TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.csv")
            dut.save_csv(path, append=True, replace=False,
                         dev_id="aaa", attestation="blob-aaa")
            dut.save_csv(path, append=True, replace=False,
                         dev_id="bbb", attestation="blob-bbb")
            with open(path) as f:
                rows = list(csv.reader(f))
            assert rows == [
                dut.CSV_HEADERS,
                ["aaa", "blob-aaa"],
                ["bbb", "blob-bbb"],
            ]

    def test_append_duplicate_device_with_replace_overwrites_row(self):
        with TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.csv")
            dut.save_csv(path, append=True, replace=False,
                         dev_id="aaa", attestation="blob-old")
            dut.save_csv(path, append=True, replace=True,
                         dev_id="aaa", attestation="blob-new")
            with open(path) as f:
                rows = list(csv.reader(f))
            # Header + the freshly added row only
            assert rows[0] == dut.CSV_HEADERS
            assert ["aaa", "blob-new"] in rows
            assert ["aaa", "blob-old"] not in rows

    def test_append_duplicate_device_without_replace_skips(self):
        with TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.csv")
            dut.save_csv(path, append=True, replace=False,
                         dev_id="aaa", attestation="blob-old")
            dut.save_csv(path, append=True, replace=False,
                         dev_id="aaa", attestation="blob-new")
            with open(path) as f:
                rows = list(csv.reader(f))
            assert ["aaa", "blob-old"] in rows
            assert ["aaa", "blob-new"] not in rows


# ---------------------------------------------------------------------------
# get_parser argument defaults
# ---------------------------------------------------------------------------

class TestParser:
    def test_default_csv_is_empty(self):
        args = dut.get_parser().parse_args(["--port", "/dev/null"])
        assert args.csv == ""

    def test_default_sectag(self):
        args = dut.get_parser().parse_args(["--port", "/dev/null"])
        assert args.sectag == dut.DEFAULT_SECTAG

    def test_custom_sectag(self):
        args = dut.get_parser().parse_args(["--port", "/dev/null", "--sectag", "42"])
        assert args.sectag == 42


# ---------------------------------------------------------------------------
# main() — high-level flow with mocks
# ---------------------------------------------------------------------------

MODULE = "nrfcloud_utils.nrf91_gather_self_signed_certs"


def _base_main_patches():
    return {
        "Comms": MagicMock(),
        "ATCommandInterface": MagicMock(),
        "check_mfw_version": Mock(return_value=TEST_MFW_VERSION_OK),
        "get_device_uuid": Mock(return_value=TEST_UUID),
        "gen_self_signed_cert": Mock(return_value=TEST_KEYGEN_BLOB),
    }


class TestMain:
    def _run(self, patches, extra_args=""):
        args = f"--port /dev/ttyACM0 --cmd-type at {extra_args}".strip().split()
        with patch.multiple(MODULE, **patches):
            patches["ATCommandInterface"].return_value.at_command.return_value = True
            patches["ATCommandInterface"].return_value.go_offline.return_value = True
            dut.main(args)

    def test_default_run_prints_csv_row(self, capsys):
        patches = _base_main_patches()
        self._run(patches)
        captured = capsys.readouterr()
        assert f"{TEST_UUID},{TEST_KEYGEN_BLOB}" in captured.out

    def test_uuid_failure_exits(self):
        patches = _base_main_patches()
        patches["get_device_uuid"] = Mock(return_value=None)
        with pytest.raises(SystemExit):
            self._run(patches)

    def test_offline_failure_exits(self):
        patches = _base_main_patches()
        with patch.multiple(MODULE, **patches):
            patches["ATCommandInterface"].return_value.at_command.return_value = True
            patches["ATCommandInterface"].return_value.go_offline.return_value = False
            with pytest.raises(SystemExit):
                dut.main("--port /dev/ttyACM0 --cmd-type at".split())

    def test_keygen_failure_exits(self):
        patches = _base_main_patches()
        patches["gen_self_signed_cert"] = Mock(return_value=None)
        with pytest.raises(SystemExit):
            self._run(patches)

    def test_csv_flag_writes_file(self):
        with TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.csv")
            self._run(_base_main_patches(), extra_args=f"--csv {path}")
            assert os.path.exists(path)
            with open(path) as f:
                rows = list(csv.reader(f))
            assert rows[0] == dut.CSV_HEADERS
            assert rows[1] == [TEST_UUID, TEST_KEYGEN_BLOB]

    def test_no_csv_means_no_file(self):
        with TemporaryDirectory() as tmp:
            self._run(_base_main_patches())
            # No file created; the directory stays empty
            assert os.listdir(tmp) == []

    def test_brings_modem_back_online(self):
        patches = _base_main_patches()
        with patch.multiple(MODULE, **patches):
            ati = patches["ATCommandInterface"].return_value
            ati.at_command.return_value = True
            ati.go_offline.return_value = True
            dut.main("--port /dev/ttyACM0 --cmd-type at".split())
            calls = [c.args[0] for c in ati.at_command.call_args_list]
            assert "AT+CFUN=1" in calls

    def test_default_does_not_clear_sectag(self):
        patches = _base_main_patches()
        with patch.multiple(MODULE, **patches):
            ati = patches["ATCommandInterface"].return_value
            ati.at_command.return_value = True
            ati.go_offline.return_value = True
            dut.main("--port /dev/ttyACM0 --cmd-type at".split())
            ati.delete_credential.assert_not_called()

    def test_clear_sectag_flag_clears_cert_and_key(self):
        patches = _base_main_patches()
        with patch.multiple(MODULE, **patches):
            ati = patches["ATCommandInterface"].return_value
            ati.at_command.return_value = True
            ati.go_offline.return_value = True
            dut.main("--port /dev/ttyACM0 --cmd-type at --sectag 99 --clear-sectag".split())
            ati.delete_credential.assert_any_call(99, 1)
            ati.delete_credential.assert_any_call(99, 2)

    def test_clear_sectag_short_flag(self):
        patches = _base_main_patches()
        with patch.multiple(MODULE, **patches):
            ati = patches["ATCommandInterface"].return_value
            ati.at_command.return_value = True
            ati.go_offline.return_value = True
            dut.main("--port /dev/ttyACM0 --cmd-type at -c".split())
            ati.delete_credential.assert_any_call(dut.DEFAULT_SECTAG, 1)
            ati.delete_credential.assert_any_call(dut.DEFAULT_SECTAG, 2)


# ---------------------------------------------------------------------------
# Integration test with FakeSerial (mirrors test_gather_attestation_tokens.py)
# ---------------------------------------------------------------------------

class FakeSerial(Mock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = []

    def write(self, data):
        cmd = data.decode("utf-8").strip()
        if cmd == "AT+CGMR":
            self.response = [b"OK\r\n", b"mfw_nrf91x1_2.0.4\r\n"]
        elif cmd == "AT%DEVICEUUID":
            self.response = [b"OK\r\n", f"%DEVICEUUID: {TEST_UUID}\r\n".encode()]
        elif cmd.startswith("AT%KEYGEN="):
            self.response = [
                b"OK\r\n",
                f'%KEYGEN: "{TEST_KEYGEN_BLOB}"\r\n'.encode(),
            ]
        elif cmd.startswith("AT%CMNG="):
            self.response = [b"OK\r\n"]
        elif cmd in ("AT+CFUN=4", "AT+CFUN=1"):
            self.response = [b"OK\r\n"]
        elif cmd == "":
            self.response = [b"OK\r\n"]
        else:
            self.response = [b"ERROR\r\n"]

    def readline(self):
        if not self.response:
            return b""
        return self.response.pop()


FakeSerialPort = namedtuple("FakeSerialPort", ["device"])


class TestIntegration:
    @patch("nrfcredstore.comms.select_device",
           return_value=(FakeSerialPort("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcredstore.comms.serial.Serial", return_value=FakeSerial())
    def test_end_to_end_with_csv(self, ser, select_device, capsys):
        with TemporaryDirectory() as tmp:
            csv_file = os.path.join(tmp, "certs.csv")
            args = f"--port /not/a/real/device --cmd-type at --csv {csv_file}".split()
            dut.main(args)
            assert os.path.exists(csv_file)
            with open(csv_file) as f:
                rows = list(csv.reader(f))
            assert rows[0] == dut.CSV_HEADERS
            assert rows[1] == [TEST_UUID, TEST_KEYGEN_BLOB]
            captured = capsys.readouterr()
            assert f"{TEST_UUID},{TEST_KEYGEN_BLOB}" in captured.out

    @patch("nrfcredstore.comms.select_device",
           return_value=(FakeSerialPort("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcredstore.comms.serial.Serial", return_value=FakeSerial())
    def test_end_to_end_stdout_only(self, ser, select_device, capsys):
        args = "--port /not/a/real/device --cmd-type at".split()
        dut.main(args)
        captured = capsys.readouterr()
        assert f"{TEST_UUID},{TEST_KEYGEN_BLOB}" in captured.out
