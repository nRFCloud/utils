"""
Tests for nrf93_onboard.py
"""

import pytest
import sys
from unittest.mock import patch, Mock, MagicMock
from nrfcloud_utils import nrf93_onboard
from nrfcloud_utils.cli_helpers import USER_AGENT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TEST_UUID = "988234bd-a066-a101-656e-684d6f5adad6"
TEST_IDENTITY_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKg+qTX2tvaPxF58Otm50Fq+PiarDYfx2cUt5N2zA+A=="
TEST_TENANT_ID = "1a2b3c4d-e5f6-7890-abcd-ef1234567890"
TEST_REGJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhNDgzMzRiZC1hMDYxLTFmNDEtYmYwMC00ZGE0MWFiZDA0YjYiLCJpZCI6IjE5Y2VkMDVjLTA5YWItNGMzNy04ZTQ0LWJhNGMzNmMxZmI3NCJ8.xe_8tEKZtPoyprqkhIR-zjJTJeR0rYcIBUNNZEBdz3KUImpismgNVxSSW7brS9Myh4KWymlWRz2QKdz40oyPew"


def make_cred_if(at_command_retval=True, expect_retval=True, expect_output=""):
    """Return a minimal mock ATCommandInterface."""
    cred_if = Mock()
    cred_if.at_command.return_value = at_command_retval
    cred_if.comms.expect_response.return_value = (expect_retval, expect_output)
    return cred_if


# ---------------------------------------------------------------------------
# get_nrf93m1_uuid
# ---------------------------------------------------------------------------

class TestGetNrf93m1Uuid:
    def test_success(self):
        output = f"%DEVICEUUID: {TEST_UUID}\nOK\n"
        cred_if = make_cred_if(expect_output=output)
        result = nrf93_onboard.get_nrf93m1_uuid(cred_if)
        assert result == TEST_UUID

    def test_at_command_fails(self):
        cred_if = make_cred_if(at_command_retval=False)
        assert nrf93_onboard.get_nrf93m1_uuid(cred_if) is None

    def test_expect_response_fails(self):
        cred_if = make_cred_if(expect_retval=False, expect_output="")
        assert nrf93_onboard.get_nrf93m1_uuid(cred_if) is None

    def test_creating_status_message_ignored(self):
        # Device responds with a "creating" status before the real UUID
        output = "%DEVICEUUID: creating device uuid...\n%DEVICEUUID: 988234bd-a066-a101-656e-684d6f5adad6\nOK\n"
        cred_if = make_cred_if(expect_output=output)
        result = nrf93_onboard.get_nrf93m1_uuid(cred_if)
        assert result == TEST_UUID

    def test_uuid_not_in_response(self):
        cred_if = make_cred_if(expect_output="OK\n")
        assert nrf93_onboard.get_nrf93m1_uuid(cred_if) is None


# ---------------------------------------------------------------------------
# get_nrf93m1_identity_key
# ---------------------------------------------------------------------------

class TestGetNrf93m1IdentityKey:
    def test_success(self):
        output = f"%CLOUDACCESSKEY: {TEST_IDENTITY_KEY}\nOK\n"
        cred_if = make_cred_if(expect_output=output)
        result = nrf93_onboard.get_nrf93m1_identity_key(cred_if)
        assert result == TEST_IDENTITY_KEY

    def test_at_command_fails(self):
        cred_if = make_cred_if(at_command_retval=False)
        assert nrf93_onboard.get_nrf93m1_identity_key(cred_if) is None

    def test_expect_response_fails(self):
        cred_if = make_cred_if(expect_retval=False, expect_output="")
        assert nrf93_onboard.get_nrf93m1_identity_key(cred_if) is None

    def test_key_too_short_rejected(self):
        output = "%CLOUDACCESSKEY: tooshort\nOK\n"
        cred_if = make_cred_if(expect_output=output)
        assert nrf93_onboard.get_nrf93m1_identity_key(cred_if) is None

    def test_key_not_in_response(self):
        cred_if = make_cred_if(expect_output="OK\n")
        assert nrf93_onboard.get_nrf93m1_identity_key(cred_if) is None


# ---------------------------------------------------------------------------
# gen_registration_jwt
# ---------------------------------------------------------------------------

class TestGenRegistrationJwt:
    def test_success(self):
        output = f"%REGJWT: {TEST_REGJWT}\nOK\n"
        cred_if = make_cred_if(expect_output=output)
        result = nrf93_onboard.gen_registration_jwt(cred_if, TEST_TENANT_ID)
        assert result == TEST_REGJWT
        cred_if.at_command.assert_called_once_with(
            f'AT%REGJWT="{TEST_TENANT_ID}"', wait_for_result=False
        )

    def test_at_command_fails(self):
        cred_if = make_cred_if(at_command_retval=False)
        assert nrf93_onboard.gen_registration_jwt(cred_if, TEST_TENANT_ID) is None

    def test_expect_response_fails(self):
        cred_if = make_cred_if(expect_retval=False, expect_output="")
        assert nrf93_onboard.gen_registration_jwt(cred_if, TEST_TENANT_ID) is None

    def test_jwt_not_in_response(self):
        cred_if = make_cred_if(expect_output="OK\n")
        assert nrf93_onboard.gen_registration_jwt(cred_if, TEST_TENANT_ID) is None


# ---------------------------------------------------------------------------
# fetch_tenant_id
# ---------------------------------------------------------------------------

class TestFetchTenantId:
    @patch("nrfcloud_utils.nrf93_onboard.requests.get")
    def test_success(self, mock_get):
        mock_get.return_value = Mock(ok=True, json=lambda: {"data": {"nrfcloud_team_id": TEST_TENANT_ID}})
        result = nrf93_onboard.fetch_tenant_id("my-oat", "my-org")
        assert result == TEST_TENANT_ID
        assert mock_get.call_args.args[0] == "https://api.memfault.com/api/v0/organizations/my-org"
        assert mock_get.call_args.kwargs["headers"]["Authorization"] == "Bearer my-oat"

    @patch("nrfcloud_utils.nrf93_onboard.requests.get")
    def test_sends_user_agent_header(self, mock_get):
        mock_get.return_value = Mock(ok=True, json=lambda: {"data": {"nrfcloud_team_id": TEST_TENANT_ID}})
        nrf93_onboard.fetch_tenant_id("my-oat", "my-org")
        assert mock_get.call_args.kwargs["headers"]["User-Agent"] == USER_AGENT

    @patch("nrfcloud_utils.nrf93_onboard.requests.get")
    def test_http_error(self, mock_get):
        mock_get.return_value = Mock(ok=False, status_code=401)
        assert nrf93_onboard.fetch_tenant_id("bad-oat", "my-org") is None

    @patch("nrfcloud_utils.nrf93_onboard.requests.get")
    def test_missing_tenant_id_in_response(self, mock_get):
        mock_get.return_value = Mock(ok=True, json=lambda: {"data": {}})
        assert nrf93_onboard.fetch_tenant_id("my-oat", "my-org") is None

    @patch("nrfcloud_utils.nrf93_onboard.requests.get")
    def test_invalid_json(self, mock_get):
        mock_get.return_value = Mock(ok=True)
        mock_get.return_value.json.side_effect = ValueError("no JSON")
        assert nrf93_onboard.fetch_tenant_id("my-oat", "my-org") is None


# ---------------------------------------------------------------------------
# onboard_device
# ---------------------------------------------------------------------------

class TestOnboardDevice:
    @patch("nrfcloud_utils.nrf93_onboard.requests.post")
    def test_request_shape(self, mock_post):
        mock_post.return_value = Mock(ok=True)
        nrf93_onboard.onboard_device("my-oat", "my-org", "my-proj", "jwt")
        assert mock_post.call_args.args[0] == (
            "https://api.nrfcloud.com/v1/organizations/my-org/projects/my-proj/long-range/devices")
        assert mock_post.call_args.kwargs["json"] == {"onboardingToken": "jwt"}
        headers = mock_post.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer my-oat"
        assert headers["User-Agent"] == USER_AGENT


# ---------------------------------------------------------------------------
# main() — exit codes
# ---------------------------------------------------------------------------

MODULE = "nrfcloud_utils.nrf93_onboard"


def _base_patches():
    """Return attribute-name keyed dict for use with patch.multiple(MODULE, ...)."""
    return {
        "Comms": MagicMock(),
        "ATCommandInterface": MagicMock(),
        "get_nrf93m1_uuid": Mock(return_value=TEST_UUID),
        "get_nrf93m1_identity_key": Mock(return_value=TEST_IDENTITY_KEY),
        "fetch_tenant_id": Mock(return_value=TEST_TENANT_ID),
        "gen_registration_jwt": Mock(return_value=TEST_REGJWT),
        "onboard_device": Mock(return_value=Mock(ok=True)),
    }


def _run_main_with_patches(patches, extra_args=""):
    args = f"--port /dev/ttyACM0 --org-token test-oat --org my-org --project my-proj {extra_args}".split()
    with patch.multiple(MODULE, **patches):
        patches["ATCommandInterface"].return_value.at_command.return_value = True
        nrf93_onboard.main(args)


class TestMainExitCodes:
    def test_success(self):
        _run_main_with_patches(_base_patches())  # should not raise

    def test_serial_open_fails_exit_1(self):
        patches = _base_patches()
        patches["Comms"].side_effect = Exception("port not found")
        with pytest.raises(SystemExit) as exc:
            _run_main_with_patches(patches)
        assert exc.value.code == 1

    def test_device_not_responsive_exit_1(self):
        patches = _base_patches()
        patches["ATCommandInterface"].return_value.at_command.return_value = False
        with patch.multiple(MODULE, **patches):
            with pytest.raises(SystemExit) as exc:
                nrf93_onboard.main("--port /dev/ttyACM0 --org-token test-oat --org my-org --project my-proj".split())
        assert exc.value.code == 1

    def test_uuid_fails_exit_2(self):
        patches = _base_patches()
        patches["get_nrf93m1_uuid"] = Mock(return_value=None)
        with pytest.raises(SystemExit) as exc:
            _run_main_with_patches(patches)
        assert exc.value.code == 2

    def test_identity_key_fails_exit_3(self):
        patches = _base_patches()
        patches["get_nrf93m1_identity_key"] = Mock(return_value=None)
        with pytest.raises(SystemExit) as exc:
            _run_main_with_patches(patches)
        assert exc.value.code == 3

    def test_tenant_id_fails_exit_4(self):
        patches = _base_patches()
        patches["fetch_tenant_id"] = Mock(return_value=None)
        with pytest.raises(SystemExit) as exc:
            _run_main_with_patches(patches)
        assert exc.value.code == 4

    def test_jwt_fails_exit_5(self):
        patches = _base_patches()
        patches["gen_registration_jwt"] = Mock(return_value=None)
        with pytest.raises(SystemExit) as exc:
            _run_main_with_patches(patches)
        assert exc.value.code == 5

    def test_onboard_http_error_exit_6(self):
        patches = _base_patches()
        patches["onboard_device"] = Mock(return_value=Mock(ok=False, status_code=403, text="Forbidden"))
        with pytest.raises(SystemExit) as exc:
            _run_main_with_patches(patches)
        assert exc.value.code == 6

    def test_onboard_called_with_org_project(self):
        patches = _base_patches()
        _run_main_with_patches(patches)
        patches["onboard_device"].assert_called_once_with(
            "test-oat", "my-org", "my-proj", TEST_REGJWT)

    def test_missing_org_token_exits_with_error(self, monkeypatch):
        for v in ("MEMFAULT_ORG_TOKEN", "MEMFAULT_ORG", "MEMFAULT_PROJECT"):
            monkeypatch.delenv(v, raising=False)
        with pytest.raises(SystemExit) as exc:
            nrf93_onboard.main("--port /dev/ttyACM0".split())
        assert exc.value.code != 0

    def test_project_defaults_to_nrf_project(self, monkeypatch):
        monkeypatch.delenv("MEMFAULT_PROJECT", raising=False)
        patches = _base_patches()
        args = "--port /dev/ttyACM0 --org-token test-oat --org my-org".split()
        with patch.multiple(MODULE, **patches):
            patches["ATCommandInterface"].return_value.at_command.return_value = True
            nrf93_onboard.main(args)
        assert patches["onboard_device"].call_args[0][2] == "nrf-project"
