"""
Tests for removed.py
"""

import pytest

from nrfcloud_utils import cli, removed

REMOVED_NAMES = [
    "claim_and_provision_device",
    "claim_devices",
    "create_proxy_jwt",
    "nrf_cloud_device_mgmt",
    "nrf_cloud_onboard",
]


class TestRemoved:
    def test_all_removed_commands_registered(self):
        assert sorted(removed.REMOVED_COMMANDS) == REMOVED_NAMES

    @pytest.mark.parametrize("name", REMOVED_NAMES)
    def test_prints_message_and_exits_nonzero(self, name, capsys):
        with pytest.raises(SystemExit) as e:
            removed.REMOVED_COMMANDS[name].main([])
        assert e.value.code == removed.EXIT_CODE_REMOVED
        out = capsys.readouterr()
        assert out.out == ""
        assert f"{name} is obsolete" in out.err

    @pytest.mark.parametrize("name", REMOVED_NAMES)
    def test_entry_point_ignores_old_arguments(self, name, capsys, monkeypatch):
        monkeypatch.setattr("sys.argv", [name, "--api-key", "KEY", "--csv", "x.csv", "-P"])
        with pytest.raises(SystemExit) as e:
            getattr(removed, f"run_{name}")()
        assert e.value.code == removed.EXIT_CODE_REMOVED
        assert "is obsolete" in capsys.readouterr().err

    @pytest.mark.parametrize("name", REMOVED_NAMES)
    def test_umbrella_cli_ignores_old_arguments(self, name, capsys, monkeypatch):
        monkeypatch.setattr("sys.argv", ["nrfcloud-utils", name, "--api-key", "KEY"])
        with pytest.raises(SystemExit) as e:
            cli.run()
        assert e.value.code == removed.EXIT_CODE_REMOVED
        assert "is obsolete" in capsys.readouterr().err

    def test_messages_point_to_replacements(self):
        for name in ("nrf_cloud_onboard", "claim_devices", "claim_and_provision_device"):
            assert "nrfcloud device create" in removed.REMOVED_COMMANDS[name].message
        mgmt = removed.REMOVED_COMMANDS["nrf_cloud_device_mgmt"].message
        assert "upload-ota-payload" in mgmt
        assert "deploy-release" in mgmt

    def test_listed_in_umbrella_help(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.argv", ["nrfcloud-utils", "--help"])
        with pytest.raises(SystemExit):
            cli.run()
        out = capsys.readouterr().out
        for name in REMOVED_NAMES:
            assert name in out
