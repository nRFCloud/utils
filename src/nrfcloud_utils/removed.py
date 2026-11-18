#!/usr/bin/env python3
#
# Copyright (c) 2026 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
"""
Placeholders for commands that were removed from nrfcloud-utils.

They used the legacy nRF Cloud API (authenticated with a legacy API key). Each placeholder
prints what to do instead and exits with a non-zero status, so that scripts calling a removed
command fail visibly instead of silently doing nothing.
"""
import argparse
import sys
from dataclasses import dataclass

EXIT_CODE_REMOVED = 1

_DOCS_URL = "https://github.com/nRFCloud/utils/blob/main/ADVANCED.md"

_ONBOARD_INSTEAD = f"""\
Use `nrfcloud device create` from the Memfault CLI instead. It authenticates with an
organization auth token (OAT) and claims and onboards the devices; credentials are then
provisioned automatically, so there are no separate claim or provisioning steps.

    pip3 install memfault-cli
    nrfcloud --org-token $OAT --org <org> --project <project> device create --csv onboard.csv

See {_DOCS_URL}#nrf-cloud-device-onboarding"""


@dataclass(frozen=True)
class RemovedCommand:
    name: str
    description: str
    message: str

    def get_parser(self):
        parser = argparse.ArgumentParser(
            description=self.description,
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            add_help=False,
        )
        # Accept and ignore whatever arguments the removed command used to take
        parser.add_argument("ignored_args", nargs="*", help=argparse.SUPPRESS)
        return parser

    def main(self, in_args=None):
        print(f"{self.name} is obsolete.\n\n{self.message}", file=sys.stderr)
        sys.exit(EXIT_CODE_REMOVED)

    def run(self):
        self.main(sys.argv[1:])


REMOVED_COMMANDS = {
    c.name: c
    for c in (
        RemovedCommand(
            name="nrf_cloud_onboard",
            description="Removed: use `nrfcloud device create`",
            message=_ONBOARD_INSTEAD,
        ),
        RemovedCommand(
            name="claim_devices",
            description="Removed: use `nrfcloud device create`",
            message=_ONBOARD_INSTEAD
            + """

`gather_attestation_tokens` writes a CSV in this format, with the device UUID as the device ID. Pass
`--csv attestation_tokens.csv` to `device create` instead of `onboard.csv`.""",
        ),
        RemovedCommand(
            name="claim_and_provision_device",
            description="Removed: use `nrfcloud device create`",
            message=_ONBOARD_INSTEAD
            + """

Provisioning commands (CSR, client and server certificates) are no longer issued by this
tool. To create the credentials locally, use `create_ca_cert` and
`device_credentials_installer`, then pass the resulting `onboard.csv` to `device create`.""",
        ),
        RemovedCommand(
            name="nrf_cloud_device_mgmt",
            description="Removed: use `memfault upload-ota-payload` and `memfault deploy-release`",
            message=f"""\
FOTA updates are now Releases that you activate on a cohort. Use the Memfault CLI with an
organization auth token (OAT):

    pip3 install memfault-cli
    memfault --org-token $OAT --org <org> --project <project> \\
        upload-ota-payload --software-type <type> --software-version <version> <file>
    memfault --org-token $OAT --org <org> --project <project> \\
        deploy-release --release-version <version> --cohort <cohort>

Devices check for updates when they connect to nRF Cloud. Activating a Release does not
notify devices that are already connected.

See {_DOCS_URL}#creating-fota-updates""",
        ),
        RemovedCommand(
            name="create_proxy_jwt",
            description="Removed: no replacement in nrfcloud-utils",
            message="""\
nrfcloud-utils no longer creates JWTs for proxy (cloud-to-cloud) requests, and there is no
replacement in this package. See the nRF Cloud documentation or contact Nordic support
(https://devzone.nordicsemi.com).""",
        ),
    )
}


def _make_run(command):
    def run():
        command.run()

    run.__name__ = f"run_{command.name}"
    return run


# Entry points for the console scripts in pyproject.toml
run_nrf_cloud_onboard = _make_run(REMOVED_COMMANDS["nrf_cloud_onboard"])
run_claim_devices = _make_run(REMOVED_COMMANDS["claim_devices"])
run_claim_and_provision_device = _make_run(REMOVED_COMMANDS["claim_and_provision_device"])
run_nrf_cloud_device_mgmt = _make_run(REMOVED_COMMANDS["nrf_cloud_device_mgmt"])
run_create_proxy_jwt = _make_run(REMOVED_COMMANDS["create_proxy_jwt"])
