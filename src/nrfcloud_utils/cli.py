#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
import argparse
import sys

from nrfcloud_utils import (
    claim_and_provision_device,
    claim_devices,
    create_ca_cert,
    create_device_credentials,
    create_proxy_jwt,
    device_credentials_installer,
    gather_attestation_tokens,
    modem_credentials_parser,
    nrf_cloud_device_mgmt,
    nrf_cloud_onboard,
    nrf93_onboard,
)

_MODULES = {
    "claim_and_provision_device": claim_and_provision_device,
    "claim_devices": claim_devices,
    "create_ca_cert": create_ca_cert,
    "create_device_credentials": create_device_credentials,
    "create_proxy_jwt": create_proxy_jwt,
    "device_credentials_installer": device_credentials_installer,
    "gather_attestation_tokens": gather_attestation_tokens,
    "modem_credentials_parser": modem_credentials_parser,
    "nrf_cloud_device_mgmt": nrf_cloud_device_mgmt,
    "nrf_cloud_onboard": nrf_cloud_onboard,
    "nrf93_onboard": nrf93_onboard,
}


def _build_parser():
    parser = argparse.ArgumentParser(
        prog="nrfcloud-utils",
        description="Scripts and utilities for working with nRF Cloud",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="command", required=False)
    for name, mod in _MODULES.items():
        _p = mod.get_parser()
        subparsers.add_parser(
            name,
            parents=[_p],
            description=_p.description,
            formatter_class=_p.formatter_class,
            help=_p.description,
        )
    return parser


def run():
    parser = _build_parser()
    # parse_args() handles --help at both levels and validates the subcommand name
    # and its args (using each module's get_parser() for the subparser definition).
    # We then re-dispatch to the module's own main() so setup_logging and other
    # module init runs exactly as it does when the command is called standalone.
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    cmd = args.command
    sys.argv = [cmd] + sys.argv[2:]
    _MODULES[cmd].main(sys.argv[1:])


if __name__ == "__main__":
    run()
