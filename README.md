# nRF Cloud Utilities

nRF Cloud Utils is a script collection to make it easier to interface with nRF Cloud.
A common use-case is to register devices with your account or to run a fota job.

The scripts in this repository mainly use endpoints in [the REST API](https://api.nrfcloud.com/v1).

The scripts are gathered from various teams and organized according to their programmatic language: [Python](https://github.com/nRFCloud/utils/tree/master/python/modem-firmware-1.3%2B).

See also the official [nRF Cloud documentation](https://docs.nordicsemi.com/bundle/nrf-cloud/page/index.html).

## Install

Run the following command to use this package as a dependency:

    pip3 install nrfcloud-utils

## Requirements

To register a device, you need special firmware flashed to it. Most scripts work with an at_host enabled or the at_client sample flashed.
However, if you intend to use the Provisioning Service, you will need to enable that library in your firmware or flash the nRF Cloud Multi Service sample.

## Usage

See [Usage](USAGE.md)
