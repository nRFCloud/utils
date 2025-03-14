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

See [Usage](USAGE.md).

## Development installation

Clone the repository:

    git clone https://github.com/nRFCloud/utils.git nrfcloud-utils
    cd nrfcloud-utils

For development mode, you need [poetry](https://python-poetry.org/):

    curl -sSL https://install.python-poetry.org | python3 -

Make sure `poetry` is in your PATH. If you're using `bash`:

    echo 'export PATH=/home/$USER/.local/bin:$PATH' | tee -a ~/.bashrc
    source ~/.bashrc

Install package dependencies, development dependencies, and the nrfcloud-utils into poetry's internal virtual environment:

    poetry install

## Test

Running the tests depends on a [development installation](#development-installation).

    poetry run pytest

Check coverage

    poetry run pytest --cov=. tests
