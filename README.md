# nRF Cloud Utilities

nRF Cloud Utils is a script collection to make it easier to interface with nRF Cloud.
A common use-case is to register devices with your account or to run a fota job.

The scripts in this repository mainly use endpoints in [the REST API](https://api.nrfcloud.com/v1).

See also the official [nRF Cloud documentation](https://docs.nordicsemi.com/bundle/nrf-cloud/page/index.html).

## Install

Run the following command to use this package as a dependency:

    pip3 install nrfcloud-utils

## Requirements

Do you already have an nRF Cloud account? If not, please visit [nrfcloud.com](https://nrfcloud.com) and register. Then, click on the burger on the top-right to get to your user account. Take note of your API key, you will need it soon. Note that if you are part of multiple teams on nRF Cloud, the API key will be different for each one.

To register a device, you need compatible firmware flashed to it. Most scripts work with an [AT Host library](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/modem/at_host.html) enabled app or the [AT Client sample](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/samples/cellular/at_client/README.html) flashed.
However, if you intend to use the [Provisioning Service](https://docs.nordicsemi.com/bundle/nrf-cloud/page/SecurityServices/ProvisioningService/ProvisioningOverview.html), you will need to enable its [library](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/networking/nrf_provisioning.html) in your firmware or flash the nRF Cloud Multi Service sample.

## How-To: Registering devices quickly

Start by creating a local certificate authority (CA). Its contents won't be checked, but you need one to make certificates for your devices. Optionally, pass options to the script to specify owner information.

    create_ca_cert

Now, you should have three `.pem` files containing the key pair and the CA certificate of your CA. The files have a unique prefix.

The fastest way to get your device registered is using the Device Credentials Installer:

    device_credentials_installer -d --ca *_ca.pem --ca-key *_prv.pem --coap --verify

Upon success, you can find an `onboard.csv` file with information about your device. We need this file to register the certificate with your account.
If you encounter a `No device found` error, you might need to specify the serial port using the `--port` option.

Finally, add the device to your account with the Onboarding script:

    nrf_cloud_onboard --api-key $API_KEY --csv onboard.csv

You can also install credentials on many devices in a row using the `--append` option and add the bulk `onboard.csv` to your account with the same command.

Congratulations! You have successfully registered your device. When compiling with the nRF Cloud Libraries, make sure to use the correct KConfig options:

    CONFIG_NRF_CLOUD_CLIENT_ID_SRC_INTERNAL_UUID=y
    CONFIG_NRF_CLOUD_SEC_TAG=16842753

For a more detailed overview of the scripts, see [Advanced Usage](https://github.com/nRFCloud/utils/blob/main/ADVANCED.md). There, you can also find details on how to use the Provisioning Service instead of provisioning your devices locally.

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

Unit tests are included in the `tests` folder. Each test script corresponds to a script in the sources.
Static files used in the tests are put in the `tests/fixtures` folder.
Running the tests depends on a [development installation](#development-installation).

    poetry run pytest

Check coverage

    poetry run pytest --cov=. tests
