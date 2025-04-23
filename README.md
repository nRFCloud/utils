# nRF Cloud Utils

nRF Cloud Utils is a script collection to make it easier to interface with nRF Cloud.

The scripts in this repository mainly use endpoints in [the REST API](https://api.nrfcloud.com/v1).

See also the official [nRF Cloud documentation](https://docs.nordicsemi.com/bundle/nrf-cloud/page/index.html).

## Table of Contents

* [Install](#install)
* [Requirements](#requirements)
* [How-To: Registering devices quickly](#how-to-registering-devices-quickly)
* [Advanced Usage](#advanced-usage)
* [Development installation](#development-installation)
* [Test](#test)

## Install

Run the following command to use this package as a dependency:

    pip3 install nrfcloud-utils

## Requirements

1. Create an account in [nrfcloud.com](https://nrfcloud.com).
2. Retrieve your API key. You can find it in your [nRF Cloud User Account page](https://nrfcloud.com/#/account).
3. To simplify the use of the scripts, you can declare your API key as an environment variable in your terminal. This way, you won't need to repeatedly type it in each command. Here's how to do it:

```bash
export API_KEY=<your_api_key>
```

Replace `<your_api_key>` with your actual API key.
If you don't choose this path, take note of your API key, you will need it soon. Note that if you are part of multiple teams on nRF Cloud, the API key will be different for each one.

4. Depending on your goal, you'll need to configure your nRF Connect SDK project with the following libraries:

* **For basic device registration:** Enable the [AT Host library](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/modem/at_host.html). Refer to the [AT Client sample](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/samples/cellular/at_client/README.html) in the nRF Connect SDK for an implementation example.

* **For using the Provisioning Service:** Enable the [Provisioning Service library](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/networking/nrf_provisioning.html). You can find more documentation about the [Provisioning Service here](https://docs.nordicsemi.com/bundle/nrf-cloud/page/SecurityServices/ProvisioningService/ProvisioningOverview.html). The nRF Connect SDK provides these illustrative samples:

    * **nRF Cloud Multi Service Sample:** Demonstrates onboarding alongside other cloud interactions.
        * [https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/nrf_cloud_multi_service](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/nrf_cloud_multi_service)
    * **nRF Provisioning Sample:** Provides a focused look at the provisioning steps.
        * [https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/nrf_provisioning](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/nrf_provisioning)

5. When compiling with the nRF Cloud Libraries, make sure to add the next Kconfig options:

    ```Kconfig
    # Enable modem-based JSON Web Token (JWT) generation required for nRF Cloud authentication
    CONFIG_MODEM_JWT=y

    # Configure the nRF Cloud library to use the device's internal UUID as the client ID
    CONFIG_NRF_CLOUD_CLIENT_ID_SRC_INTERNAL_UUID=y

    # Define the modem security tag where nRF Cloud credentials will be stored (16842753 is the standard tag used by Nordic examples)
    CONFIG_NRF_CLOUD_SEC_TAG=16842753
    ```
**Failure to include these settings will prevent the device from connecting to nRF Cloud.**

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

Congratulations! You have successfully registered your device to nRF Cloud, you should be able to visualize it on the [Devices panel](https://nrfcloud.com/#/devices).

## Advanced Usage

For a more detailed overview of the scripts and their capabilities, refer to the [Advanced Usage Guide](https://github.com/nRFCloud/utils/blob/main/ADVANCED.md). This guide provides in-depth instructions on leveraging advanced features, including the use of the Provisioning Service for remote provisioning of devices, as an alternative to local provisioning.

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
