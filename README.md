# nRF Cloud Utils

[![PyPI version](https://img.shields.io/pypi/v/nrfcloud-utils)](https://pypi.org/project/nrfcloud-utils/)
![License](https://img.shields.io/pypi/l/nrfcloud-utils)
![Python versions](https://img.shields.io/pypi/pyversions/nrfcloud-utils)

nRF Cloud Utils is a script collection to make it easier to interface with nRF Cloud. They also include [nrfcredstore](https://github.com/NordicSemiconductor/nrfcredstore) to interface with nRF91 Series devices.

The scripts in this repository mainly use endpoints in the [nRF Cloud API](https://api.nrfcloud.com/v1) and the [nRF Cloud Provisioning API](https://api.provisioning.nrfcloud.com/v1/).

See also the official [nRF Cloud documentation](https://docs.nordicsemi.com/bundle/nrf-cloud/page/index.html).

## Table of contents

* [Install](#install)
* [Requirements](#requirements)
* [Registering devices quickly](#registering-devices-quickly)
* [Advanced usage](#advanced-usage)
* [Development installation](#development-installation)
* [Test](#test)

## Install

Run the following command to use this package as a dependency:

    pip3 install nrfcloud-utils

## Requirements

1. Create an account in [nrfcloud.com](https://nrfcloud.com).
2. For the scripts that use the legacy nRF Cloud API (`claim_devices`, `claim_and_provision_device`, `nrf93_onboard`, and `nrf_cloud_device_mgmt`), retrieve your **legacy nRF Cloud API key**. Open the legacy nRF Cloud app (the **Legacy App** link at the bottom of the nRF Cloud side navigation, or [app.nrfcloud.com](https://app.nrfcloud.com/#/account) directly), then go to **User Account** > **Current Team Details**. If you are part of multiple teams, each team has its own API key.

    :warning:**The User API key shown under My Profile in the new nRF Cloud app is a different key. These scripts reject it with `401 Unauthorized`.**

    > [!NOTE]
    > The scripts in this repository use the legacy nRF Cloud APIs. For nRF9151 and nRF9161 devices, the recommended path is [Secure Device Onboarding](https://docs.nrfcloud.com/docs/nrfcloud/secure-device-onboarding) in the new nRF Cloud app, which needs no local CA and no legacy API key. If you can't open the legacy app or its User Account page, contact [Nordic support](https://devzone.nordicsemi.com).
3. Depending on your goal, you'll need to configure your nRF Connect SDK project with the following libraries:

* **For basic device registration:** Enable the [AT Host library](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/modem/at_host.html). Refer to the [AT Client sample](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/samples/cellular/at_client/README.html) in the nRF Connect SDK for an implementation example.

* **For using the Provisioning Service:** Enable the [Provisioning Service library](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/networking/nrf_provisioning.html). You can find more documentation about the [Provisioning Service here](https://docs.nordicsemi.com/bundle/nrf-cloud/page/SecurityServices/ProvisioningService/ProvisioningOverview.html). The nRF Connect SDK provides a [sample](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/nrf_device_provisioning) with a focused look at provisioning steps on cellular devices.

4. For devices with a Nordic cellular modem, the device ID that the firmware uses must match the modem UUID that the scripts use by default.
   This is the default of the nRF Cloud library since the nRF Connect SDK v3.4.0.
   With older versions, set the `CONFIG_NRF_CLOUD_CLIENT_ID_SRC_INTERNAL_UUID` Kconfig option to `y` (which enables `CONFIG_MODEM_JWT`).

:warning:**A device ID mismatch will prevent the device from connecting to nRF Cloud.**

For devices without a modem, such as nRF71 Series and nRF70 Series Wi-Fi devices, see [Devices without a modem](https://github.com/nRFCloud/utils/blob/main/ADVANCED.md#devices-without-a-modem) instead.

## Registering devices quickly

Start by creating a local certificate authority (CA). Its contents won't be checked, but you need one to make certificates for your devices. Optionally, pass options to the script to specify owner information.

    create_ca_cert

Now, you should have three `.pem` files containing the key pair and the CA certificate of your CA. The files have a unique prefix.

To get your device registered, use the `device_credentials_installer` script. Be aware of which device ID is your project using, as it can be either a UUID or an IMEI. Depending on your device ID type, use one of the following commands:

#### UUID
```
device_credentials_installer -d --ca *_ca.pem --ca-key *_prv.pem --verify --coap
```

#### nrf-\<IMEI\>
```
device_credentials_installer -d --ca *_ca.pem --ca-key *_prv.pem --verify --id-imei --id-str nrf- --coap
```

#### Device without a modem, key generated on the device (for example, nRF71 Series or nRF70 Series with Wi-Fi)

For a device without a modem, pass the device ID that the firmware uses and let the device generate its key, using the following command:

```
device_credentials_installer -d --ca *_ca.pem --ca-key *_prv.pem --verify --coap --cmd-type nrf_cloud_cred_shell --id-str <device_id>
```
See [Devices without a modem](https://github.com/nRFCloud/utils/blob/main/ADVANCED.md#devices-without-a-modem) for the firmware requirements.

:warning:**Failure to select the correct device ID will result in a connection refused from nRF Cloud.**

Upon success, you can find an `onboard.csv` file with information about your device. This file is needed to register the certificate with your account.
If you encounter a `No device found` error, you might need to specify the serial port using the `--port` option.

Onboard the device to your account with `onboard.csv`, as described in the [device onboarding quickstart](https://docs.nrfcloud.com/docs/best-practices/device-onboarding-quickstart#manually-provisioning-a-device-certificate).

It is possible to install credentials on many devices in a row using the `--append` option and onboard them all at once with the resulting `onboard.csv`.

Congratulations! You have successfully registered your device to nRF Cloud, you should be able to visualize it on the [Devices panel](https://app.nrfcloud.com/#/devices).

## Advanced usage

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

    poetry run pytest --cov=src tests
