# nRF Cloud Utils

These Python scripts are designed to assist users in provisioning devices with the necessary credentials to connect to nRF Cloud, creating FOTA jobs, and onboarding devices to their nRF Cloud accounts.

## Table of Contents

- [Overview of Python Utilities for nRF Cloud Integration](#overview-of-python-utilities-for-nrf-cloud-integration)
- [Create CA Cert](#create-ca-cert)
- [Device Credentials Installer](#device-credentials-installer)
- [nRF Cloud Device Onboarding](#nrf-cloud-device-onboarding)
- [Modem Credentials Parser](#modem-credentials-parser)
- [Create Device Credentials](#create-device-credentials)
- [Claim and Provision Device](#claim-and-provision-device)
- [Gather Attestation Tokens](#gather-attestation-tokens)
- [Claim Devices](#claim-devices)
- [Creating FOTA Updates](#creating-fota-updates)

## Overview of Python Utilities for nRF Cloud Integration

When using nRF9160, these utilities require [Modem firmware v1.3 or later](https://www.nordicsemi.com/Software-and-tools/Development-Kits/nRF9160-DK/Download#infotabs) to function correctly. This requirement is automatically met when using nRF9151 and nRF9161 devices.

For additional details, refer to the [nRF Cloud Security documentation](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/external_comp/nrf_cloud.html#security).

## Create CA Cert
This script creates a self-signed CA certificate and an associated EC keypair. The CA cert and private key can then be used to create device credentials.  Generally, this script needs to be called only once and then its output can be used to produce many device credentials. The specific values that you specify for the various options are not important, though it is recommended to use reasonable and accurate values for country code, state or province, locality, organization and its unit. The number of days valid defaults to 10 years.  The common name could be your company domain name or something similar.

The output file name format is as follows:
`<your_prefix><CA_serial_number_hex>_ca.pem`
`<your_prefix><CA_serial_number_hex>_prv.pem`
`<your_prefix><CA_serial_number_hex>_pub.pem`

### Example
```
create_ca_cert -c NO -p ./my_ca
Creating self-signed CA certificate...
File created: /some/path/my_ca/0x48a2b0c9862ffe08d709864f576caa0a9ff9bfbf_ca.pem
File created: /some/path/my_ca/0x48a2b0c9862ffe08d709864f576caa0a9ff9bfbf_prv.pem
File created: /some/path/my_ca/0x48a2b0c9862ffe08d709864f576caa0a9ff9bfbf_pub.pem
```

## Device Credentials Installer

This script automates the process of generating and programming device credentials to a device such as a Thingy:91 X or nRF9151-DK running an nRF Connect SDK application containing the [AT Host library](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/modem/at_host.html).
The [AT Client sample](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/at_client) is the simplest implementation of the AT Host library.

Use the `create_ca_cert` script to generate the required CA certificate and CA key before running this script.

This script utilizes methods within the classes inside the other scripts `modem_credentials_parser` and `create_device_credentials`.
You do not need to use them directly unless `device_credentials_installer` does not meet your needs.

By default, this script will attempt to connect to the device using a serial connection.
Depending on your device hardware and firmware application, you may need to use one or more of the following parameters:
`xonxoff`, `rtscts_off`, `dsrdtr`, `term`.
**Note**: if only a single supported device is detected on a serial port, it will be automatically selected and used. Otherwise, the script displays a list of detected devices and gives the user a choice of which to use. By default, the scripts filter for Nordic devices. You can use the `--all` option to disable that.

If the `rtt` option is specified, communication will be performed using [SEGGER's RTT](https://www.segger.com/products/debug-probes/j-link/technology/about-real-time-transfer/) interface.
To use RTT, the device must be running the [Modem Shell](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/modem_shell) sample application [built with the RTT overlay](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/samples/cellular/modem_shell/README.html#segger-rtt-support).

In addition to the device specific credentials, this script will install the CA certificate(s) necessary for connecting to nRF Cloud.
By default, the script will install the AWS root CA.
If your device uses CoAP, add the `coap` option to also install the nRF Cloud CoAP CA.

**Note**: the device ID options must match those used to build the device firmware, or else the device will fail to connect to nRF Cloud.
See: [Configuration options for device ID](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/networking/nrf_cloud.html#configuration_options_for_device_id).

### Examples

#### UUID device ID with verification enabled
```
device_credentials_installer -d --ca ./ca.pem --ca-key ./ca_prv_key.pem --verify
```

#### nrf-\<IMEI\> device ID (for nRF91 DKs and Thingy91s) with verification enabled
```
device_credentials_installer -d --ca ./ca.pem --ca-key ./ca_prv_key.pem --verify --id-imei --id-str nrf-
```

# nRF Cloud Device Onboarding
The `nrf_cloud_onboard` script performs device onboarding with nRF Cloud.
Your nRF Cloud REST API key is a required parameter and can be found on your [User Account page](https://nrfcloud.com/#/account).
Also required is a CSV file compatible with the [onboarding endpoint](https://api.nrfcloud.com/v1/#operation/ProvisionDevices). You can use the onboarding CSV file produced by `device_credentials_installer`.

### Example
```
nrf_cloud_onboard --api-key $API_KEY --csv onboard.csv
```

If the `--res` parameter is used, the onboarding result information will be saved to the specified file instead of printed to the output.

# Modem Credentials Parser
The script above, `device_credentials_installer` makes use of this script, `modem_credentials_parser`, so if you use the former, you do not need to also follow the directions below. If `device_credentials_installer` does not meet your needs, you can use `modem_credentials_parser` directly to take advantage of additional options.

This script parses the output of `AT%KEYGEN` and `AT%ATTESTTOKEN`. Each command outputs two base64 strings joined by a `.` character. The first string is the command specific data. The second string is the [COSE](https://datatracker.ietf.org/doc/html/rfc8152) signature of the first string.
The parsed data is displayed in the output. Providing the COSE string to this script is optional, as it is only used to display extra information.  When providing `AT%KEYGEN` output, PEM files can be optionally saved.

Parse modem [KEYGEN](https://docs.nordicsemi.com/bundle/ref_at_commands_nrf91x1/page/REF/at_commands/security/keygen_set.html) output; with or without COSE string:

`modem_credentials_parser -k <base64url AT%KEYGEN output>`

Parse modem keygen output and save PEM file(s); COSE string is required:

`modem_credentials_parser -k <base64url AT%KEYGEN output> -s`

`modem_credentials_parser -k <base64url AT%KEYGEN output> -p <my_output_path> -f <my_file_prefix>`

Parse modem [ATTESTTOKEN](https://docs.nordicsemi.com/bundle/ref_at_commands_nrf91x1/page/REF/at_commands/security/attesttoken_set.html) output; with or without COSE string:

`modem_credentials_parser -a <base64url AT%ATTESTTOKEN output>`

### Examples

#### KEYGEN - Certificate Signing Request (CSR): `AT%KEYGEN=17,2,0`
```
modem_credentials_parser -k MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0xMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o_EXnw62bnQWr8-JqsNh_HZxS3k3bMD4KZ8-qxnvgeoiqQ5zAycEP_Wcmzqypvwyf3qWMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANIADBFAiEAv7OLZ_dXbszfhhjcLMUT72wTmw-z6GlgWxVhyWgR27ACIAvY_lPu3yfYZY5AL6uYTkUFp4GQkbSOUC_lsHyCxOuG.0oRDoQEmoQRBIVhL2dn3hQlQUDYxVDkxRPCAIhIbZAFifUERWCBwKj1W8FsvclMdZQgl4gBB4unZMYw0toU6uQZuXHLoDFAbhyLuHetYFWbiyxNZsnzSWEDUiTl7wwFt0hEsCiEQsxj-hCtpBk8Za8UXfdAycpx2faCOPJIrkfmiSS8-Y6_2tTAoAMN1BiWiTOimY1wZE3Ud

Parsing AT%KEYGEN output:

-----BEGIN CERTIFICATE REQUEST-----
MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0x
MjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o/EX
nw62bnQWr8+JqsNh/HZxS3k3bMD4KZ8+qxnvgeoiqQ5zAycEP/Wcmzqypvwyf3qW
MrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwDAYIKoZIzj0E
AwIFAANIADBFAiEAv7OLZ/dXbszfhhjcLMUT72wTmw+z6GlgWxVhyWgR27ACIAvY
/lPu3yfYZY5AL6uYTkUFp4GQkbSOUC/lsHyCxOuG
-----END CERTIFICATE REQUEST-----

Device public key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKg+qTX2tvaPxF58Otm50Fq/PiarD
Yfx2cUt5N2zA+CmfPqsZ74HqIqkOcwMnBD/1nJs6sqb8Mn96ljK2dlQeWg==
-----END PUBLIC KEY-----

SHA256 Digest:
702a3d56f05b2f72531d650825e20041e2e9d9318c34b6853ab9066e5c72e80c

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Payload ID: CSR_msg_v1
    Dev UUID:  50363154-3931-44f0-8022-121b6401627d
    sec_tag:    17
    SHA256:     702a3d56f05b2f72531d650825e20041e2e9d9318c34b6853ab9066e5c72e80c
    Nonce:      1b8722ee1deb581566e2cb1359b27cd2
  ---------------
  Sig:
      d489397bc3016dd2112c0a2110b318fe842b69064f196bc5177dd032729c767da08e3c922b91f9a2492f3e63aff6b5302800c3750625a24ce8a6635c1913751d

COSE digest matches payload
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
```

#### KEYGEN - Public Key: `AT%KEYGEN=16,2,1`
```
modem_credentials_parser -k MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZKgDx0O0FKa7i1yFoxYngNdV5Csyi4rEPHcFTfeBVtkkJX-G0QZs-yesfzIaPs91b4x5xYN_g28k63gkeVMJwA.0oRDoQEmoQRBIVhL2dn3hQhQUDYxVDkxRPCAIhIbZAFifUEQWCDlovwqMVoJ1W-x93Tqypy2v_1ALv3-GCF1R9gYIy2WVlBQXvxKqA9JTveFh3nVwce-WEAMltwSSkVh8jSBPhP79ndSG0HJTOaTF9SExIq-FstjdLUW2inxdvVfqzLa05rgXqxshN5vfQIs22QT-swCt30h

Parsing AT%KEYGEN output:

Device public key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZKgDx0O0FKa7i1yFoxYngNdV5Csy
i4rEPHcFTfeBVtkkJX+G0QZs+yesfzIaPs91b4x5xYN/g28k63gkeVMJwA==
-----END PUBLIC KEY-----

SHA256 Digest:
e5a2fc2a315a09d56fb1f774eaca9cb6bffd402efdfe18217547d818232d9656

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Payload ID: pubkey_msg_v2
    Dev UUID:   50363154-3931-44f0-8022-121b6401627d
    sec_tag:    16
    SHA256:     e5a2fc2a315a09d56fb1f774eaca9cb6bffd402efdfe18217547d818232d9656
    Nonce:      505efc4aa80f494ef7858779d5c1c7be
  ---------------
  Sig:
      0c96dc124a4561f234813e13fbf677521b41c94ce69317d484c48abe16cb6374b516da29f176f55fab32dad39ae05eac6c84de6f7d022cdb6413facc02b77d21

COSE digest matches payload
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
```

#### AT%ATTESTTOKEN
```
modem_credentials_parser -a 2dn3hQFQUDYxVDkxRPCAIhIbZAFifQNQGv86y_GmR2SiY0wmRsHGVFDT791_BPH8YOWFiyCHND1q.0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY

Parsing AT%ATTESTTOKEN output:

---------------
Msg Type:    Device identity message v1
Dev UUID:    50363154-3931-44f0-8022-121b6401627d
Dev Type:    NRF9160 SIAA
FW UUID:     1aff3acb-f1a6-4764-a263-4c2646c1c654
---------------
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Not present
  ---------------
  Sig:
      6b97c099628a71dceb10cfaee8b28ec697c9765b655a54b8e8471bd612f0bd3956e82509c26130de045215951a968780d9c71e7a3a6a18be779b4e79998070d6
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
```

#### KEYGEN - Certificate Signing Request (CSR) + File Save: `AT%KEYGEN=17,2,0`
```
modem_credentials_parser -k MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0xMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o_EXnw62bnQWr8-JqsNh_HZxS3k3bMD4KZ8-qxnvgeoiqQ5zAycEP_Wcmzqypvwyf3qWMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANIADBFAiEAv7OLZ_dXbszfhhjcLMUT72wTmw-z6GlgWxVhyWgR27ACIAvY_lPu3yfYZY5AL6uYTkUFp4GQkbSOUC_lsHyCxOuG.0oRDoQEmoQRBIVhL2dn3hQlQUDYxVDkxRPCAIhIbZAFifUERWCBwKj1W8FsvclMdZQgl4gBB4unZMYw0toU6uQZuXHLoDFAbhyLuHetYFWbiyxNZsnzSWEDUiTl7wwFt0hEsCiEQsxj-hCtpBk8Za8UXfdAycpx2faCOPJIrkfmiSS8-Y6_2tTAoAMN1BiWiTOimY1wZE3Ud -p my_devices/pem_files -f hw_rev2-

Parsing AT%KEYGEN output:

-----BEGIN CERTIFICATE REQUEST-----
MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0x
MjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o/EX
nw62bnQWr8+JqsNh/HZxS3k3bMD4KZ8+qxnvgeoiqQ5zAycEP/Wcmzqypvwyf3qW
MrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA+gwDAYIKoZIzj0E
AwIFAANIADBFAiEAv7OLZ/dXbszfhhjcLMUT72wTmw+z6GlgWxVhyWgR27ACIAvY
/lPu3yfYZY5AL6uYTkUFp4GQkbSOUC/lsHyCxOuG
-----END CERTIFICATE REQUEST-----

Device public key:
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKg+qTX2tvaPxF58Otm50Fq/PiarD
Yfx2cUt5N2zA+CmfPqsZ74HqIqkOcwMnBD/1nJs6sqb8Mn96ljK2dlQeWg==
-----END PUBLIC KEY-----

SHA256 Digest:
702a3d56f05b2f72531d650825e20041e2e9d9318c34b6853ab9066e5c72e80c

* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
COSE:
  Prot Hdr:   1 : -7 (ECDSA w/ SHA-256)
  Unprot Hdr: 4 : -2 (identity_key)
  ---------------
  Attestation:
    Payload ID: CSR_msg_v1
    Dev UUID:   50363154-3931-44f0-8022-121b6401627d
    sec_tag:    17
    SHA256:     702a3d56f05b2f72531d650825e20041e2e9d9318c34b6853ab9066e5c72e80c
    Nonce:      1b8722ee1deb581566e2cb1359b27cd2
  ---------------
  Sig:
      d489397bc3016dd2112c0a2110b318fe842b69064f196bc5177dd032729c767da08e3c922b91f9a2492f3e63aff6b5302800c3750625a24ce8a6635c1913751d

COSE digest matches payload
* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
Argument -s has been selected since path/fileprefix was specified
File created: /my_devices/pem_files/hw_rev2-50363154-3931-44f0-8022-121b6401627d_17_csr.pem
File created: /my_devices/pem_files/hw_rev2-50363154-3931-44f0-8022-121b6401627d_17_pub.pem
```

# Create Device Credentials
The script above, `device_credentials_installer` makes use of this script, `create_device_credentials`, so if you use the former, you do not need to also follow the directions below.
If `device_credentials_installer` does not meet your needs, you can use `create_device_credentials` directly to take advantage of additional options.

This script creates device credentials for use with nRF Cloud.
It requires a CA certificate and the associated private key as an input.
It optionally accepts a CSR (from `AT%KEYGEN`/modem_credentials_parser).

The output file name format is as follows:
`<your_prefix><CN>_crt.pem`
`<your_prefix><CN>_pub.pem`
if no CSR provided:
`<your_prefix><CN>_prv.pem`
If no CN (common name) is provided/available, the serial number hex value will be used.

### Examples

#### No CSR provided
```
create_device_credentials --ca /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_ca.pem --ca-key my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_prv.pem -c US --st WA -l Seattle -o "My Company" --ou "Devs" --cn my-unique-device-id -e email@example.com --dv 2000 -p dev_credentials -f hw_rev2-
Creating device credentials...
File created: /dev_credentials/hw_rev2-my-unique-device-id_crt.pem
File created: /dev_credentials/hw_rev2-my-unique-device-id_pub.pem
File created: /dev_credentials/hw_rev2-my-unique-device-id_prv.pem
```

#### CSR provided
```
create_device_credentials --ca /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_ca.pem --ca-key my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_prv.pem --csr my_devices/pem_files/hw_rev2-50363154-3931-44f0-8022-121b6401627d_17_csr.pem --dv 2000 -p dev_credentials -f hw_rev2-
Creating device credentials...
File created: /dev_credentials/hw_rev2-50363154-3931-44f0-8022-121b6401627d_crt.pem
File created: /dev_credentials/hw_rev2-50363154-3931-44f0-8022-121b6401627d_pub.pem
```

## Claim and Provision Device
This script uses the [nRF Cloud Identity and Provisioning API](https://api.provisioning.nrfcloud.com/v1/) to perform remote device provisioning tasks.
This service is only compatible with nRF91x1 devices running modem firmware >= 2.0.0.

After claiming and provisioning, this script will onboard the device to your nRF Cloud account.
The target device must be running the [nRF Device Provisioning](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/nrf_provisioning) sample built with the following options:
```
CONFIG_AT_SHELL=y
CONFIG_NRF_PROVISIONING_RX_BUF_SZ=2048
CONFIG_SHELL_BACKEND_SERIAL_RX_RING_BUFFER_SIZE=2048
CONFIG_SHELL_CMD_BUFF_SIZE=2048
```

When not using provisioning tags (with the `--provisioning-tags` argument), this script creates device credentials for use with nRF Cloud and so requires a CA certificate and the associated private key as an input.

Use the `create_ca_cert` script to create a self-signed CA certificate and keys.
Your nRF Cloud REST API key is also a required parameter. It can be found on your [User Account page](https://nrfcloud.com/#/account).
Use `--help` for additional parameter information.

### Examples

#### Device certificate created locally from CSR received over the air:

It's recommended to use the `nrf_cloud_multi_service` sample with the provisioning overlay for this.
Since this process takes some time, it is not recommended in a production setting.
For a production setting, it's better to use `gather_attestation_tokens` (see below).
```
claim_and_provision_device --api-key $API_KEY --ca=./ca.pem --ca-key=ca_prv_key.pem --cmd-type at_shell
```
Query the device for its attestation token over USB, claim the device with the REST API, then provision over the air up to receiving the CSR.
Create the device certificate locally, then send back to the device over the air.

#### Claim device and use a provisioning tag to fully provision and onboard it
```
claim_and_provision_device --api-key $API_KEY --provisioning-tags "nrf-cloud-onboarding" --cmd-type at_shell
```
Like before, but use a built-in provisioning tag so the device certificate is created by the cloud and then sent to the device over the air.

## Gather Attestation Tokens

Use the `gather_attestation_tokens` script to collect the IMEI, UUID, and attestation token from a connected device without requiring an internet connection.

The collected data, along with the current date and time, is saved to a CSV file. By default, the file is named `attestation_tokens.csv`. If the file already exists, the script will:

- Append new entries if the UUID is not already present.
- Replace the row with updated information if the UUID is already in the file.

**Note:** The generated CSV file can later be used with the `claim_devices` script on an internet-connected computer.

### Limitation

- This script is **not supported for nRF9160 devices.**

### Examples

* #### Gather attestation tokens using AT Commands
    ```bash
    gather_attestation_tokens
    ```

* #### Gather attestation tokens using Shell Commands (e.g. Multi Service Sample)
    ```bash
    gather_attestation_tokens --coap --cmd-type at_shell
    ```
## Claim Devices

Use the `claim_devices` script to claim devices by sending the contents of a CSV file to the nRF Cloud REST API, along with a specified set of provisioning tags. By default, the script looks for a file named `attestation_tokens.csv`. If you want to use a different file, you can specify it using the `--csv` option followed by the file name.

### Output

The script will display:
- The total number of devices successfully claimed.
- The total number of devices attempted.

### Examples

* #### Claim devices using the default CSV file and a specific provisioning configuration
    ```bash
    claim_devices --provisioning-tags "nrf-cloud-onboarding" --api-key $API_KEY
    ```

* #### Claim devices using a custom CSV file
    ```bash
    claim_devices --csv custom_tokens.csv --provisioning-tags "nrf-cloud-onboarding" --api-key $API_KEY
    ```

## Creating FOTA Updates

Use the `nrf_cloud_device_mgmt` script to create FOTA (Firmware Over-The-Air) update jobs for your devices via nRF Cloud.

### Prerequisites

* On boarded device to nRF Cloud. Follow the steps outlined in the [Device Credentials Installer](#device-credentials-installer) and [nRF Cloud Device Onboarding](#nrf-cloud-device-onboarding) sections, which include generating device credentials, programming them to the device, and completing the onboarding process.
* Enable FOTA in your project by referring to the following design examples: [nRF Cloud REST FOTA Sample](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/nrf_cloud_rest_fota) and [nRF Cloud Multi-Service Sample](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/nrf_cloud_multi_service).
* An **nRF Cloud API key** is required. You can find your API key on your [nRF Cloud User Account page](https://nrfcloud.com/#/account).

### Execution Modes

The script can run in two modes:

1.  **Non-interactive:** Executes immediately without prompts if all required information is provided via command-line arguments. This requires:
    * `--api-key <your_api_key>`
    * `--name <job_name>` (A descriptive name for the FOTA job)
    * `--desc <job_description>` (A description for the FOTA job)
    * `--bundle-id <firmware_bundle_id>` (The ID of the firmware bundle previously uploaded to nRF Cloud)
    * *And* one of the following target arguments:
        * `--tag <tag_name>` (Targets all devices associated with this tag)
        * `--dev-id <device_id>` (Targets a single specific device ID)

2.  **Interactive:** If any of the required arguments for non-interactive mode (excluding `--api-key`) are omitted, the script will prompt you step-by-step to enter the necessary information (job name, description, bundle selection, target device/tag selection).

### Applying the FOTA Job

* **Default Behavior:** By default, the script automatically attempts to apply the created FOTA job to the target device(s).
* **Manual Application:** To create the job definition without immediately applying it, add the `--defer-apply` flag. You can then manually trigger the update later using the [ApplyFOTAJob](https://api.nrfcloud.com/v1#tag/FOTA-Jobs/operation/ApplyFOTAJob) API endpoint or directly from the [Firmware Updates dashboard](https://nrfcloud.com/#/updates-dashboard) on nRF Cloud.

### Output

* If the FOTA update job is created successfully, the script will print the `job id`.
* This `job id` can be used to manage or query the job status using other nRF Cloud FOTA REST API endpoints, such as [FetchFOTAJob](https://api.nrfcloud.com/v1#operation/FetchFOTAJob).

### Examples

* #### Create and apply a FOTA job non-interactively for a specific device
    ```bash
    nrf_cloud_device_mgmt --api-key $API_KEY --name "MyModemUpdateV2" --desc "Update modem firmware to v2.0" --bundle-id "fw-modem-v2.0-bundle-id" --dev-id "nrf-XXXXXXXXXXXXXX"
    ```

* #### Create (but do not apply) a FOTA job non-interactively for all devices with a specific tag
    ```bash
    nrf_cloud_device_mgmt --api-key $API_KEY --name "MyAppUpdateV1.1" --desc "App core update v1.1 for beta testers" --bundle-id "fw-app-v1.1-bundle-id" --tag "beta-testers" --defer-apply
    ```

* #### Create a FOTA job interactively (will prompt for details)
    ```bash
    nrf_cloud_device_mgmt --api-key $API_KEY
    ```
