# nRF Cloud Utils

These Python scripts are designed to assist users in provisioning devices with the necessary credentials to connect to nRF Cloud and onboarding devices to their nRF Cloud accounts.

## Table of contents

- [Overview of Python utilities for nRF Cloud integration](#overview-of-python-utilities-for-nrf-cloud-integration)
- [Create CA certificate](#create-ca-certificate)
- [Device credentials installer](#device-credentials-installer)
- [nRF Cloud device onboarding](#nrf-cloud-device-onboarding)
- [nRF93M1 device onboarding](#nrf93m1-device-onboarding)
- [Modem credentials parser](#modem-credentials-parser)
- [Create device credentials](#create-device-credentials)
- [Gather attestation tokens](#gather-attestation-tokens)
- [Creating FOTA updates](#creating-fota-updates)
- [nRF Credential Store](#nrf-credential-store)

## Overview of Python utilities for nRF Cloud integration

When using nRF9160, these utilities require [Modem firmware v1.3 or later](https://www.nordicsemi.com/Software-and-tools/Development-Kits/nRF9160-DK/Download#infotabs) to function correctly. This requirement is automatically met when using nRF9151 and nRF9161 devices.

For additional details, refer to the [nRF Cloud Security documentation](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/external_comp/nrf_cloud.html#security).

## Create CA certificate

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

## Device credentials installer

This script automates the process of generating and programming device credentials to a device such as the nRF9160-DK, Thingy:91X or nRF9151-DK running an nRF Connect SDK application containing the [AT Host library](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/modem/at_host.html) or [AT Shell](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/modem/at_shell.html).
It also supports devices without a modem, such as nRF71 Series and nRF70 Series Wi-Fi devices. See [Devices without a modem](#devices-without-a-modem).

Use the `create_ca_cert` script to generate the required CA certificate and CA key before running this script.

This script utilizes methods within the classes inside the other scripts `modem_credentials_parser` and `create_device_credentials`.
You do not need to use them directly unless `device_credentials_installer` does not meet your needs.

By default, this script will attempt to connect to the device using a serial connection.
Depending on your device hardware and firmware application, you may need to use one or more of the following parameters:
`xonxoff`, `rtscts_off`, `dsrdtr`, `term`.
**Note**: if only a single supported device is detected on a serial port, it will be automatically selected and used. Otherwise, the script displays a list of detected devices and gives the user a choice of which to use. By default, the scripts filter for Nordic devices. You can use the `--all` option to disable that.

If the `rtt` option is specified, communication will be performed using [SEGGER's RTT](https://www.segger.com/products/debug-probes/j-link/technology/about-real-time-transfer/) interface.
RTT support is not part of the default installation. Install it with `pip3 install "nrfcloud-utils[rtt]"`.
To use RTT, the device must be running the [Modem Shell](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/modem_shell) sample application [built with the RTT overlay](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/samples/cellular/modem_shell/README.html#segger-rtt-support).

In addition to the device specific credentials, this script will install the CA certificate(s) necessary for connecting to nRF Cloud.
By default, the script will install the AWS root CA.
If your device uses CoAP, add the `coap` option to also install the nRF Cloud CoAP CA.

**Note**: The device ID options must match those used to build the device firmware. Otherwise, the device will fail to connect to nRF Cloud.
See: [Configuration options for device ID](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/networking/nrf_cloud.html#configuration_options_for_device_id).

The script also writes an onboarding CSV file (`onboard.csv` by default, set with `--csv`) for [onboarding](#nrf-cloud-device-onboarding).
If the file already exists, the script asks whether to overwrite it, append to it, or skip saving.
To provision several devices into the same file, use the `--append` option, which adds a row for each device without asking.
A file can hold up to 1000 devices. A device ID that is already in the file is rejected unless you also pass `--replace`.

### Examples

#### UUID device ID with verification enabled
```
device_credentials_installer -d --ca *_ca.pem --ca-key *_prv.pem --verify
```

#### nrf-\<IMEI\> device ID with verification enabled
```
device_credentials_installer -d --ca *_ca.pem --ca-key *_prv.pem --verify --id-imei --id-str nrf-
```

### Devices without a modem

Devices without a Nordic cellular modem have no AT interface, so use the `--cmd-type` option to select the shell that the device firmware provides:

* `nrf_cloud_cred_shell` (recommended) - The device generates its private key and CSR itself, and the script installs the signed device certificate. The private key never leaves the device.
  The firmware must include the [nRF Cloud credentials keygen library](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/networking/nrf_cloud_credentials_keygen.html) with its shell enabled (nRF Connect SDK v3.5.0 or later).
  To use the `--verify` option, the firmware must also enable the `CONFIG_NRF_CLOUD_CREDENTIALS_KEYGEN_VERIFY` Kconfig option.
  Do not use `--local-cert` or `--local-cert-file` with this command type.
* `tls_cred_shell` - The script generates the private key and device certificate on the host and installs them through the Zephyr [TLS Credentials Shell](https://docs.zephyrproject.org/latest/services/connectivity/networking/api/tls_credentials_shell.html).
  This command type requires `--local-cert` or `--local-cert-file`, as the TLS Credentials Shell cannot generate a CSR.
  Because the private key exists on the host, this is less secure. Delete it from the host after installation.

These devices have no modem UUID or IMEI to read the device ID from, so pass the device ID that the firmware uses with `--id-str`.
If you omit it, the script generates a random UUID, which the firmware does not know about.

#### On-device key generation

For provisioning with on-device key generation, use the following command:

```
device_credentials_installer -d --ca *_ca.pem --ca-key *_prv.pem --verify --coap --cmd-type nrf_cloud_cred_shell --id-str <device_id>
```

#### Host-generated key

For provisioning with a host-generated key, use the following command:

```
device_credentials_installer -d --ca *_ca.pem --ca-key *_prv.pem --verify --coap --cmd-type tls_cred_shell --local-cert --id-str <device_id>
```

Omit `--coap` if the device connects to nRF Cloud using MQTT only.

## nRF Cloud device onboarding

Onboard devices with the `nrfcloud device create` command from the [Memfault CLI](https://pypi.org/project/memfault-cli/). Onboarding claims the device for your nRF Cloud project and registers its public key. The credentials are then provisioned to the device automatically, so there are no separate claim or provisioning steps.

Install the CLI (version 1.12.0 or later). It installs both the `memfault` and the `nrfcloud` commands:
```
pip3 install memfault-cli
```

The command authenticates with an organization auth token (OAT) that has the `device:write` permission. Create one under **Admin** > **Organization Auth Tokens** in the nRF Cloud app. You also need your organization slug and project slug.

### After `device_credentials_installer`

`device_credentials_installer` and `create_device_credentials` write an onboarding CSV file (`onboard.csv` by default). Pass it to `device create`:
```
nrfcloud --org-token $OAT --org <org> --project <project> device create --csv onboard.csv --res results.csv
```
The command uploads the devices, waits for the result, and prints `OK` or the error for each device. `--res` also writes a `Device ID,Result` CSV.

The `subType`, `tags` and `fwTypes` columns of `onboard.csv` have no equivalent in the new API and are ignored. Use cohorts and device attributes in the nRF Cloud app instead.

### Other credential types

`--csv` also accepts a CSV with a header row of `deviceId` and exactly one of these columns:

| Column | Credential |
| --- | --- |
| `certificate` | Device certificate PEM |
| `attestationToken` | Identity attestation token (nRF9151, nRF9161) |
| `onboardingToken` | Onboarding token, such as the registration JWT of an nRF93M1 (see [nRF93M1 device onboarding](#nrf93m1-device-onboarding)) |

`gather_attestation_tokens` writes rows of `imei,uuid,attestation_token,timestamp` without a header row. Convert them before onboarding, using the column that matches the device ID your firmware uses (the UUID here):
```
(echo deviceId,attestationToken; awk -F, '{print $2","$3}' attestation_tokens.csv) > onboard_tokens.csv
nrfcloud --org-token $OAT --org <org> --project <project> device create --csv onboard_tokens.csv
```

### Limits

- A single command creates at most 1000 devices. Split larger files.
- Identity operations are currently supported only in an organization's default project.
- A device that already belongs to another project must be deleted from that project first. Deleting a device releases its claim.

See [Device onboarding](https://docs.nrfcloud.com/docs/nrfcloud/device-onboarding) in the nRF Cloud documentation.

## nRF93M1 device onboarding

The `nrf93_onboard` script onboards an nRF93M1 device to nRF Cloud using a registration token JWT generated directly on the device. It connects over serial, retrieves the device UUID and identity key via AT commands, fetches the nRF Cloud tenant ID of your organization, calls `AT%REGJWT` on the device to produce the JWT, and registers the device with the nRF Cloud API.

The script authenticates with an organization auth token (OAT) that has the `device:write` permission. It needs the OAT and your organization slug, plus a project slug that defaults to `nrf-project`. Each can be given as an option or as an environment variable:

| Option | Environment variable |
| --- | --- |
| `--org-token` | `MEMFAULT_ORG_TOKEN` |
| `--org` | `MEMFAULT_ORG` |
| `--project` | `MEMFAULT_PROJECT` (defaults to `nrf-project`) |

Devices are onboarded without tags or a subtype and start in the default cohort.

### Example
```
export MEMFAULT_ORG_TOKEN=<your OAT>
nrf93_onboard --port /dev/ttyACM0 --org my-org
```

### Collecting registration JWTs for bulk onboarding

With the `--csv` option, the script does not onboard the device. Instead, it saves the device UUID and the registration JWT to a CSV file that `nrfcloud device create` accepts:
```
deviceId,onboardingToken
<device_uuid>,<registration_jwt>
```
Run the script once for each device with the same file to collect up to 1000 devices. A device that is already in the file gets its row replaced with the new registration JWT.

The registration JWT is generated for the nRF Cloud tenant ID (team ID) of your organization. Pass it with `--tenant-id` to collect registration JWTs offline, without an OAT:
```
nrf93_onboard --port /dev/ttyACM0 --csv devices.csv --tenant-id <tenant_id>
```
The tenant ID is part of the `AT%REGJWT` command that the **Add devices** wizard in nRF Cloud shows for the nRF93M1. A registration JWT generated with the wrong tenant ID is only rejected when the device is onboarded.

Without `--tenant-id`, the script looks the tenant ID up, which requires network access, the OAT and the organization slug:
```
nrf93_onboard --port /dev/ttyACM0 --org my-org --csv devices.csv
```

Then onboard all collected devices as described in [nRF Cloud device onboarding](#nrf-cloud-device-onboarding):
```
nrfcloud --org-token $OAT --org <org> --project <project> device create --csv devices.csv
```

## Modem credentials parser

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

#### KEYGEN - Public key: `AT%KEYGEN=16,2,1`
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

#### KEYGEN - Certificate Signing Request (CSR) + file save: `AT%KEYGEN=17,2,0`
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

## Create device credentials

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

The script also writes an onboarding CSV file (`onboard.csv` by default, set with `--csv`) for [onboarding](#nrf-cloud-device-onboarding).

With the `--embed-save` option, the script instead writes `client-cert.pem`, `private-key.pem`, and `ca-cert.pem`, formatted for building into firmware using the `CONFIG_NRF_CLOUD_PROVISION_CERTIFICATES` Kconfig option. See [Hard-coded credentials](https://docs.nordicsemi.com/bundle/ncs-latest/page/nrf/libraries/networking/nrf_cloud_preconnect_provisioning.html#hard-coded-credentials).
The `ca-cert.pem` file holds the nRF Cloud root CA certificate(s), not your own CA. Add `--coap` to include the nRF Cloud CoAP root CA certificate.

:warning:**This stores the device private key in unprotected memory on the device. Use it for testing only.**

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

#### Credentials to build into firmware

To create credentials to build into the firmware with nRF Cloud CoAP support, use the following command:

```
create_device_credentials --ca *_ca.pem --ca-key *_prv.pem -c NO --cn my-unique-device-id -p dev_credentials --embed-save --coap
```

## Gather attestation tokens

Use the `gather_attestation_tokens` script to collect the IMEI, UUID, and attestation token from a connected device without requiring an internet connection.

The collected data, along with the current date and time, is saved to a CSV file. By default, the file is named `attestation_tokens.csv`. If the file already exists, the script will:

- Append new entries if the UUID is not already present.
- Replace the row with updated information if the UUID is already in the file.

**Note:** The generated CSV file can be converted for use with `nrfcloud device create` on an internet-connected computer. See [nRF Cloud device onboarding](#nrf-cloud-device-onboarding).

### Limitation

- This script is **not supported for nRF9160 devices.**
- This service is only compatible with nRF91x1 devices running modem firmware >= 2.0.0.

### Examples

* #### Gather attestation tokens
    ```bash
    gather_attestation_tokens
    ```

## Creating FOTA updates

Create and activate FOTA updates with the [Memfault CLI](https://pypi.org/project/memfault-cli/), using an OAT. Upload the firmware as a Release with `upload-ota-payload` (or `upload-zchunk-ota-payload`), then activate it on a cohort with `deploy-release`:
```
memfault --org-token $OAT --org <org> --project <project> \
    upload-ota-payload --software-type <type> --software-version <version> <file>
memfault --org-token $OAT --org <org> --project <project> \
    deploy-release --release-version <version> --cohort <cohort> --rollout-percent 10
```
Run each command with `--help` for all options, including modem (multi-component) and delta updates.

Devices check for updates when they connect to nRF Cloud. Activating a Release does not notify devices that are already connected. See [Over-the-air updates](https://docs.nrfcloud.com/docs/nrfcloud/fota-transition) in the nRF Cloud documentation.

## nRF Credential Store

`nrfcredstore` is a command-line tool that simplifies the management of credentials stored in nRF91 modems.

It supports the following subcommands:

    list                List all keys stored in the modem
    write               Write key/cert to a secure tag
    delete              Delete value from a secure tag
    deleteall           Delete all keys in a secure tag
    imei                Get IMEI from the modem
    attoken             Get attestation token of the modem
    generate            Generate private key

### Examples

* #### List all keys stored in the modem
    ```bash
    nrfcredstore /dev/ttyACM0 list
    ```

* #### Delete sectag 42, Key type ROOT_CA_CERT
    ```bash
    nrfcredstore /dev/ttyACM0 delete 42 ROOT_CA_CERT
    ```

* #### Delete all keys in the modem, similar to a factory reset.
    ```bash
    nrfcredstore /dev/ttyACM0 deleteall
    ```

More information can be found on the [nrfcredstore GitHub page](https://github.com/NordicSemiconductor/nrfcredstore/tree/main)
