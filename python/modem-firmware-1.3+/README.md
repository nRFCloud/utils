# Python Utilities for Working with Modem Firmware v1.3+

[Modem firmware v1.3 and later](https://www.nordicsemi.com/Software-and-tools/Development-Kits/nRF9160-DK/Download#infotabs) provide new [AT security commands](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fref_at_commands%2FREF%2Fat_commands%2Fintro.html), including `KEYGEN` and `ATTESTTOKEN`, which are the focus of these Python scripts.

## Prerequisites

Use Python pip to install required packages:
```
~$ pip3 install -r requirements.txt
```

# Create CA Cert
This script creates a self-signed CA certificate and an associated EC keypair.   The CA cert and private key can then be used to create device credentials.  Generally, this script needs to be called only once and then its output can be used to produce many device credentials.

The output file name format is as follows:
`<your_prefix><CA_serial_number_hex>_ca.pem`
`<your_prefix><CA_serial_number_hex>_prv.pem`
`<your_prefix><CA_serial_number_hex>_pub.pem`

### Example
```
python3 create_ca_cert.py -c US -st OR -l Portland -o "My Company" -ou "RD" -cn example.com -e admin@example.com -p /my_ca -f my_company-
Creating self-signed CA certificate...
File created: /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_ca.pem
File created: /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_prv.pem
File created: /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_pub.pem
```

# Device Credentials Installer

This script automates the process of generating and programming device credentials to a device such as a Thingy:91 or 9160DK running an nRF Connect SDK application containing the [AT Host library](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/libraries/modem/at_host.html).
The [AT Client sample](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/at_client) is the simplest implementation of the AT Host library.

It can also be used on an [LTE gateway](https://github.com/nRFCloud/lte-gateway), by interacting with the built-in shell.

Use the `create_ca_cert.py` script to generate the required CA certificate and CA key before running this script.

This script utilizes methods within the classes inside the other scripts `modem_credentials_parser.py` and `create_device_credentials.py`.
You do not need to use them directly unless `device_credentials_installer.py` does not meet your needs.

By default, this script will attempt to connect to the device using a serial connection.
Depending on your device hardware and firmware application, you may need to use one or more of the following parameters:
`xonxoff`, `rtscts_off`, `dsrdtr`, `term`.
**Note**: if only a single supported device is detected on a serial port, it will be automatically selected and used. Otherwise, the script displays a list of detected devices and gives the user a choice of which to use.

If the `rtt` option is specified, communication will be performed using [SEGGER's RTT](https://www.segger.com/products/debug-probes/j-link/technology/about-real-time-transfer/) interface.
To use RTT, the device must be running the [Modem Shell](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/modem_shell) sample application [built with the RTT overlay](https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/samples/cellular/modem_shell/README.html#segger-rtt-support).
This script will optionally flash the modem shell application on startup if a hex file path is provided with the `mosh_rtt_hex` option.

### Examples

#### UUID device ID with verification enabled
```
python3 device_credentials_installer.py -d --ca ./ca.pem --ca_key ./ca_prv_key.pem --verify
```

#### nrf-\<IMEI\> device ID (for nRF91 DKs and Thingy91s) with verification enabled
```
python3 device_credentials_installer.py -d --ca ./ca.pem --ca_key ./ca_prv_key.pem --verify --id_imei --id_str nrf-
```

# nRF Cloud Device Onboarding
The `nrf_cloud_onboard.py` script performs device onboarding with nRF Cloud.
Your nRF Cloud REST API key is a required parameter. See [https://nrfcloud.com/#/account](https://nrfcloud.com/#/account).
Also required is a CSV file compatible with the [onboarding endpoint](https://api.nrfcloud.com/v1/#operation/ProvisionDevices). You can use the onboarding CSV file produced by `device_credentials_installer.py`.

### Example
```
python3 ./nrf_cloud_onboard.py --apikey $API_KEY --csv onboard.csv
```

If the `--res` parameter is used, the onboarding result information will be saved to the specified file instead of printed to the output.

# Modem Credentials Parser
The script above, `device_credentials_installer.py` makes use of this script, `modem_credentials_parser.py`, so if you use the former, you do not need to also follow the directions below.  If `device_credentials_installer.py` does not meet your needs, you can use `modem_credentials_parser.py` directly to take advantage of additional options.

This script parses the output of `AT%KEYGEN` and `AT%ATTESTTOKEN`.   Each command outputs two base64 strings joined by a `.` character.  The first string is the command specific data.  The second string is the [COSE](https://datatracker.ietf.org/doc/html/rfc8152) signature of the first string.
The parsed data is displayed in the output.  Providing the COSE string to this script is optional, as it is only used to display extra information.  When providing `AT%KEYGEN` output, PEM files can be optionally saved.

Parse modem [KEYGEN](https://infocenter.nordicsemi.com/topic/ref_at_commands/REF/at_commands/security/keygen_set.html) output; with or without COSE string:

`python3 modem_credentials_parser.py -k <base64url AT%KEYGEN output>`

Parse modem keygen output and save PEM file(s); COSE string is required:

`python3 modem_credentials_parser.py -k <base64url AT%KEYGEN output> -s`

`python3 modem_credentials_parser.py -k <base64url AT%KEYGEN output> -p <my_output_path> -f <my_file_prefix>`

Parse modem [ATTESTTOKEN](https://infocenter.nordicsemi.com/topic/ref_at_commands/REF/at_commands/security/attesttoken_set.html) output; with or without COSE string:

`python3 modem_credentials_parser.py -a <base64url AT%ATTESTTOKEN output>`

### Examples

#### KEYGEN - Certificate Signing Request (CSR): `AT%KEYGEN=17,2,0`
```
python3 modem_credentials_parser.py -k MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0xMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o_EXnw62bnQWr8-JqsNh_HZxS3k3bMD4KZ8-qxnvgeoiqQ5zAycEP_Wcmzqypvwyf3qWMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANIADBFAiEAv7OLZ_dXbszfhhjcLMUT72wTmw-z6GlgWxVhyWgR27ACIAvY_lPu3yfYZY5AL6uYTkUFp4GQkbSOUC_lsHyCxOuG.0oRDoQEmoQRBIVhL2dn3hQlQUDYxVDkxRPCAIhIbZAFifUERWCBwKj1W8FsvclMdZQgl4gBB4unZMYw0toU6uQZuXHLoDFAbhyLuHetYFWbiyxNZsnzSWEDUiTl7wwFt0hEsCiEQsxj-hCtpBk8Za8UXfdAycpx2faCOPJIrkfmiSS8-Y6_2tTAoAMN1BiWiTOimY1wZE3Ud

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
python3 modem_credentials_parser.py -k MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZKgDx0O0FKa7i1yFoxYngNdV5Csyi4rEPHcFTfeBVtkkJX-G0QZs-yesfzIaPs91b4x5xYN_g28k63gkeVMJwA.0oRDoQEmoQRBIVhL2dn3hQhQUDYxVDkxRPCAIhIbZAFifUEQWCDlovwqMVoJ1W-x93Tqypy2v_1ALv3-GCF1R9gYIy2WVlBQXvxKqA9JTveFh3nVwce-WEAMltwSSkVh8jSBPhP79ndSG0HJTOaTF9SExIq-FstjdLUW2inxdvVfqzLa05rgXqxshN5vfQIs22QT-swCt30h

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
python3 modem_credentials_parser.py -a 2dn3hQFQUDYxVDkxRPCAIhIbZAFifQNQGv86y_GmR2SiY0wmRsHGVFDT791_BPH8YOWFiyCHND1q.0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY

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
python3 modem_credentials_parser.py -k MIIBCjCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2MzE1NC0zOTMxLTQ0ZjAtODAyMi0xMjFiNjQwMTYyN2QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQqD6pNfa29o_EXnw62bnQWr8-JqsNh_HZxS3k3bMD4KZ8-qxnvgeoiqQ5zAycEP_Wcmzqypvwyf3qWMrZ2VB5aoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANIADBFAiEAv7OLZ_dXbszfhhjcLMUT72wTmw-z6GlgWxVhyWgR27ACIAvY_lPu3yfYZY5AL6uYTkUFp4GQkbSOUC_lsHyCxOuG.0oRDoQEmoQRBIVhL2dn3hQlQUDYxVDkxRPCAIhIbZAFifUERWCBwKj1W8FsvclMdZQgl4gBB4unZMYw0toU6uQZuXHLoDFAbhyLuHetYFWbiyxNZsnzSWEDUiTl7wwFt0hEsCiEQsxj-hCtpBk8Za8UXfdAycpx2faCOPJIrkfmiSS8-Y6_2tTAoAMN1BiWiTOimY1wZE3Ud -p /my_devices/pem_files -f hw_rev2-

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
The script above, `device_credentials_installer.py` makes use of this script, `create_device_credentials.py`, so if you use the former, you do not need to also follow the directions below.
If `device_credentials_installer.py` does not meet your needs, you can use `create_device_credentials.py` directly to take advantage of additional options.

This script creates device credentials for use with nRF Cloud.
It requires a CA certificate and the associated private key as an input.
It optionally accepts a CSR (from `AT%KEYGEN`/modem_credentials_parser.py).

The output file name format is as follows:
`<your_prefix><CN>_crt.pem`
`<your_prefix><CN>_pub.pem`
if no CSR provided:
`<your_prefix><CN>_prv.pem`
If no CN (common name) is provided/available, the serial number hex value will be used.

### Examples

#### No CSR provided:
```
python3 create_device_credentials.py -ca /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_ca.pem -ca_key /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_prv.pem -c US -st WA -l Seattle -o "My Company" -ou "Devs" -cn my-unique-device-id -e email@example.com -dv 2000 -p /dev_credentials -f hw_rev2-
Creating device credentials...
File created: /dev_credentials/hw_rev2-my-unique-device-id_crt.pem
File created: /dev_credentials/hw_rev2-my-unique-device-id_pub.pem
File created: /dev_credentials/hw_rev2-my-unique-device-id_prv.pem
```

#### CSR provided:
```
python3 create_device_credentials.py -ca /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_ca.pem -ca_key /my_ca/my_company-0x3bc7f3b014a8ad492999c594f08bbc2fcffc5fd1_prv.pem -csr /my_devices/pem_files/hw_rev2-50363154-3931-44f0-8022-121b6401627d_17_csr.pem -dv 2000 -p /dev_credentials -f hw_rev2-
Creating device credentials...
File created: /dev_credentials/hw_rev2-50363154-3931-44f0-8022-121b6401627d_crt.pem
File created: /dev_credentials/hw_rev2-50363154-3931-44f0-8022-121b6401627d_pub.pem
```

# Device Management - Creating FOTA Updates:
Use the `nrf_cloud_device_mgmt.py` script to create FOTA update jobs.

An nRF Cloud API key `--apikey` is required to create FOTA updates. It can be found on the nrfcloud.com User Account page.
By providing `--name`, `--desc`, `--bundle_id` and either `--tag` or `--dev_id`, the script will execute without user interaction. Otherwise, the script will prompt the user for information required to create the FOTA update.

If a FOTA update is successfully created, the script will print the `job id`, which can be used with the FOTA REST API endpoints, e.g. [FetchFOTAJob](https://api.nrfcloud.com/v1#operation/FetchFOTAJob).

### Examples

#### Modem FOTA via device tag:
```
python3 nrf_cloud_device_mgmt.py --apikey enter_your_api_key_here --type MODEM --name "My FOTA Update" --desc "This is a description of the FOTA update." --bundle_id "MODEM*be0ef0bd*mfw_nrf9160_1.3.1" --tag "device_group_1"
...
Created job: 43129aa3-656e-444f-bfd4-2e87932c6199
```

#### Modem FOTA via device ID:
```
python3 nrf_cloud_device_mgmt.py --apikey enter_your_api_key_here --type MODEM --name "My FOTA Update" --desc "This is a description of the FOTA update." --bundle_id "MODEM*be0ef0bd*mfw_nrf9160_1.3.1" --dev_id nrf-123456789012345
...
Created job: 17058622-683e-48d5-a752-b2a77a13c9c9
```

# Claim and Provision Device
This script uses the [nRF Cloud Identity and Provisioning API](https://api.provisioning.nrfcloud.com/v1/) to perform remote device provisioning tasks.
After claiming and provisioning, this script will onboard the device to your nRF Cloud account.
The target device must be running the [nRF Device Provisioning](https://github.com/nrfconnect/sdk-nrf/tree/main/samples/cellular/nrf_provisioning) sample built with the following options:
```
CONFIG_AT_SHELL=y
CONFIG_NRF_PROVISIONING_RX_BUF_SZ=2048
CONFIG_SHELL_BACKEND_SERIAL_RX_RING_BUFFER_SIZE=2048
CONFIG_SHELL_CMD_BUFF_SIZE=2048
```

Because this script creates device credentials for use with nRF Cloud, it requires a CA certificate and the associated private key as an input.
Use the `create_ca_cert.py` script to create a self-signed CA certificate and keys.
Your nRF Cloud REST API key is also a required parameter. See [https://nrfcloud.com/#/account](https://nrfcloud.com/#/account).
Use `--help` for additional parameter information.

### Example
```
python3 ./claim_and_provision_device.py --apikey $API_KEY --ca=./ca.pem --ca_key=ca_prv_key.pem
```
