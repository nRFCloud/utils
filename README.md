# nRF Cloud Utilities

This repository contains scripts that support certain use cases of nRF Cloud, mainly endpoints in [the Device API](https://api.nrfcloud.com/v1).

The scripts are gathered from various teams and organized according to their programmatic language. We cannot, at this time, offer the same scripts across all languages.

Please see the README in each folder for more information.

## How to obtain the nRF9160's UUID:

The nRF9160 contains a UUID which can be used as the nRF Cloud device ID (MQTT client ID).

The UUID is found in the device identity attestation token, which is a base64 encoded CBOR object.  To request an attestation token issue the following [AT command](https://infocenter.nordicsemi.com/index.jsp?topic=/ref_at_commands/REF/at_commands/intro.html): `AT%ATTESTTOKEN`

The attestation token must then be decoded/parsed.  This can be done using the [modem_credentials_parser.py](https://github.com/nRFCloud/utils/blob/master/python/modem-firmware-1.3+/modem_credentials_parser.py) python3 script.  See the [README](https://github.com/nRFCloud/utils/blob/master/python/modem-firmware-1.3+/README.md) for additional details.
The UUID will be displayed in the script's output on the line starting with `Dev UUID:`.

To obtain the UUID in your device's application code, use the following library: https://developer.nordicsemi.com/nRF_Connect_SDK/doc/latest/nrf/include/modem/modem_attest_token.html


## WIP: Securely generating credentials on the nRF9160:

1.  Invoke `AT%KEYGEN=<sec_tag>,2,0`. This will generate a key pair and CSR using the default attributes and key usage (per the AT commands spreadsheet):
    1.  attributes:  `CN=<device-uuid>`
    2.  key usage:  `111010000`  (digitalSignature, nonRepudiation, keyEncipherment and keyAgreement bits are set as "1")
2.  Collect the exported payload via the serial port.
3.  Decode and verify signature of the CBOR/COSE payload to extract the device ID and CSR.  This can be done using the [modem_credentials_parser.py](https://github.com/nRFCloud/utils/blob/master/python/modem-firmware-1.3+/modem_credentials_parser.py) python3 script.  See the [README](https://github.com/nRFCloud/utils/blob/master/python/modem-firmware-1.3+/README.md) for additional details.
4.  Create the device certificate using the CSR and a CA certificate.
