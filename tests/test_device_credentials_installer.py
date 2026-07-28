"""
Test for device_credentials_installer.py
"""

from unittest.mock import patch, Mock
from nrfcloud_utils import device_credentials_installer
from tempfile import TemporaryDirectory
import os
import base64
import hashlib
import pytest
from collections import namedtuple, deque
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

TEST_KEYGEN_UUID = [b"OK\r\n", b"%KEYGEN: \"MIIBCzCBrwIBADAvMS0wKwYDVQQDDCQ1MDM2Mzk1My0zMjM0LTQ3MjMtODBiOS0xNTAzZDg4MjcxYmYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ37lDghqs2kF2iiH8lYRDDxNMiziQRPPdw9Meb1iHfTEZNdlB1xZzMV-oK6i52p1GHYQszjoDzUAZF2zU2MTGGoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANJADBGAiEAzaMPi5NcWFYZBJGBMk0tU-TBoNDVlQUzhHWJzXKRTWsCIQCWYpYqjccA281F5Geb8SwOP3tnjS_ZbAXUgVWhTVNuvg.0oRDoQEmoQRBIVhM2dn3hQlQUDY5UzI0RyOAuRUD2IJxv0IYNFggTaa7Z9K-8bQPz3YG5o_h32quNr0FHEtnX5VpEZ-8gflQY8D67v4xx32mF0L3-mbuuVhAfY3TgibaimIVPaN1C3Sz_oWj6JPf8sEOV2XNBDUNCV3sD3WdNOjgv32-rLXAx_vBIvpk1DTCb3Y97zqFhhdKlw\"\r\n"]
TEST_KEYGEN_IMEI = [b"OK\r\n", b"%KEYGEN: \"MIH4MIGeAgEAMB4xHDAaBgNVBAMME25yZi0zNTUwMjU5MzAwMDAwMDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATYRrWI0v6LJWciuTlscw8E1TcOBJoygkALKecquhe-fr_QT_tcjC2DgmDyX1cjTubp7n_mUaf5ZJ1s-Ke-ABBuoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA-gwDAYIKoZIzj0EAwIFAANHADBEAiBDTS-I_ye8nJpB7vtO6FQWvnUhJnG6QsjRPo56nBFh2gIgPB5NW16dANAMmn0VLMBXGeRPTtoxOs5Ld1Z7JW46_8s.0oRDoQEmoQRBIVhM2dn3hQlQUDQ5VjA3RziADR8p4KD3v0IYNFggl3ygk__l-pZ9jtlsf0AyuFJlRaaEouhzYgau2zOcHwBQp2eEbVMiHVcHrE9R2670dlhA1a7jaKq3ALRx2h-h2TIkxxh82oyr4c4LqzraUecL8SFek-IbvEBfv30695FKOt3FXEk7y5G_JW3yaRQGczL3TQ\"\r\n"]
TEST_CA_FILE = "tests/fixtures/test_ca.pem"
TEST_CA_KEY_FILE = "tests/fixtures/test_ca_prv.pem"
TEST_CGSN = [b"OK\r\n", b"355025930000000\r\n"]

class FakeSerial(Mock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = []
    def write(self, data):
        data_str = data.decode('utf-8')
        if data_str.strip() == ('AT%KEYGEN=52,2,0'):
            self.response = TEST_KEYGEN_UUID.copy()
        elif data_str.strip() == ('AT%KEYGEN=52,2,0,"CN=nrf-355025930000000"'):
            self.response = TEST_KEYGEN_IMEI.copy()
        elif data_str.strip() == "AT+CGSN":
            self.response = TEST_CGSN.copy()
        elif data_str.strip() == "AT+CFUN=4":
            self.response = [b"OK\r\n"]
        elif data_str.strip() == "AT+CGMR":
            self.response = [b"OK\r\n", b"mfw_nrf91x1_2.0.2\r\n"]
        elif data_str.strip().startswith("AT%CMNG=0,52,0,\""):
            self.response = [b"OK\r\n"]
        elif data_str.strip().startswith("AT%CMNG=0,52,1,\""):
            self.response = [b"OK\r\n"]
        elif len(data_str.strip()) == 0:
            self.response = [b"OK\r\n"]
        else:
            self.response = [b"ERROR\r\n"]
    def readline(self):
        if len(self.response) == 0:
            return b""
        response = self.response.pop()
        return response

FakeSerialPort = namedtuple("FakeSerialPort", ["device"])

class TestDeviceCredentialsInstaller:
    @patch("nrfcredstore.comms.select_device", return_value=(FakeSerialPort("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcredstore.comms.serial.Serial", return_value=FakeSerial())
    def test_minimal_case(self, ser, select_device):
        with TemporaryDirectory() as tmp_dir:
            csv_file = os.path.join(tmp_dir, 'onboard.csv')
            args = f"--port /not/a/real/device --log-level debug --cmd-type at --ca {TEST_CA_FILE} --ca-key {TEST_CA_KEY_FILE} --csv {csv_file} --term CRLF --sectag 52".split()
            # call DUT
            device_credentials_installer.main(args)
            # check that the file was created
            assert os.path.exists(csv_file)
            # check that the file has the expected contents
            with open(csv_file, "r") as f:
                content = f.read().strip()
            device_id, sub_type, tags, fw_types, cert_pem = content.split(",")
            cert_pem = cert_pem.replace("\"", "").strip()
            assert device_id == "50363953-3234-4723-80b9-1503d88271bf"
            assert fw_types == "APP|MODEM"
            assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
            assert cert_pem.endswith("-----END CERTIFICATE-----")

    @patch("nrfcredstore.comms.select_device", return_value=(FakeSerialPort("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcredstore.comms.serial.Serial", return_value=FakeSerial())
    def test_nrf_prefix(self, ser, select_device):
        with TemporaryDirectory() as tmp_dir:
            csv_file = os.path.join(tmp_dir, 'onboard.csv')
            args = f"--port /not/a/real/device --log-level debug --id-imei --id-str nrf- --cmd-type at --ca {TEST_CA_FILE} --ca-key {TEST_CA_KEY_FILE} --csv {csv_file} --term CRLF --sectag 52".split()
            # call DUT
            device_credentials_installer.main(args)
            # check that the file was created
            assert os.path.exists(csv_file)
            # check that the file has the expected contents
            with open(csv_file, "r") as f:
                content = f.read().strip()
            device_id, sub_type, tags, fw_types, cert_pem = content.split(",")
            cert_pem = cert_pem.replace("\"", "").strip()
            assert device_id == "nrf-355025930000000"
            assert fw_types == "APP|MODEM"
            assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
            assert cert_pem.endswith("-----END CERTIFICATE-----")


# --- nrf_cloud_cred_shell command type ---------------------------------------
#
# This command type generates the device private key and CSR on-device via the
# 'nrf_cloud_cred' shell commands; certificates are still written with the
# inherited TLS Credentials Shell commands. The private key stays in PSA, so it
# is verified by matching the device public key against the device certificate
# instead of by hash.

NRF_CLOUD_CRED_CN = "test-device-id"
NRF_CLOUD_CRED_SECTAG = 52


def _make_device_key_and_csr(cn):
    """Build an on-device-style EC P-256 key + CSR the way the device would.

    Returns (base64 DER CSR, base64 SEC1-uncompressed public key). The CSR is
    what 'nrf_cloud_cred csr' prints; the public key is what
    'nrf_cloud_cred pubkey' prints. Because the device certificate is created
    from this CSR, its public key equals this key's public key, so the
    public-key verification matches.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .sign(key, hashes.SHA256())
    )
    csr_der_b64 = base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()
    pub_sec1 = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return csr_der_b64, base64.b64encode(pub_sec1).decode()


DEV_CSR_DER_B64, DEV_PUBKEY_B64 = _make_device_key_and_csr(NRF_CLOUD_CRED_CN)


class FakeShellSerial(Mock):
    """A stateful fake device speaking the Zephyr shell protocol.

    It answers the 'nrf_cloud_cred' keygen/csr/pubkey commands and the TLS
    Credentials Shell 'cred' commands. For 'cred add' it reassembles the
    base64 chunks, and for 'cred list' it returns the SHA-256 hash the
    installer expects, so --verify passes end-to-end against real crypto.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lines = deque()
        self._buf = ""       # accumulated base64 chunks for the current credential
        self._hashes = {}    # cred type string -> base64(sha256(cred + NUL))

    def _queue(self, *lines):
        for line in lines:
            self._lines.append((line + "\r\n").encode())

    def write(self, data):
        cmd = data.decode("utf-8", errors="replace").strip()
        parts = cmd.split()

        if cmd.startswith("nrf_cloud_cred keygen"):
            self._queue(f"Generated device key in sec tag {parts[-1]}")
        elif cmd.startswith("nrf_cloud_cred csr"):
            self._queue(f"CSR: {DEV_CSR_DER_B64}", "CSR generation complete")
        elif cmd.startswith("nrf_cloud_cred pubkey"):
            self._queue(f"PUBKEY: {DEV_PUBKEY_B64}", "Public key export complete")
        elif cmd == "cred buf clear":
            self._buf = ""            # no response expected after clear
        elif cmd.startswith("cred buf "):
            self._buf += cmd[len("cred buf "):]
            self._queue("Stored")
        elif cmd.startswith("cred add "):
            # cred add <sectag> <TYPE> DEFAULT bint
            cred_type = parts[3]
            raw = base64.b64decode(self._buf)
            self._hashes[cred_type] = base64.b64encode(
                hashlib.sha256(raw + b"\x00").digest()).decode()
            self._buf = ""
            self._queue("Added TLS credential")
        elif cmd.startswith("cred list "):
            # cred list <sectag> <TYPE>
            sectag, cred_type = parts[2], parts[3]
            self._queue(f"{sectag},{cred_type},{self._hashes.get(cred_type, '')},0",
                        "1 credentials found.")
        # Any other command (including the empty line-ending probe) gets no
        # response, which is what the installer expects for those.

    def readline(self):
        if self._lines:
            return self._lines.popleft()
        return b""


FakeSerialPortShell = namedtuple("FakeSerialPortShell", ["device"])


class TestNrfCloudCredShell:
    def _base_args(self, csv_file, extra=""):
        return (
            f"--port /not/a/real/device --log-level debug "
            f"--cmd-type nrf_cloud_cred_shell "
            f"--ca {TEST_CA_FILE} --ca-key {TEST_CA_KEY_FILE} "
            f"--csv {csv_file} --term CRLF --sectag {NRF_CLOUD_CRED_SECTAG} "
            f"--id-str {NRF_CLOUD_CRED_CN} {extra}"
        ).split()

    def _assert_onboard_csv(self, csv_file):
        assert os.path.exists(csv_file)
        with open(csv_file, "r") as f:
            content = f.read().strip()
        device_id, _sub_type, _tags, _fw_types, cert_pem = content.split(",")
        cert_pem = cert_pem.replace("\"", "").strip()
        # The device ID comes from the CN of the on-device CSR.
        assert device_id == NRF_CLOUD_CRED_CN
        assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert cert_pem.endswith("-----END CERTIFICATE-----")

    @patch("nrfcredstore.comms.select_device",
           return_value=(FakeSerialPortShell("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcredstore.comms.serial.Serial", return_value=FakeShellSerial())
    def test_on_device_keygen_and_csr(self, ser, select_device):
        # Generates the key/CSR on-device, decodes the Base64 DER CSR, creates
        # and writes the device cert, and writes the onboarding CSV. No private
        # key is written to the device.
        with TemporaryDirectory() as tmp_dir:
            csv_file = os.path.join(tmp_dir, "onboard.csv")
            device_credentials_installer.main(self._base_args(csv_file))
            self._assert_onboard_csv(csv_file)

    @patch("nrfcredstore.comms.select_device",
           return_value=(FakeSerialPortShell("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcredstore.comms.serial.Serial", return_value=FakeShellSerial())
    def test_verify_by_public_key_match(self, ser, select_device):
        # With --verify, the certs are checked by hash and the on-device key is
        # verified by matching the device public key to the device certificate.
        # Reaching the CSV write means verification passed (a mismatch would
        # exit with code 12).
        with TemporaryDirectory() as tmp_dir:
            csv_file = os.path.join(tmp_dir, "onboard.csv")
            device_credentials_installer.main(self._base_args(csv_file, "--verify"))
            self._assert_onboard_csv(csv_file)

    @patch("nrfcredstore.comms.select_device",
           return_value=(FakeSerialPortShell("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcredstore.comms.serial.Serial", return_value=FakeShellSerial())
    def test_verify_fails_on_public_key_mismatch(self, ser, select_device):
        # If the device reports a public key that does not match the device
        # certificate, verification must fail (exit code 12).
        other_key = ec.generate_private_key(ec.SECP256R1())
        wrong_pub = base64.b64encode(other_key.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint)).decode()

        with TemporaryDirectory() as tmp_dir:
            csv_file = os.path.join(tmp_dir, "onboard.csv")
            fake = ser.return_value
            orig_write = fake.write

            def write_wrong_pubkey(data):
                cmd = data.decode("utf-8", errors="replace").strip()
                if cmd.startswith("nrf_cloud_cred pubkey"):
                    fake._queue(f"PUBKEY: {wrong_pub}", "Public key export complete")
                    return
                orig_write(data)

            fake.write = write_wrong_pubkey
            with pytest.raises(SystemExit) as e:
                device_credentials_installer.main(self._base_args(csv_file, "--verify"))
            assert e.value.code == 12

    def test_rejects_local_cert(self):
        # The key is generated on-device, so --local-cert is a mistake and must
        # be rejected before any device interaction.
        args = (
            f"--port /not/a/real/device --cmd-type nrf_cloud_cred_shell "
            f"--local-cert --ca {TEST_CA_FILE} --ca-key {TEST_CA_KEY_FILE} "
            f"--sectag {NRF_CLOUD_CRED_SECTAG}"
        ).split()
        with pytest.raises(SystemExit) as e:
            device_credentials_installer.main(args)
        assert e.value.code == 1
