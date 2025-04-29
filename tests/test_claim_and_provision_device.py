"""
Test for claim_and_provision_device.py
"""

from unittest.mock import patch, Mock
from serial import Serial
import pytest
from nrfcloud_utils import claim_and_provision_device
from tempfile import TemporaryDirectory
from requests import Response
from collections import namedtuple
from uuid import uuid4

TEST_ATTESTTOKEN = [b"OK\r\n", b"%ATTESTTOKEN: \"2dn3hQFQUDYxVDkxRPCAIhIbZAFifQNQGv86y_GmR2SiY0wmRsHGVFDT791_BPH8YOWFiyCHND1q.0oRDoQEmoQRBIfZYQGuXwJliinHc6xDPruiyjsaXyXZbZVpUuOhHG9YS8L05VuglCcJhMN4EUhWVGpaHgNnHHno6ahi-d5tOeZmAcNY\"\r\n"]
TEST_CGSN = [b"OK\r\n", b"355025930000000\r\n"]
TEST_RESPONSE_201 = Response()
TEST_RESPONSE_201.status_code = 201

TEST_RESPONSE_CREATE_CSR = Response()
TEST_RESPONSE_CREATE_CSR.status_code = 201
TEST_RESPONSE_CREATE_CSR._content = b'{"id":"47be3210-0e73-4ce2-9533-59422c6cc781","deviceId":"50344354-3837-4d8d-8064-190467791bd9","ruleId":null,"description":"Generate CSR","request":{"certificateSigningRequest":{"secTag":16842753,"attributes":"CN=50344354-3837-4d8d-8064-190467791bd9","keyUsage":"101010000"},"requestedAt":null},"response":null,"status":"PENDING","createdAt":"2025-04-29T11:02:33.377Z","updatedAt":null}'

TEST_RESPONSE_GET_PROVISIONING_CMD = Response()
TEST_RESPONSE_GET_PROVISIONING_CMD.status_code = 200
TEST_RESPONSE_GET_PROVISIONING_CMD._content = b'{"id":"47be3210-0e73-4ce2-9533-59422c6cc781","deviceId":"50344354-3837-4d8d-8064-190467791bd9","ruleId":null,"description":"Generate CSR","request":{"certificateSigningRequest":{"secTag":16842753,"attributes":"CN=50344354-3837-4d8d-8064-190467791bd9","keyUsage":"101010000"},"requestedAt":"2025-04-29T11:02:53.327Z"},"response":{"certificateSigningRequest":{"message":"MIIBCzCBrwIBADAvMS0wKwYDVQQDDCQ1MDM0NDM1NC0zODM3LTRkOGQtODA2NC0xOTA0Njc3OTFiZDkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARDcYEtuo9L7xXvStpf0EDdqtw-EYRBxvu_KL4C--cm4xWLkKfV6tSWE0rFjgg5kUxj2nBQG08ZNZmTw6KvQpyuoB4wHAYJKoZIhvcNAQkOMQ8wDTALBgNVHQ8EBAMCA6gwDAYIKoZIzj0EAwIFAANJADBGAiEA9tirJwan6HnvQKx3dCVmbltMIFgmAjhGaA7jaWl5mekCIQDu5DakwwV7SZjkUAcCd4mls_Og0dy03Lc9wEr26v7_SA"},"respondedAt":"2025-04-29T11:02:53.327Z"},"status":"SUCCEEDED","createdAt":"2025-04-29T11:02:33.377Z","updatedAt":null}'

CA_FILE = "tests/fixtures/test_ca.pem"
CA_KEY_FILE = "tests/fixtures/test_ca_prv.pem"

class FakeSerial(Mock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response = []
    def write(self, data):
        print(data.__repr__())
        data_str = data.decode('utf-8')
        if data_str.strip().startswith('AT%ATTESTTOKEN'):
            print("putting ATTESTTOKEN in response")
            self.response = TEST_ATTESTTOKEN
        elif data_str.strip() == "AT+CGSN":
            self.response = TEST_CGSN
        elif data_str.strip() == "AT+CFUN=4":
            self.response = [b"OK\r\n"]
        elif len(data_str.strip()) == 0:
            self.response = [b"OK\r\n"]
        else:
            self.response = [b"ERROR\r\n"]
    def readline(self):
        print("readline called")
        if len(self.response) == 0:
            return b""
        response = self.response.pop()
        return response

FakeSerialPort = namedtuple("FakeSerialPort", ["device"])

class FakeCloud(Mock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pending_jobs = []
    def create_provisioning_cmd_client_cert(api_key, dev_uuid, cert_pem,
                                        description='Update client cert',
                                        sec_tag=16842753):
        self.pending_jobs.append((api_key, dev_uuid, cert_pem, description, sec_tag))


class TestClaimAndProvisionDevice:
    #@patch("nrfcloud_utils.claim_and_provision_device.nrf_cloud_diap")
    #@patch("nrfcloud_utils.comms.select_device", return_value=(FakeSerialPort("/not/a/real/device"), "TEST_DEVICE"))
    #@patch("nrfcloud_utils.comms.serial.Serial", return_value=FakeSerial())
    #def test_provisioning_tags(self, ser, select_device, diap):
    #    diap.claim_device = Mock(return_value=TEST_RESPONSE_201)
    #    args = f"--port /not/a/real/device --api-key NOTAKEY --provisioning-tags nrf-cloud-onboarding".split()
    #    # call DUT
    #    claim_and_provision_device.main(args)
    #    diap.claim_device.assert_called_once()

    @patch("nrfcloud_utils.claim_and_provision_device.nrf_cloud_diap")
    @patch("nrfcloud_utils.comms.select_device", return_value=(FakeSerialPort("/not/a/real/device"), "TEST_DEVICE"))
    @patch("nrfcloud_utils.comms.serial.Serial", return_value=FakeSerial())
    def test_with_ca(self, ser, select_device, diap):
        diap.claim_device = Mock(return_value=TEST_RESPONSE_201)
        diap.create_provisioning_cmd_csr = Mock(return_value=TEST_RESPONSE_CREATE_CSR)
        diap.get_provisioning_cmd = Mock(return_value=TEST_RESPONSE_GET_PROVISIONING_CMD)
        diap.create_provisioning_cmd_client_cert = Mock(return_value=TEST_RESPONSE_201)
        diap.create_provisioning_cmd_server_cert = Mock(return_value=TEST_RESPONSE_201)
        diap.create_provisioning_cmd_finished = Mock(return_value=TEST_RESPONSE_201)
        args = f"--port /not/a/real/device --api-key NOTAKEY --ca {CA_FILE} --ca-key {CA_KEY_FILE} --log-level debug".split()
        # call DUT
        claim_and_provision_device.main(args)
        diap.claim_device.assert_called_once()

# TODO: test with local CA
