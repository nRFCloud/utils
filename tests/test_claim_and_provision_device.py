"""
Test for claim_and_provision_device.py
"""

from unittest.mock import patch, Mock
from serial import Serial
import pytest
from nrfcloud_utils import gather_attestation_tokens
from tempfile import TemporaryDirectory

# TODO: mock Serial
# TODO: mock nrf_cloud_diap
