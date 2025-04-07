"""
Test for device_credentials_installer.py
"""

from unittest.mock import patch, Mock
from serial import Serial
import pytest
from nrfcloud_utils import gather_attestation_tokens
from tempfile import TemporaryDirectory
import os

# TODO: mock Serial
