#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

# comms module for nrfcloud-utils
# This module handles finding and selecting a device and doing serial comms with it.
# Both serial and RTT backends are supported.

from serial.tools import list_ports
import serial
from collections import defaultdict
import sys
import time
import atexit
import inquirer
from pynrfjprog import LowLevel
import coloredlogs, logging

logger = logging.getLogger(__name__)

usb_patterns = [
    (r"THINGY91X", "Thingy:91 X", 0),
    (r"THINGY91", "Thingy:91", 0),
    (r"PCA20035", "Thingy:91", 0),
    (r"0009600", "nRF9160-DK", 0),
    (r"0009601", "nRF5340-DK", 1),
    (r"0010500", "nRF5340-DK", 1),
    (r"0010507", "nRF7002-DK", 1),
    (r"0010509", "nRF9161-DK", 0),
    (r"0010510", "nRF9131-EK", 0),
    (r"0010511", "nRF54H20-DK", 0),
    (r"0010512", "nRF9151-DK", 0),
    (r"0010550", "Thingy:91 X", 0),
    (r"0010551", "Thingy:91 X", 0),
    (r"0010513", "Thingy:91 X", 0),
    (r"0010577", "nRF54L15-DK", 1),
    (r"00105", "Unknown Nordic Kit", 0),
    (r"NRFBLEGW", "nRF Cloud Gateway", 0),
]

# HWIDs look different on different platforms:
# Linux: 'USB VID:PID=1366:1059 SER=001051216197 LOCATION=3-12.1.3.2.1.4:1.0'
# MacOS: 'USB VID:PID=1366:1059 SER=001051246141 LOCATION=0-1.4.2.3'
# Windows: [(1, 'USB VID:PID=1366:1059 SER=001057731013'), (2, 'USB VID:PID=1366:1059 SER=001057731013 LOCATION=1-21:x.2')]


# returns a list of printable name, serial number and serial port for connected Nordic boards
def get_connected_nordic_boards():
    ports = list(sorted(list_ports.comports()))
    nordic_boards = defaultdict(list)
    for port in ports:
        # Get serial number from hwid, because port.serial_number is not always available
        serial = extract_serial_number_from_serial_device(port)
        nordic_boards[serial].append(port)
    main_ports = []
    for serial, ports in nordic_boards.items():
        for pattern, name, main_port in usb_patterns:
            if f"SER={pattern}" in ports[0].hwid:
                main_ports.append((name, serial, ports[main_port]))
                break
    return main_ports


# returns a list of SEGGER J-Link serial numbers as int
def get_connected_jlinks():
    with LowLevel.API(LowLevel.DeviceFamily.UNKNOWN) as api:
        return api.enum_emu_snr() or []


# for a serial device, return the serial number
def extract_serial_number_from_serial_device(dev):
    hwid = dev.hwid
    # Get serial number from hwid, because port.serial_number is not always available
    serial = [x[4:] for x in hwid.split(" ") if x.startswith("SER=")]
    if len(serial) == 0:
        return None
    serial = serial[0]

    if serial.isnumeric():
        return int(serial)

    return serial


# find the main port for a device if it's a Nordic board
def get_port_index(dev):
    for pattern, name, main_port in usb_patterns:
        if f"SER={pattern}" in dev.hwid:
            return main_port
    return None


def select_jlink(jlinks, list_all):
    if len(jlinks) == 0:
        raise Exception("No J-Link device found")
    if len(jlinks) == 1:
        return jlinks[0]
    if list_all:
        question = inquirer.List(
            "serial",
            message="Select a J-Link device",
            choices=[(str(serial), serial) for serial in jlinks],
        )
    else:
        nordic_boards = get_connected_nordic_boards()
        serial_numbers = [serial for _, serial, _ in nordic_boards if serial in jlinks]
        if len(serial_numbers) == 0:
            raise Exception("No J-Link device found")
        if len(serial_numbers) == 1:
            return serial_numbers[0]
        else:
            question = inquirer.List(
                "serial",
                message="Select a J-Link device",
                choices=[(str(serial), serial) for serial in serial_numbers],
            )
    answer = inquirer.prompt([question])
    return answer["serial"]


def select_device_by_serial(serial_number, list_all):
    serial_devices = [
        x
        for x in list_ports.comports()
        if extract_serial_number_from_serial_device(x) == serial_number
    ]
    if len(serial_devices) == 0:
        raise Exception(f"No device found with serial {serial_number}")
    if len(serial_devices) == 1:
        return (serial_devices[0], serial_number)

    if not list_all:
        port_index = get_port_index(serial_devices[0])
        if port_index is not None:
            # can return early if we can guess the right port
            return (serial_devices[port_index], serial_number)
    question = inquirer.List(
        "port",
        message="Select a serial port",
        choices=[(port.device, port) for port in serial_devices],
    )
    answer = inquirer.prompt([question])
    selected_port = answer["port"]
    return (selected_port, serial_number)


# returns serial_port, serial_number of selected device
def select_device(rtt, serial_number, port, list_all):
    if type(serial_number) == str and serial_number.isnumeric():
        serial_number = int(serial_number)

    if rtt:
        # RTT requires a J-Link device
        jlinks = get_connected_jlinks()
        if serial_number:
            if serial_number in jlinks:
                return (None, serial_number)
            else:
                raise Exception(f"No device found with serial {serial_number}")
        return (None, select_jlink(jlinks, list_all))

    if port:
        # Serial ports are unique, so we just check if it exists and try to get a serial number
        serial_devices = [x for x in list_ports.comports() if x.device == port]
        if len(serial_devices) == 0:
            raise Exception(f"No device found with port {port}")
        extracted_serial_number = extract_serial_number_from_serial_device(
            serial_devices[0]
        )
        if serial_number and extracted_serial_number != serial_number:
            logger.warning(
                f"Given Serial number {serial_number} does not match device serial number {extracted_serial_number}"
            )
        return (serial_devices[0], serial_number)

    if serial_number:
        # Often, there are multiple serial ports for a device, so we need to find the right one
        return select_device_by_serial(serial_number, list_all)

    if list_all:
        # Show all ports, no filtering
        ports = list_ports.comports()
        question = inquirer.List(
            "port",
            message="Select a serial port",
            choices=[(port.device, port) for port in ports],
        )
        answer = inquirer.prompt([question])
        selected_port = answer["port"]
        extracted_serial_number = extract_serial_number_from_serial_device(
            selected_port
        )
        return (selected_port, extracted_serial_number)

    # Select from connected Nordic boards
    nordic_boards = get_connected_nordic_boards()
    if len(nordic_boards) == 0:
        raise Exception("No device found")
    if len(nordic_boards) == 1:
        name, serial, port = nordic_boards[0]
        return (port, serial)
    inquirer.List(
        "port",
        message="Select a serial port",
        choices=[port.device for name, serial, port in nordic_boards],
    )
    answer = inquirer.prompt([question])
    selected_port = answer["port"]
    extracted_serial_number = extract_serial_number_from_serial_device(selected_port)
    return (selected_port, extracted_serial_number)


class Comms:
    def __init__(
        self,
        port=None,
        serial=None,
        baudrate=115200,
        xonxoff=False,
        rtscts=True,
        dsrdtr=False,
        timeout=1,
        line_ending=b"\r\n",
        rtt=False,
        list_all=False,
    ):
        self.timeout = timeout
        self.jlink_api = None
        self.serial_api = None
        self.write = None
        self.read_line = None
        self.line_ending = line_ending
        self._rtt_line_buffer = ''

        serial_port, self.serial_number = select_device(rtt, serial, port, list_all)

        if rtt:
            self._init_rtt()
        else:
            self._init_serial(serial_port, baudrate, xonxoff, rtscts, dsrdtr)

        atexit.register(self.close)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        if self.jlink_api:
            self.jlink_api.close()
            self.jlink_api = None
        if self.serial_api:
            self.serial_api.close()
            self.serial_api = None

    def write_line(self, data : str):
        self.write(data.encode('ascii') + self.line_ending)

    def _readline_rtt(self) -> str:
        time_end = time.time() + self.timeout
        while time.time() < time_end:
            self._rtt_line_buffer += self.jlink_api.rtt_read(channel_index=0, length=4096)
            # find first line ending
            line_end = self._rtt_line_buffer.find(self.line_ending.decode('ascii'))
            if line_end != -1:
                # split the line from the buffer
                line = self._rtt_line_buffer[:line_end]
                self._rtt_line_buffer = self._rtt_line_buffer[line_end + len(self.line_ending) :]
                return line
            time.sleep(0.1)
        return None

    def _readline_serial(self) -> str:
        # read a line from the serial port
        line = self.serial_api.readline()
        if line:
            return line.decode('utf-8').strip()
        return None

    def _write_rtt(self, data):
        # hacky workaround from old rtt_interface
        for i in range(0, len(data), 12):
            self.jlink_api.rtt_write(channel_index=0, msg=data[i : i + 12])
            time.sleep(0.01)

    def _write_serial(self, data):
        self.serial_api.write(data)

    def _init_rtt(self):
        self.jlink_api = LowLevel.API(LowLevel.DeviceFamily.UNKNOWN)
        self.jlink_api.open()
        self.jlink_api.connect_to_emu_with_snr(self.serial_number)
        self.jlink_api.select_family(self.jlink_api.read_device_family())
        self.jlink_api.sys_reset()
        self.jlink_api.go()
        self.jlink_api.rtt_start()
        for _ in range(5):
            if self.jlink_api.rtt_is_control_block_found():
                break
            time.sleep(0.5)
        self.write = self._write_rtt
        self.read_line = self._readline_rtt

    def _init_serial(self, serial_port, baudrate, xonxoff, rtscts, dsrdtr):
        self.serial_api = serial.Serial(
            port=serial_port.device,
            baudrate=baudrate,
            timeout=self.timeout,
            xonxoff=xonxoff,
            rtscts=rtscts,
            dsrdtr=dsrdtr,
        )
        # initialize the serial port, clear the buffers
        self.serial_api.reset_output_buffer()
        self.serial_api.write(self.line_ending)
        self.serial_api.flush()
        time.sleep(0.2)
        self.serial_api.reset_input_buffer()
        self.write = self._write_serial
        self.read_line = self._readline_serial

