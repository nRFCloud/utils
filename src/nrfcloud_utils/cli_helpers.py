#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

from colorama import init, Fore, Back, Style
from os import path
from os import makedirs
import platform
import os
import csv

MAX_CSV_ROWS = 1000

is_macos = platform.system() == 'Darwin'
is_windows = platform.system() == 'Windows'
is_linux = platform.system() == 'Linux'
full_encoding = 'mbcs' if is_windows else 'ascii'

use_styles = True

def cli_disable_styles():
    global use_styles
    use_styles = False

def local_style(line):
    global use_styles
    return (Fore.CYAN + line + Style.RESET_ALL) if use_styles else line

def hivis_style(line):
    global use_styles
    return (Fore.MAGENTA + line + Style.RESET_ALL) if use_styles else line

def send_style(line):
    global use_styles
    return (Fore.BLUE + line + Style.RESET_ALL) if use_styles else line

def error_style(line):
    global use_styles
    return (Fore.RED + line + Style.RESET_ALL) if use_styles else line

def init_colorama():
    init(convert = use_styles)

def write_file(pathname, filename, bytes):
    """
    save bytes to file
    """

    if not path.isdir(pathname):
        try:
            makedirs(pathname, exist_ok=True)
        except OSError as e:
            raise RuntimeError(f"Error creating file path [{pathname}]")

    full_path = path.join(pathname, filename)

    try:
        f = open(full_path, "wb")
    except OSError:
        raise RuntimeError("Error opening file: " + full_path)

    f.write(bytes)
    print("File created: " + path.abspath(f.name))
    f.close()

    return

def user_request_open_mode(filename, append):
    mode = 'a' if append else 'w'
    exists = os.path.isfile(filename)

    # if not appending, give user a choice whether to overwrite
    if not append and exists:
        answer = ' '
        while answer not in 'yan':
            answer = input('--- File {} exists; overwrite, append, or quit (y,a,n)? '.format(filename))

        if answer == 'n':
            print(local_style('File will not be overwritten'))
            return None
        elif answer == 'y':
            mode = 'w'
        else:
            mode = 'a'

    elif not exists and append:
        mode = 'w'
        print('Append specified but file does not exist...')

    return mode

def save_onboarding_csv(csv_filename, append, replace, dev_id, sub_type, tags, fw_types, dev):
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return

    row_count = 0

    row = [dev_id, sub_type, tags, fw_types, str(dev, encoding=full_encoding)]

    if mode == 'a':
        do_not_write = False
        duplicate_rows, row_count = check_if_device_exists_in_csv(csv_filename, dev_id, replace)

        if row_count >= MAX_CSV_ROWS:
            print(error_style('Onboarding CSV file is full'))
            do_not_write = True

        if len(duplicate_rows):
            if replace:
                print(hivis_style(f'Removed existing device onboarding data:\r\n\t{duplicate_rows}'))
            else:
                print(error_style(f'Onboarding CSV file already contains device \'{dev_id}\''))
                do_not_write = True

        if do_not_write:
            print(error_style('The following row was NOT added to the onboarding CSV file:'))
            print(local_style(str(row)))
            return

    try:
        with open(csv_filename, mode, newline='\n') as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=',', lineterminator='\n',
                                    quoting=csv.QUOTE_MINIMAL)
            csv_writer.writerow(row)
        print(local_style(f'Onboarding CSV file saved, row count: {row_count + 1}'))
    except OSError:
        print(error_style(f'Error opening file {csv_filename}'))

def check_if_device_exists_in_csv(csv_filename, dev_id, delete_duplicates):
    row_count = 0
    duplicate_rows = list()
    if delete_duplicates:
        keep_rows = list()

    try:
        with open(csv_filename) as csvfile:
            csv_contents = csv.reader(csvfile, delimiter=',')

            for row in csv_contents:
                row_count += 1
                # First column is the device ID
                if row[0] == dev_id:
                    # Device ID found, save the row
                    duplicate_rows.append(row)
                else:
                    if delete_duplicates:
                        # Copy all non-duplicate rows if the delete flag is set
                        keep_rows.append(row)

            csvfile.close()
    except OSError:
        print(error_style(f'Error opening (read) file {csv_filename}'))

    # Re-write the file without the duplicate rows
    if delete_duplicates and len(duplicate_rows):
        # Get new row count
        row_count = len(keep_rows)
        try:
            with open(csv_filename, 'w', newline='\n') as csvfile:
                csv_writer = csv.writer(csvfile, delimiter=',', lineterminator='\n',
                                        quoting=csv.QUOTE_MINIMAL)
                csv_writer.writerows(keep_rows)
                csvfile.close()
        except OSError:
            print(error_style(f'Error opening file (write) {csv_filename}'))

    return duplicate_rows, row_count

def save_devinfo_csv(csv_filename, append, replace, dev_id, mfw_ver = None, imei = None):
    mode = user_request_open_mode(csv_filename, append)

    if mode == None:
        return

    row_count = 0

    row = f'{dev_id},{mfw_ver if mfw_ver else ""},{imei if imei else ""}\n'

    if mode == 'a':
        duplicate_rows, row_count = check_if_device_exists_in_csv(csv_filename, dev_id, replace)

        if len(duplicate_rows):
            if replace:
                print(hivis_style(f'Removed existing device info data:\r\n\t{duplicate_rows}'))
            else:
                print(error_style('Device already exists in device info CSV, the following row was NOT added:'))
                print(local_style(row))
                return

    try:
        with open(csv_filename, mode, newline='\n') as devinfo_file:
            devinfo_file.write(row)
        print(local_style(f'Device info CSV file saved, row count: {row_count + 1}'))
    except OSError:
        print(error_style('Error opening file {}'.format(csv_filename)))
