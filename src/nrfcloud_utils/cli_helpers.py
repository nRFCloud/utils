#!/usr/bin/env python3
#
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause

from colorama import init, Fore, Back, Style
from os import path
from os import makedirs

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
