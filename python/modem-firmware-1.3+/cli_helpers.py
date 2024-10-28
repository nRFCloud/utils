from colorama import init, Fore, Back, Style
from os import path
from os import makedirs
import platform

use_styles = True

is_macos = platform.system() == 'Darwin'
is_windows = platform.system() == 'Windows'
is_linux = platform.system() == 'Linux'
full_encoding = 'mbcs' if is_windows else 'ascii'

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
    if is_windows:
        init(convert = use_styles)

def print_os_detect():
    print(local_style(f"OS detect: Linux={is_linux}, MacOS={is_macos}, Windows={is_windows}"))

def write_file(pathname, filename, bytes):
    """
    save bytes to file
    """

    if not path.isdir(pathname):
        try:
            makedirs(pathname, exist_ok=True)
        except OSError as e:
            raise RuntimeError("Error creating file path")

    full_path = path.join(pathname, filename)

    try:
        f = open(full_path, "wb")
    except OSError:
        raise RuntimeError("Error opening file: " + full_path)

    f.write(bytes)
    print("File created: " + path.abspath(f.name))
    f.close()

    return
