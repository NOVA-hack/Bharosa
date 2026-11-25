"""Clipboard reading for `bharosa watch clipboard` (stdlib only; uses tkinter, falls back to PowerShell)."""

from __future__ import annotations

import platform
import re
import shutil
import subprocess

from .checks.extract import extract_upi_uris, extract_urls, extract_vpas


def read_clipboard() -> str:
    try:
        import tkinter

        root = tkinter.Tk()
        root.withdraw()
        try:
            return root.clipboard_get()
        except tkinter.TclError:
            return ""
        finally:
            root.destroy()
    except Exception:
        pass
    if platform.system() == "Windows" and shutil.which("powershell"):
        r = subprocess.run(["powershell", "-NoProfile", "-Command", "Get-Clipboard"], capture_output=True, text=True)
        return r.stdout.strip()
    for cmd in (["pbpaste"], ["xclip", "-o", "-selection", "clipboard"], ["wl-paste"]):
        if shutil.which(cmd[0]):
            return subprocess.run(cmd, capture_output=True, text=True).stdout
    return ""


def worth_checking(text: str) -> bool:
    """Only clips that contain a link, a UPI link or a UPI ID, or look like a message, are checked."""
    text = text.strip()
    if not text or len(text) > 4096:
        return False
    if extract_upi_uris(text) or extract_urls(text) or extract_vpas(text):
        return True
    return len(re.findall(r"\w+", text)) >= 8
