
import hashlib
import json
import shutil
import subprocess
import platform
from pathlib import Path


# ExifTool location for Windows and Streamlit Cloud
WINDOWS_EXIFTOOL = Path(
    r"C:\exiftool-13.60_64\exiftool.exe"
)


def find_exiftool():
    # First check PATH
    tool = shutil.which("exiftool")
    if tool:
        return tool

    # Windows fixed installation path
    if platform.system() == "Windows" and WINDOWS_EXIFTOOL.is_file():
        return str(WINDOWS_EXIFTOOL)

    return None


def sha256_file(filepath):
    h = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.hexdigest()


def tool_availability():
    return [
        {
            "Tool": "ExifTool",
            "Available": bool(find_exiftool()),
            "Input": "Supported image/document metadata"
        },
        {
            "Tool": "tshark",
            "Available": bool(shutil.which("tshark")),
            "Input": ".pcap / .pcapng"
        },
        {
            "Tool": "FTK Imager",
            "Available": "External app",
            "Input": "Disk image / acquisition"
        },
        {
            "Tool": "Autopsy",
            "Available": "External app",
            "Input": "Forensic case / disk image"
        }
    ]


def command(tool, args, timeout=60):
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        out = (p.stdout or "") + (
            "\n" + p.stderr if p.stderr else ""
        )

        return {
            "tool": tool,
            "status": "SUCCESS" if p.returncode == 0 else "ERROR",
            "output": out[:20000] or
            f"Exit code {p.returncode}; no text output."
        }

    except subprocess.TimeoutExpired:
        return {
            "tool": tool,
            "status": "ERROR",
            "output": f"{tool} timed out."
        }

    except Exception as e:
        return {
            "tool": tool,
            "status": "ERROR",
            "output": str(e)
        }


def run_applicable_tools(evidence_id, filepath, actor):
    p = Path(filepath)

    if not filepath or not p.is_file():
        return [{
            "tool": "Evidence Check",
            "status": "ERROR",
            "output": "No valid evidence file path. Re-acquire evidence."
        }]

    out = []

    # ExifTool
    exif = find_exiftool()

    if exif:
        out.append(
            command("ExifTool", [exif, "-json", str(p)])
        )
    else:
        out.append({
            "tool": "ExifTool",
            "status": "NOT INSTALLED",
            "output": (
                "ExifTool not found. Install ExifTool "
                "and configure its executable path."
            )
        })

    # tshark
    tshark = shutil.which("tshark")

    if p.suffix.lower() in (".pcap", ".pcapng"):
        if tshark:
            out.append(
                command(
                    "tshark",
                    [tshark, "-r", str(p), "-c", "100"],
                    90
                )
            )
        else:
            out.append({
                "tool": "tshark",
                "status": "NOT INSTALLED",
                "output": "Install Wireshark/tshark and configure PATH."
            })
    else:
        out.append({
            "tool": "tshark",
            "status": "SKIPPED",
            "output": (
                f"Input is {p.suffix or 'unknown'}; "
                "tshark requires .pcap/.pcapng."
            )
        })

    # SHA-256
    try:
        out.append({
            "tool": "SHA-256",
            "status": "SUCCESS",
            "output": json.dumps({
                "evidence_id": evidence_id,
                "file": p.name,
                "sha256": sha256_file(str(p)),
                "actor": actor
            }, indent=2)
        })

    except Exception as e:
        out.append({
            "tool": "SHA-256",
            "status": "ERROR",
            "output": str(e)
        })

    return out
