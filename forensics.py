
import hashlib
import json
import shutil
import subprocess
import platform
from pathlib import Path


# --------------------------------------------------
# EXIFTOOL CONFIGURATION
# --------------------------------------------------

WINDOWS_EXIFTOOL = Path(
    r"C:\exiftool-13.60_64\exiftool.exe"
)


def find_exiftool():

    tool = shutil.which("exiftool")

    if tool:
        return tool

    if platform.system() == "Windows":
        if WINDOWS_EXIFTOOL.is_file():
            return str(WINDOWS_EXIFTOOL)

    return None


# --------------------------------------------------
# SHA-256
# --------------------------------------------------

def sha256_file(filepath):

    h = hashlib.sha256()

    with open(filepath, "rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b""
        ):
            h.update(chunk)

    return h.hexdigest()


# --------------------------------------------------
# TOOL AVAILABILITY
# --------------------------------------------------

def tool_availability():

    exif = find_exiftool()
    tshark = shutil.which("tshark")

    return [
        {
            "Tool": "ExifTool",
            "Available": bool(exif),
            "Input": "Supported image/document metadata"
        },
        {
            "Tool": "TShark",
            "Available": bool(tshark),
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


# --------------------------------------------------
# COMMAND EXECUTION
# --------------------------------------------------

def command(tool, args, timeout=60):

    try:

        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        output = (p.stdout or "") + (
            "\n" + p.stderr if p.stderr else ""
        )

        return {
            "tool": tool,
            "status": (
                "SUCCESS"
                if p.returncode == 0
                else "ERROR"
            ),
            "output": (
                output[:20000]
                or f"Exit code {p.returncode}; no text output."
            )
        }

    except subprocess.TimeoutExpired:

        return {
            "tool": tool,
            "status": "ERROR",
            "output": f"{tool} timed out."
        }

    except Exception as exc:

        return {
            "tool": tool,
            "status": "ERROR",
            "output": str(exc)
        }


# --------------------------------------------------
# MAIN FORENSIC ANALYSIS
# Supports BOTH old and new calling methods
# --------------------------------------------------

def run_applicable_tools(
    evidence_id,
    filepath=None,
    actor=None
):

    # Backward compatibility:
    # run_applicable_tools(evidence_id)

    if filepath is None:

        try:
            from database import get_evidence

            evidence = get_evidence(evidence_id)

            if not evidence:
                return [{
                    "tool": "Evidence Check",
                    "status": "ERROR",
                    "output": "Evidence ID not found."
                }]

            filepath = evidence.get("filepath")
            actor = actor or evidence.get(
                "collected_by",
                "Unknown"
            )

        except Exception as exc:

            return [{
                "tool": "Evidence Check",
                "status": "ERROR",
                "output": str(exc)
            }]

    if not actor:
        actor = "Unknown"

    if not filepath:

        return [{
            "tool": "Evidence Check",
            "status": "ERROR",
            "output": "Evidence filepath is missing."
        }]

    p = Path(filepath)

    if not p.is_file():

        return [{
            "tool": "Evidence Check",
            "status": "ERROR",
            "output": (
                "Evidence file not found. "
                "Please upload the evidence again."
            )
        }]

    results = []

    # --------------------------------------------------
    # EXIFTOOL
    # --------------------------------------------------

    exif = find_exiftool()

    if exif:

        results.append(
            command(
                "ExifTool",
                [
                    exif,
                    "-json",
                    str(p)
                ]
            )
        )

    else:

        results.append({
            "tool": "ExifTool",
            "status": "NOT INSTALLED",
            "output": (
                "ExifTool not found. "
                "Install ExifTool and configure its path."
            )
        })

    # --------------------------------------------------
    # TSHARK
    # --------------------------------------------------

    tshark = shutil.which("tshark")

    if p.suffix.lower() in (
        ".pcap",
        ".pcapng"
    ):

        if tshark:

            results.append(
                command(
                    "TShark",
                    [
                        tshark,
                        "-r",
                        str(p),
                        "-c",
                        "100"
                    ],
                    timeout=90
                )
            )

        else:

            results.append({
                "tool": "TShark",
                "status": "NOT INSTALLED",
                "output": (
                    "Install Wireshark/TShark "
                    "and ensure TShark is on PATH."
                )
            })

    else:

        results.append({
            "tool": "TShark",
            "status": "SKIPPED",
            "output": (
                f"Input is {p.suffix or 'unknown'}. "
                "TShark requires PCAP/PCAPNG files."
            )
        })

    # --------------------------------------------------
    # SHA-256
    # --------------------------------------------------

    try:

        hash_value = sha256_file(str(p))

        results.append({
            "tool": "SHA-256",
            "status": "SUCCESS",
            "output": json.dumps(
                {
                    "evidence_id": evidence_id,
                    "file": p.name,
                    "sha256": hash_value,
                    "actor": actor
                },
                indent=2
            )
        })

    except Exception as exc:

        results.append({
            "tool": "SHA-256",
            "status": "ERROR",
            "output": str(exc)
        })

    return results


# --------------------------------------------------
# END OF SECURELAND FORENSICS MODULE
# --------------------------------------------------
