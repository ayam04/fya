from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional

KNOWN_TOOLS = {
    "nuclei": ["-version"],
    "nikto": ["-Version"],
    "sqlmap": ["--version"],
    "nmap": ["--version"],
    "testssl.sh": ["--version"],
    "sslyze": ["--help"],
    "jadx": ["--version"],
    "apkleaks": ["--version"],
}


def which(tool: str) -> Optional[str]:
    return shutil.which(tool)


def tool_version(tool: str) -> str:
    path = which(tool)
    if not path:
        return ""
    args = KNOWN_TOOLS.get(tool, ["--version"])
    code, out, err = run([path, *args], timeout=20)
    text = (out or err or "").strip().splitlines()
    return text[0][:120] if text else ("present" if code is not None else "")


def detect_tools() -> dict:
    found = {}
    for tool in KNOWN_TOOLS:
        path = which(tool)
        if path:
            found[tool] = {"path": path, "version": tool_version(tool)}
    return found


def run(args: List[str], timeout: float = 120.0, input_text: Optional[str] = None):
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        return None, exc.stdout or "", exc.stderr or "timeout"
    except (OSError, ValueError) as exc:
        return None, "", str(exc)
