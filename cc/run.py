"""Subprocess runner. argv lists only, always a timeout, never a shell.

crosscheck flags `shell=True` sinks in other people's code, so it does not get
to have one. There is no `cmd: str` overload on purpose - if you cannot express
it as a list, you are building a shell string. >:[
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

DEFAULT_TIMEOUT = 120


@dataclass
class Proc:
    argv: list[str]
    code: int
    out: str
    err: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.code == 0 and not self.timed_out

    def text(self) -> str:
        return (self.out or "") + (self.err or "")


def have(tool: str) -> bool:
    """Is this tool on PATH? Used to decide delegate-vs-declare-invalid."""
    return shutil.which(tool) is not None


def run(
    argv: list[str],
    cwd: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    env: dict | None = None,
    stdin: str | None = None,
) -> Proc:
    if not isinstance(argv, (list, tuple)) or not argv:
        raise TypeError("argv must be a non-empty list - no shell strings here")
    argv = [str(a) for a in argv]

    full_env = os.environ.copy()
    if env:
        full_env.update(env)

    try:
        p = subprocess.run(
            argv,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=full_env,
            input=stdin,
            shell=False,
        )
    except subprocess.TimeoutExpired as e:
        # A timeout is never "clean". Callers turn this into INVALID. 💀
        return Proc(
            argv=argv,
            code=124,
            out=(e.stdout or "") if isinstance(e.stdout, str) else "",
            err=f"timed out after {timeout}s",
            timed_out=True,
        )
    except FileNotFoundError:
        return Proc(argv=argv, code=127, out="", err=f"not found: {argv[0]}")
    except PermissionError:
        return Proc(argv=argv, code=126, out="", err=f"not executable: {argv[0]}")

    return Proc(argv=argv, code=p.returncode, out=p.stdout or "", err=p.stderr or "")
