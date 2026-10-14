"""
Contain spawned processes in a Windows Job Object.

Measured problem, not a theoretical one: a child spawned through `sh.run`
survives the death of the process that spawned it. Kill the client mid-scan and
the scan keeps running — burning CPU, holding file handles, and writing into a
session folder nobody is watching any more.

The fix is the same mechanism the Rust client already uses for the server
process: a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. A job's
processes die when the last handle to the job closes, and children inherit the
job unless they explicitly break away. So assigning *this* process to a job
covers everything `sh.run`, `code.run` and `job.submit` ever spawn, however
deep, without touching any of them.

Two further limits are worth having and one is deliberately left out:

* `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` — a cap on concurrent processes, so a
  runaway loop that spawns cannot take the machine down. Set generously; the
  point is to stop a fork bomb, not to police normal work.
* **No memory cap.** A memory limit would kill exactly the legitimate case this
  runtime exists for — loading a 411 MB executable, or holding a 9649-case
  sweep in memory. A limit that breaks the real work gets disabled by whoever
  it breaks, and then it protects nothing.

Nested jobs are supported from Windows 8 on, so this composes with the job the
Rust client already creates rather than fighting it. Every call here is
best-effort: a machine or a configuration that refuses the job must still run
xcore. Containment is an improvement to the failure mode, never a precondition.
"""

from __future__ import annotations

import sys
import threading

_job_handle = None
_lock = threading.RLock()

# Enough for a sweep that shells out per sample, far below a fork bomb.
MAX_CONCURRENT_PROCESSES = 128

_APPLIED = "applied"
_UNSUPPORTED = "unsupported-platform"
_FAILED = "failed"

_last_result = {"status": "not-attempted", "detail": ""}


def status() -> dict:
    return dict(_last_result, handle=_job_handle is not None)


def contain_children(max_processes: int = MAX_CONCURRENT_PROCESSES) -> dict:
    """Put this process in a kill-on-close job so its descendants cannot outlive it.

    Idempotent, and never raises: the caller is usually startup code, and a
    runtime that refuses to boot because it could not harden itself is a worse
    outcome than one that boots unhardened and says so.
    """
    global _job_handle
    with _lock:
        if _job_handle is not None:
            return status()
        if sys.platform != "win32":
            _last_result.update(status=_UNSUPPORTED,
                                detail="job objects are Windows-only")
            return status()
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            class IO_COUNTERS(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in
                            ("ReadOperationCount", "WriteOperationCount",
                             "OtherOperationCount", "ReadTransferCount",
                             "WriteTransferCount", "OtherTransferCount")]

            class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation",
                     JOBOBJECT_BASIC_LIMIT_INFORMATION),
                    ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
            JobObjectExtendedLimitInformation = 9

            # argtypes are not optional here. Without them ctypes passes a
            # Python int as a C int, and a 64-bit HANDLE overflows:
            # "OverflowError: int too long to convert". The first version
            # omitted them and failed on every call.
            kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p,
                                                  wintypes.LPCWSTR]
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = [
                wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.GetCurrentProcess.argtypes = []
            kernel32.GetCurrentProcess.restype = wintypes.HANDLE
            kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE,
                                                          wintypes.HANDLE]
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL

            job = kernel32.CreateJobObjectW(None, None)
            if not job:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW")

            info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            info.BasicLimitInformation.LimitFlags = (
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
            info.BasicLimitInformation.ActiveProcessLimit = max_processes
            ok = kernel32.SetInformationJobObject(
                job, JobObjectExtendedLimitInformation,
                ctypes.byref(info), ctypes.sizeof(info))
            if not ok:
                raise OSError(ctypes.get_last_error(), "SetInformationJobObject")

            process = kernel32.GetCurrentProcess()
            if not kernel32.AssignProcessToJobObject(job, process):
                # Windows 7 cannot nest jobs; Windows 8+ can, which is what lets
                # this compose with the job the Rust client already owns.
                raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject")

            _job_handle = job
            _last_result.update(
                status=_APPLIED,
                detail=(f"kill-on-close job, active-process cap "
                        f"{max_processes}"))
        except Exception as exc:  # noqa: BLE001 - hardening must not break boot
            _last_result.update(
                status=_FAILED,
                detail=(f"{type(exc).__name__}: {exc}. Spawned processes may "
                        f"outlive xcore."))
        return status()
