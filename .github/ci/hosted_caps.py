"""Consumer10 fixed hosted entry. No local execution, SDK fallback or cap borrowing.
SDK-free parent holds actual nonroot/Job child until source/event/start/caps bind.
Inputs are admitted inside that boundary before any build/package payload.
"""
import argparse
import base64
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

REPOSITORY = "pouriajamali/price-time-matching-core"
SHARED = {"sdk10_hosted_inputs.py": "a0a71989c7629314b134955b2d697939d27059150181168935d998fcf1404a5e",
          "sdk10-inputs.lock.json": "582017ddb5fedcddcffcc66effb7dcb3f9b54949ed81ca3b033b15d78bfa44c8",
          "sdk10-members.jsonl": "edb30fd64e0d8e1c476e27a019dbb00fd7fe76989a5c3c991cbab16627f4d9cf"}
HOST_SHA = {"linux-x64": "99eb018192769d9964612afa04914e3c56187d87de1918426c0ade866db467a8",
            "win-x64": "0a1b7ca731245de1f267a9c3c4d1ef8705e0821923fcdd6e0d61c31132f51240"}
LOCK_SHA = "92226e085c0512971454e5e313d3fad8586565079110b85af9a3615e7be13386"
MS_CERT = "9A1B131BEE0605433056A4EA3815478A8E177961A968C6C0027C1093D1FEB630"
REPO_CERT = "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D"
CAP = {"cpu.max": "200000 100000", "memory.max": "2147483648", "memory.swap.max": "0", "pids.max": "128"}
KEEP_ORIGINAL_HANDLES = []


class Failure(RuntimeError):
    def __init__(self, cause, detail=""):
        self.cause = cause
        super().__init__(cause + (": " + detail if detail else ""))


def need(ok, cause, detail=""):
    if not ok:
        raise Failure(cause, detail)


def sha(path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with Path(path).open("rb") as f:
        for part in iter(lambda: f.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "DUPLICATE_JSON_FIELD", key)
        result[key] = value
    return result


def load(path, cap=8 * 1024 * 1024):
    p = Path(path)
    need(p.is_file() and not p.is_symlink() and p.stat().st_size <= cap, "METADATA_PATH_OR_CAP", str(p))
    return json.loads(p.read_text(encoding="utf-8"), object_pairs_hook=unique)


def save(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as f:
        json.dump(value, f, indent=2)
        f.write("\n"); f.flush(); os.fsync(f.fileno())


def remaining(ctx, ceiling=None):
    value = ctx["deadlineMono"] - time.monotonic()
    need(value > 0, "ROW_MONOTONIC_DEADLINE")
    return value if ceiling is None else min(value, ceiling)


def head(workspace):
    git = workspace / ".git"
    need(git.is_dir() and not git.is_symlink(), "SOURCE_GIT_DIRECTORY")
    value = (git / "HEAD").read_text().strip()
    if value.startswith("ref: "):
        ref = value[5:]
        need(re.fullmatch(r"refs/[A-Za-z0-9_./-]+", ref) and ".." not in ref.split("/"), "SOURCE_REF")
        loose = git / ref
        if loose.is_file():
            value = loose.read_text().strip()
        else:
            packed = (git / "packed-refs").read_text()
            matches = [line.split(" ")[0] for line in packed.splitlines() if line.endswith(" " + ref)]
            need(len(matches) == 1, "SOURCE_PACKED_REF")
            value = matches[0]
    return value


def windows_host_policy(observation):
    # Retain the existing win25 family; add only this documented image tuple.
    image_ok = (observation["imageOS"] == "win25" or
                (observation["imageOS"] == "win25-vs2026" and observation["imageVersion"] == "20261103.298.1"))
    version = observation["ntVersion"]
    need(image_ok and observation["runnerOS"] == "Windows" and observation["runnerArch"] == "X64"
         and observation["system"] == "Windows" and observation["pointerBits"] == 64
         and (version["major"], version["minor"], version["build"], version["productType"]) == (10, 0, 26100, 3)
         and observation["processMachine"] == 0 and observation["nativeMachine"] == 0x8664,
         "UNSUPPORTED_WINDOWS_HOSTED_IMAGE", json.dumps(observation, sort_keys=True))


def windows_host_observation():
    from ctypes import wintypes as T
    class VERSION(ctypes.Structure):
        _fields_ = [("size", T.DWORD), ("major", T.DWORD), ("minor", T.DWORD), ("build", T.DWORD),
                    ("platform", T.DWORD), ("servicePack", T.WCHAR * 128), ("servicePackMajor", T.WORD),
                    ("servicePackMinor", T.WORD), ("suiteMask", T.WORD), ("productType", T.BYTE), ("reserved", T.BYTE)]
    native = ctypes.WinDLL("ntdll", use_last_error=True)
    native.RtlGetVersion.argtypes = [ctypes.POINTER(VERSION)]; native.RtlGetVersion.restype = T.LONG
    version = VERSION(); version.size = ctypes.sizeof(version)
    need(native.RtlGetVersion(ctypes.byref(version)) == 0, "WINDOWS_RAW_VERSION_API")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []; kernel.GetCurrentProcess.restype = T.HANDLE
    kernel.IsWow64Process2.argtypes = [T.HANDLE, ctypes.POINTER(T.WORD), ctypes.POINTER(T.WORD)]
    kernel.IsWow64Process2.restype = T.BOOL
    process_machine, native_machine = T.WORD(), T.WORD()
    need(kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process_machine), ctypes.byref(native_machine)),
         "WINDOWS_RAW_ARCH_API", str(ctypes.get_last_error()))
    return {"imageOS": os.environ.get("ImageOS"), "imageVersion": os.environ.get("ImageVersion"),
            "runnerOS": os.environ.get("RUNNER_OS"), "runnerArch": os.environ.get("RUNNER_ARCH"),
            "system": platform.system(), "machine": platform.machine(), "platformVersion": platform.version(),
            "platformRelease": platform.release(), "pointerBits": ctypes.sizeof(ctypes.c_void_p) * 8,
            "ntVersion": {"major": version.major, "minor": version.minor, "build": version.build,
                          "productType": version.productType},
            "processMachine": process_machine.value, "nativeMachine": native_machine.value}


def source_event(expected_controller, expected_payload, rid):
    need(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "HOSTED_ONLY")
    expected_os = "Windows" if rid == "win-x64" else "Linux"
    need(platform.system() == expected_os and os.environ.get("RUNNER_OS") == expected_os
         and os.environ.get("RUNNER_ARCH") == "X64", "NATIVE_ROW_OS_ARCH")
    if rid == "linux-x64":
        need(os.environ.get("ImageOS") == "ubuntu24", "NATIVE_ROW_OS_ARCH")
    need(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY, "REPOSITORY_IDENTITY")
    workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    own = workspace / ".github" / "ci" / "hosted_caps.py"
    payload = workspace / ".github" / "ci" / "matching10-native.ps1"
    need(Path(__file__).resolve() == own and sha(own) == expected_controller, "CONTROLLER_SOURCE_IDENTITY")
    need(sha(payload) == expected_payload, "PAYLOAD_SOURCE_IDENTITY")
    if rid == "win-x64":
        host_observation = windows_host_observation()
        windows_host_policy(host_observation)
    else:
        host_observation = {"imageOS": os.environ.get("ImageOS"), "imageVersion": os.environ.get("ImageVersion"),
                            "runnerOS": os.environ.get("RUNNER_OS"), "runnerArch": os.environ.get("RUNNER_ARCH"),
                            "system": platform.system(), "machine": platform.machine()}
    source = os.environ.get("GITHUB_SHA", "")
    need(re.fullmatch(r"[0-9a-f]{40}", source) and head(workspace) == source, "CHECKOUT_HEAD_IDENTITY")
    event = os.environ.get("GITHUB_EVENT_NAME")
    ref = os.environ.get("GITHUB_REF", "")
    body = load(os.environ["GITHUB_EVENT_PATH"], 16 * 1024 * 1024)
    need(body.get("repository", {}).get("full_name", "").lower() == REPOSITORY, "EVENT_REPOSITORY")
    if event == "push":
        need(ref == "refs/heads/main" or ref.startswith("refs/tags/"), "EXISTING_PUSH_EVENT")
        need(body.get("ref") == ref and re.fullmatch(r"[0-9a-f]{40}", body.get("after", "")), "PUSH_REF_BINDING")
        if ref == "refs/heads/main":
            need(body["after"] == source, "PUSH_SOURCE_BINDING")
    elif event == "pull_request":
        need(re.fullmatch(r"refs/pull/[0-9]+/merge", ref)
             and body["pull_request"]["base"]["repo"]["full_name"].lower() == REPOSITORY, "EXISTING_PR_EVENT")
    else:
        need(event == "workflow_dispatch", "EXISTING_EVENT_ONLY")
    for name, digest in SHARED.items():
        need(sha(workspace / "tools" / name) == digest, "SHARED_INTERFACE_PIN", name)
    need(sha(workspace / "tests/Matching.Tests/packages.lock.json") == LOCK_SHA, "TEST_LOCK_IDENTITY")
    sdk_pin = load(workspace / "global.json")["sdk"]
    need(sdk_pin["version"] == "10.0.404" and sdk_pin["rollForward"] == "disable", "SOURCE_SDK_PIN")
    props = ET.parse(workspace / "Directory.Build.props").getroot()
    need(props.findtext(".//TargetFramework") == "net10.0" and props.findtext(".//RuntimeFrameworkVersion") == "10.0.15"
         and set(props.findtext(".//RuntimeIdentifiers").split(";")) == {"win-x64", "linux-x64"}, "SOURCE_FRAMEWORK_RID_GRAPH")
    return workspace, payload, {"event": event, "ref": ref, "source": source, "eventSHA256": sha(os.environ["GITHUB_EVENT_PATH"]),
                                "controllerSHA256": expected_controller, "payloadSHA256": expected_payload, "hostObservation": host_observation}


def linux_start(pid):
    value = Path("/proc/" + str(pid) + "/stat").read_text()
    return value[value.rfind(")") + 2:].split()[19]


def linux_identity(pid, unit, uid, gid):
    base = Path("/proc") / str(pid)
    status = (base / "status").read_text()
    need(int(re.search(r"^Uid:\s+(\d+)", status, re.M)[1]) == uid
         and int(re.search(r"^Gid:\s+(\d+)", status, re.M)[1]) == gid, "ACTUAL_NONROOT_RUNNER_IDENTITY")
    row = (base / "cgroup").read_text().strip()
    need(row.startswith("0::/"), "CGROUP_V2")
    group = Path("/sys/fs/cgroup") / row[4:]
    need(group.name == unit, "OWN_UNIT_MEMBERSHIP")
    values = {key: (group / key).read_text().strip() for key in CAP}
    need(values == CAP, "ACTUAL_KERNEL_CAP_MISMATCH")
    return {"pid": pid, "start": linux_start(pid), "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "uid": uid, "gid": gid, "cgroup": str(group), "caps": values,
            "availableCPUs": len(os.sched_getaffinity(pid))}


def budget(ctx, force=False):
    remaining(ctx)
    last = ctx.get("lastDiskMono", 0)
    if not force and time.monotonic() - last < 1:
        return
    ctx["lastDiskMono"] = time.monotonic()
    stage_path = Path(ctx["runRoot"]) / "stage.json"
    if stage_path.exists():
        stage = load(stage_path)
        need(time.monotonic() - stage["startedMono"] <= stage["maxSeconds"], "OWN_STAGE_DEADLINE", stage["name"])
    roots = [Path(ctx["workspace"]), Path(ctx["runRoot"]), Path(ctx["sdkStage"])]
    total = logs = 0
    for root in roots:
        if not root.exists():
            continue
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs:
                need(not (Path(directory) / name).is_symlink(), "OWN_STORAGE_LINK")
            for name in files:
                p = Path(directory) / name
                need(not p.is_symlink(), "OWN_STORAGE_LINK")
                try:
                    size = p.stat().st_size
                except FileNotFoundError:
                    continue
                total += size
                if name.endswith(".log"):
                    logs += size
                need(total <= 4294967296, "OWN_DISK_BUDGET")
                need(logs <= 8388608, "OWN_LOG_BUDGET")


def stage(ctx, name, cap):
    value = {"name": name, "startedMono": time.monotonic(), "maxSeconds": cap}
    p = Path(ctx["runRoot"]) / "stage.json"
    temporary = p.with_suffix(".new")
    save(temporary, value)
    os.replace(temporary, p)


def command(ctx, argv, name, cap, sdk=False, expected=0):
    stage(ctx, name, cap)
    logfile = Path(ctx["runRoot"]) / (name + ".log")
    if sdk:
        ctx["SDKLaunchAttempts"] += 1
    proc = None
    with logfile.open("xb") as log:
        try:
            proc = subprocess.Popen([str(x) for x in argv], cwd=ctx["workspace"], env=ctx["environment"],
                                    stdout=log, stderr=subprocess.STDOUT)
            if sdk:
                ctx["SDKProcessesStarted"] += 1
            while proc.poll() is None:
                budget(ctx)
                time.sleep(0.1)
            budget(ctx, True)
            need(proc.returncode == expected, "COMMAND_FAILED", name + " exit=" + str(proc.returncode))
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=3)
            if name == "nuget-signatures":
                ctx["signatureVerifyExitCode"] = proc.returncode if proc is not None else None
    need(logfile.stat().st_size <= 8388608, "OWN_LOG_BUDGET")
    return logfile.read_text(encoding="utf-8", errors="replace")


def release_child(ctx, identity):
    ready_path = Path(ctx["runRoot"]) / "held-ready.json"
    need(ready_path.is_file(), "HELD_READY_MISSING")
    ready = load(ready_path)
    need(ready["pid"] == identity["pid"] and ready["start"] == identity["start"]
         and ready["nonce"] == ctx["nonce"] and ready["source"] == ctx["binding"]["source"], "HELD_CHILD_START_BINDING")
    need(ready["controllerSHA256"] == ctx["binding"]["controllerSHA256"], "HELD_CHILD_SOURCE")
    save(Path(ctx["runRoot"]) / "release.json", {"pid": identity["pid"], "start": identity["start"], "nonce": ctx["nonce"]})
    return ready


def windows_api():
    from ctypes import wintypes as T
    K = ctypes.WinDLL("kernel32", use_last_error=True); SIZE = ctypes.c_size_t
    class IO(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount", "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]
    class BASIC(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong), ("LimitFlags", T.DWORD),
                    ("MinimumWorkingSetSize", SIZE), ("MaximumWorkingSetSize", SIZE), ("ActiveProcessLimit", T.DWORD),
                    ("Affinity", SIZE), ("PriorityClass", T.DWORD), ("SchedulingClass", T.DWORD)]
    class EXT(ctypes.Structure):
        _fields_ = [("Basic", BASIC), ("IoInfo", IO), ("ProcessMemoryLimit", SIZE), ("JobMemoryLimit", SIZE), ("PeakProcessMemoryUsed", SIZE), ("PeakJobMemoryUsed", SIZE)]
    class CPU(ctypes.Structure):
        _fields_ = [("Flags", T.DWORD), ("Rate", T.DWORD)]
    class START(ctypes.Structure):
        _fields_ = [("cb", T.DWORD), ("lpReserved", T.LPWSTR), ("lpDesktop", T.LPWSTR), ("lpTitle", T.LPWSTR),
                    ("dwX", T.DWORD), ("dwY", T.DWORD), ("dwXSize", T.DWORD), ("dwYSize", T.DWORD), ("dwXCountChars", T.DWORD),
                    ("dwYCountChars", T.DWORD), ("dwFillAttribute", T.DWORD), ("dwFlags", T.DWORD), ("wShowWindow", T.WORD),
                    ("cbReserved2", T.WORD), ("lpReserved2", ctypes.POINTER(ctypes.c_byte)), ("hStdInput", T.HANDLE), ("hStdOutput", T.HANDLE), ("hStdError", T.HANDLE)]
    class PROC(ctypes.Structure):
        _fields_ = [("hProcess", T.HANDLE), ("hThread", T.HANDLE), ("pid", T.DWORD), ("tid", T.DWORD)]
    signatures = {
        "CreateJobObjectW": ([ctypes.c_void_p, T.LPCWSTR], T.HANDLE), "SetInformationJobObject": ([T.HANDLE, ctypes.c_int, ctypes.c_void_p, T.DWORD], T.BOOL),
        "QueryInformationJobObject": ([T.HANDLE, ctypes.c_int, ctypes.c_void_p, T.DWORD, ctypes.c_void_p], T.BOOL),
        "CreateProcessW": ([T.LPCWSTR, T.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, T.BOOL, T.DWORD, ctypes.c_void_p, T.LPCWSTR, ctypes.POINTER(START), ctypes.POINTER(PROC)], T.BOOL),
        "AssignProcessToJobObject": ([T.HANDLE, T.HANDLE], T.BOOL), "IsProcessInJob": ([T.HANDLE, T.HANDLE, ctypes.POINTER(T.BOOL)], T.BOOL),
        "ResumeThread": ([T.HANDLE], T.DWORD), "WaitForSingleObject": ([T.HANDLE, T.DWORD], T.DWORD), "TerminateJobObject": ([T.HANDLE, T.UINT], T.BOOL),
        "TerminateProcess": ([T.HANDLE, T.UINT], T.BOOL), "GetExitCodeProcess": ([T.HANDLE, ctypes.POINTER(T.DWORD)], T.BOOL), "CloseHandle": ([T.HANDLE], T.BOOL),
        "GetActiveProcessorCount": ([T.WORD], T.DWORD), "GetActiveProcessorGroupCount": ([], T.WORD), "GetCurrentProcess": ([], T.HANDLE),
        "GetProcessTimes": ([T.HANDLE, ctypes.POINTER(T.FILETIME), ctypes.POINTER(T.FILETIME), ctypes.POINTER(T.FILETIME), ctypes.POINTER(T.FILETIME)], T.BOOL)}
    for name, (args, result) in signatures.items():
        getattr(K, name).argtypes, getattr(K, name).restype = args, result
    def ok(value, name):
        need(bool(value), "WINDOWS_API", name + " code=" + str(ctypes.get_last_error()))
    def birth(handle):
        times = [T.FILETIME() for _ in range(4)]
        ok(K.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)), "GetProcessTimes original")
        return str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
    def active(job):
        buffer = ctypes.create_string_buffer(8 + 128 * ctypes.sizeof(SIZE))
        ok(K.QueryInformationJobObject(job, 3, buffer, len(buffer), None), "Original Job PID list")
        return int(ctypes.cast(buffer, ctypes.POINTER(T.DWORD))[0])
    return K, T, EXT, CPU, START, PROC, ok, birth, active


def windows_parent(ctx, argv):
    K, T, EXT, CPU, START, PROC, ok, birth, active = windows_api()
    need(K.GetActiveProcessorGroupCount() == 1, "CPU_GROUP_AMBIGUOUS")
    cpus = int(K.GetActiveProcessorCount(0)); need(cpus > 0, "ACTUAL_CPU_COUNT")
    rate = min(10000, 20000 // cpus)
    job, child, assigned, forced = K.CreateJobObjectW(None, None), PROC(), False, False
    ok(job, "Create original Job")
    error = None; active_before = None; cleanup_before = None; terminal = False; exit_code = None
    try:
        limits = EXT(); limits.Basic.LimitFlags = 0x2000 | 0x200 | 0x8
        limits.Basic.ActiveProcessLimit = 128; limits.JobMemoryLimit = 2147483648
        cpu = CPU(5, rate)
        ok(K.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)), "Set Job limits")
        ok(K.SetInformationJobObject(job, 15, ctypes.byref(cpu), ctypes.sizeof(cpu)), "Set CPU hardcap")
        observed, observed_cpu = EXT(), CPU()
        ok(K.QueryInformationJobObject(job, 9, ctypes.byref(observed), ctypes.sizeof(observed), None), "Query limits")
        ok(K.QueryInformationJobObject(job, 15, ctypes.byref(observed_cpu), ctypes.sizeof(observed_cpu), None), "Query CPU")
        need(observed.JobMemoryLimit == 2147483648 and observed.Basic.ActiveProcessLimit == 128
             and observed.Basic.LimitFlags & (0x2000 | 0x200 | 0x8) == (0x2000 | 0x200 | 0x8)
             and observed_cpu.Flags == 5 and observed_cpu.Rate == rate, "ACTUAL_JOB_CAPS")
        startup = START(); startup.cb = ctypes.sizeof(startup)
        ok(K.CreateProcessW(None, ctypes.create_unicode_buffer(subprocess.list2cmdline(argv)), None, None, False, 0x4,
                            None, ctx["workspace"], ctypes.byref(startup), ctypes.byref(child)), "Create suspended original child")
        created = birth(child.hProcess)
        ok(K.AssignProcessToJobObject(job, child.hProcess), "Assign original suspended child"); assigned = True
        member = T.BOOL(); ok(K.IsProcessInJob(child.hProcess, job, ctypes.byref(member)), "Actual Job membership")
        need(member.value and active(job) == 1, "OWNED_HELD_JOB_MEMBERSHIP")
        proof = {"pid": child.pid, "start": created, "FILETIME": created, "actualCPUCount": cpus, "cpuRate": rate,
                 "memory": observed.JobMemoryLimit, "activeLimit": 128, "actualOriginalJobMember": True,
                 "createdSuspended": True, "swapZeroClaim": False}
        save(Path(ctx["runRoot"]) / "caps.json", proof)
        need(K.ResumeThread(child.hThread) != 0xffffffff, "RESUME_ORIGINAL_THREAD")
        until = time.monotonic() + min(15, remaining(ctx))
        while not (Path(ctx["runRoot"]) / "held-ready.json").exists():
            budget(ctx); need(K.WaitForSingleObject(child.hProcess, 0) == 258 and time.monotonic() < until, "HELD_CHILD_NOT_READY")
            time.sleep(0.05)
        need(birth(child.hProcess) == created and K.WaitForSingleObject(child.hProcess, 0) == 258, "ORIGINAL_FILETIME_CHANGED")
        release_child(ctx, proof)
        while K.WaitForSingleObject(child.hProcess, 250) == 258:
            budget(ctx)
        code = T.DWORD(); ok(K.GetExitCodeProcess(child.hProcess, ctypes.byref(code)), "Original exit status"); exit_code = code.value
        # The pre-cleanup reading is decisive. Killing descendants can NEVER turn this into PASS.
        active_before = active(job)
        need(active_before == 0, "DESCENDANTS_REMAINING_BEFORE_CLEANUP", str(active_before))
        terminal = True
        need(exit_code == 0, "CHILD_FAILED", str(exit_code))
    except Exception as failure:
        error = {"cause": getattr(failure, "cause", "STARTER_EXCEPTION"), "detail": str(failure)[:2048]}
    finally:
        if assigned and not terminal:
            before_cleanup = active(job); cleanup_before = before_cleanup
            if before_cleanup:
                forced = True; ok(K.TerminateJobObject(job, 1), "Terminate only owned Job")
            until = time.monotonic() + 10
            while active(job) and time.monotonic() < until:
                time.sleep(0.05)
            terminal = active(job) == 0
        elif child.hProcess and not assigned:
            forced = True; K.TerminateProcess(child.hProcess, 1)
            terminal = K.WaitForSingleObject(child.hProcess, 10000) == 0
        elif not child.hProcess:
            terminal = True
        if forced and error is None:
            error = {"cause": "FORCED_CLEANUP", "detail": "Never a passing terminal path"}
        result = {"status": "PASS" if error is None and terminal and not forced and active_before == 0 else "FAIL_INCOMPLETE",
                  "error": error, "forcedCleanup": forced, "activeBeforeAnyTermination": active_before,
                  "activeImmediatelyBeforeCleanup": cleanup_before, "allOwnedTerminal": terminal, "exitCode": exit_code, "originalPID": child.pid,
                  "originalFILETIME": birth(child.hProcess) if child.hProcess else None}
        save(Path(ctx["runRoot"]) / "parent-terminal.json", result)
        if terminal:
            for handle in (child.hThread, child.hProcess, job):
                if handle:
                    K.CloseHandle(handle)
        else:
            KEEP_ORIGINAL_HANDLES.append((K, child.hThread, child.hProcess, job))
        return result


def linux_parent(ctx, argv):
    uid, gid = os.getuid(), os.getgid(); need(uid != 0 and gid != 0, "NONROOT_RUNNER_REQUIRED")
    unit = ctx["unit"]
    command_line = ["sudo", "-n", "systemd-run", "--wait", "--pipe", "--collect", "--unit=" + unit,
                    "--uid=" + str(uid), "--gid=" + str(gid), "--property=Type=exec", "--working-directory=" + ctx["workspace"],
                    "--property=CPUQuota=200%", "--property=CPUQuotaPeriodSec=100ms", "--property=MemoryMax=2147483648",
                    "--property=MemorySwapMax=0", "--property=TasksMax=128", "--property=RuntimeMaxSec=" + str(max(1, math.floor(remaining(ctx)))),
                    "--property=KillMode=control-group", "--property=TimeoutStopSec=10s"]
    for key in ("GITHUB_ACTIONS", "GITHUB_WORKSPACE", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_REF",
                "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_TEMP", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "ImageOS", "ImageVersion", "PATH"):
        value = os.environ.get(key); need(value is not None and "\x00" not in value, "HOSTED_ENV", key)
        command_line.append("--setenv=" + key + "=" + value)
    command_line.extend(argv)
    child = None; identity = None; error = None; forced = False; terminal = False; exit_code = None
    log = (Path(ctx["runRoot"]) / "unit-owner.log").open("xb")
    try:
        child = subprocess.Popen(command_line, stdout=log, stderr=subprocess.STDOUT)
        until = time.monotonic() + min(15, remaining(ctx))
        ready_file = Path(ctx["runRoot"]) / "held-ready.json"
        while not ready_file.exists():
            budget(ctx); need(child.poll() is None and time.monotonic() < until, "HELD_CHILD_NOT_READY")
            time.sleep(0.05)
        ready = load(ready_file)
        identity = linux_identity(int(ready["pid"]), unit, uid, gid)
        need(ready["start"] == identity["start"], "HELD_PROC_START_MISMATCH")
        save(Path(ctx["runRoot"]) / "caps.json", identity)
        release_child(ctx, identity)
        while child.poll() is None:
            budget(ctx); time.sleep(0.2)
        exit_code = child.returncode
        group = Path(identity["cgroup"])
        terminal = not group.exists() or "populated 0" in (group / "cgroup.events").read_text()
        result = load(Path(ctx["runRoot"]) / "child-result.json")
        need(result["status"] == "PASS", "CHILD_FAILED", json.dumps(result.get("error"), sort_keys=True))
        need(result["naturalMembersBeforeExit"] == [identity["pid"]], "CHILD_PREEXIT_MEMBERSHIP")
        need(exit_code == 0 and terminal, "OWN_UNIT_NOT_NATURALLY_TERMINAL")
    except Exception as failure:
        error = {"cause": getattr(failure, "cause", "STARTER_EXCEPTION"), "detail": str(failure)[:2048]}
    finally:
        if child is not None and child.poll() is None:
            if identity is not None:
                proc = Path("/proc") / str(identity["pid"])
                if proc.exists() and linux_start(identity["pid"]) == identity["start"]:
                    current = linux_identity(identity["pid"], unit, uid, gid)
                    if current["start"] == identity["start"]:
                        forced = True; os.kill(identity["pid"], signal.SIGTERM)
            try:
                child.wait(timeout=min(15, max(1, ctx["deadlineMono"] - time.monotonic() + 10)))
            except subprocess.TimeoutExpired:
                error = {"cause": "OWN_UNIT_TERMINAL_UNKNOWN", "detail": "Original process/unit/start not released; no foreign PID or sudo repair"}
        if identity is not None:
            group = Path(identity["cgroup"])
            terminal = not group.exists() or "populated 0" in (group / "cgroup.events").read_text()
        elif child is None:
            terminal = True
        log.flush(); os.fsync(log.fileno()); log.close()
        result = {"status": "PASS" if error is None and terminal and not forced else "FAIL_INCOMPLETE", "error": error,
                  "forcedCleanup": forced, "allOwnedTerminal": terminal, "unit": unit, "heldIdentity": identity,
                  "exitCode": exit_code, "supervisorPID": child.pid if child else None}
        save(Path(ctx["runRoot"]) / "parent-terminal.json", result)
        return result


def bounded_get(ctx, url, destination, limit, total, expected_size=None, expected_sha512=None):
    need(url.startswith("https://api.nuget.org/v3-flatcontainer/") or url.startswith("https://api.nuget.org/v3/"), "UNEXPECTED_NUGET_ORIGIN")
    cap = min(60, ctx.get("nugetAcquisitionDeadlineMono", time.monotonic() + 60) - time.monotonic())
    need(cap > 0, "NUGET_ACQUISITION_DEADLINE")
    stage(ctx, "nuget-input-transport", cap)
    h256, h512, count = hashlib.sha256(), hashlib.sha512(), 0
    class DenyRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, response, code, message, headers, new_url):
            raise Failure("NUGET_REDIRECT_DENIED")
    opener = urllib.request.build_opener(DenyRedirect())
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity", "User-Agent": "Matching10-BoundedInput/1"})
    with opener.open(request, timeout=min(30, cap, remaining(ctx))) as response, Path(destination).open("xb") as out:
        need(response.status == 200 and response.geturl() == url, "NUGET_REDIRECT_OR_STATUS")
        for chunk in iter(lambda: response.read(65536), b""):
            count += len(chunk); total[0] += len(chunk)
            need(count <= limit and total[0] <= 536870912, "INPUT_TRANSPORT_BYTES")
            budget(ctx); out.write(chunk); h256.update(chunk); h512.update(chunk)
        out.flush(); os.fsync(out.fileno())
    need(expected_size is None or count == expected_size, "NUGET_RAW_SIZE")
    need(expected_sha512 is None or h512.hexdigest() == expected_sha512, "NUGET_RAW_SHA512")
    return {"url": url, "bytes": count, "sha256": h256.hexdigest(), "sha512": h512.hexdigest()}


def safe_package(raw, spec, notice_root):
    # Read signed bytes only after their expected raw hash matched. No arbitrary extraction.
    notices = []
    with zipfile.ZipFile(raw) as archive:
        infos = archive.infolist()
        need(1 <= len(infos) <= 4096 and sum(x.file_size for x in infos) <= 268435456, "NUGET_MEMBER_BUDGET")
        names = set()
        for item in infos:
            path = PurePosixPath(item.filename)
            mode = item.external_attr >> 16
            need(not path.is_absolute() and ".." not in path.parts and "\\" not in item.filename
                 and ":" not in item.filename and "\x00" not in item.filename, "NUGET_MEMBER_PATH")
            key = item.filename.casefold()
            need(key not in names and not item.flag_bits & 1 and item.file_size <= 134217728, "NUGET_MEMBER_DUPLICATE_OR_SIZE")
            need(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR) and not mode & 0o6000, "NUGET_MEMBER_TYPE")
            names.add(key)
        nuspecs = [x for x in infos if x.filename.lower().endswith(".nuspec")]
        need(len(nuspecs) == 1 and nuspecs[0].file_size <= 1048576 and ".signature.p7s" in names, "SIGNED_NUSPEC_MEMBERSHIP")
        signature_member = next((x for x in infos if x.filename == ".signature.p7s"), None)
        need(signature_member is not None and signature_member.file_size <= 131072, "SIGNATURE_MEMBER_IDENTITY_OR_CAP")
        signature_hash = hashlib.sha256(archive.read(signature_member)).hexdigest()
        if not spec["implicit"]:
            need(signature_hash == spec["signatureFileSHA256"], "TEST_SIGNER_SIGNATURE_FILE_IDENTITY", spec["id"])
        xml = archive.read(nuspecs[0])
        need(b"<!DOCTYPE" not in xml.upper() and b"<!ENTITY" not in xml.upper(), "NUSPEC_DTD")
        root = ET.fromstring(xml)
        metadata = next(x for x in root if x.tag.split("}")[-1] == "metadata")
        fields = {x.tag.split("}")[-1]: x for x in metadata}
        need(fields["id"].text.lower() == spec["id"].lower() and fields["version"].text == spec["version"], "SIGNED_NUSPEC_ID_VERSION")
        license_element = fields.get("license")
        need(license_element is not None and license_element.text, "SIGNED_LICENSE_MISSING")
        license_kind = license_element.attrib.get("type")
        need(license_kind in ("expression", "file"), "SIGNED_LICENSE_KIND")
        required_license = license_element.text if license_kind == "file" else None
        for item in infos:
            base = PurePosixPath(item.filename).name.upper()
            if not item.is_dir() and (base.startswith(("LICENSE", "THIRD-PARTY-NOTICE", "NOTICE", "COPYRIGHT")) or item.filename == required_license):
                need(item.file_size <= 2097152, "NOTICE_BYTES")
                data = archive.read(item)
                name = str(len(notices)) + ".original"
                (notice_root / name).write_bytes(data)
                notices.append({"member": item.filename, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "retained": name})
        need(required_license is None or any(x["member"] == required_license for x in notices), "LICENSE_FILE_MEMBER_MISSING")
        if spec["implicit"]:
            need(notices and any(PurePosixPath(x["member"]).name.upper().startswith("LICENSE") for x in notices), "IMPLICIT_FULL_LICENSE_MISSING")
        # Build-only packages may carry a signed SPDX expression without a full-text member.
        return {"id": spec["id"], "version": spec["version"], "signatureFileSHA256": signature_hash, "memberCount": len(infos),
                "expandedBytes": sum(x.file_size for x in infos), "nuspecSHA256": hashlib.sha256(xml).hexdigest(),
                "license": {"kind": license_kind, "value": license_element.text},
                "copyright": fields["copyright"].text if "copyright" in fields else None,
                "notices": notices, "fullTextAbsentForBuildOnlyExpression": not notices and not spec["implicit"]}


def stable_compare(version, bound):
    # All admitted package versions are stable; prerelease bounds are below equal-core stable.
    m = re.fullmatch(r"(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?", bound)
    need(m is not None, "UNSUPPORTED_ADVISORY_VERSION", bound)
    left = tuple(int(x) for x in version.split(".")); left += (0,) * (4 - len(left))
    right = tuple(int(x) for x in m[1].split(".")); right += (0,) * (4 - len(right))
    if left != right:
        return 1 if left > right else -1
    return 1 if m[2] else 0


def in_range(version, text):
    need(isinstance(text, str) and text, "ADVISORY_RANGE")
    if text[0] not in "[(":
        return stable_compare(version, text) >= 0
    need(text[-1] in ")]", "ADVISORY_RANGE")
    inside = text[1:-1]
    if "," not in inside:
        need(text[0] == "[" and text[-1] == "]", "ADVISORY_EXACT_RANGE")
        return stable_compare(version, inside.strip()) == 0
    low, high = [x.strip() for x in inside.split(",")]
    return ((not low or stable_compare(version, low) > 0 or (text[0] == "[" and stable_compare(version, low) == 0))
            and (not high or stable_compare(version, high) < 0 or (text[-1] == "]" and stable_compare(version, high) == 0)))


def advisory_guard(ctx, specs, total):
    root = Path(ctx["runRoot"]) / "advisory"; root.mkdir()
    index_file = root / "service.json"
    records = [bounded_get(ctx, "https://api.nuget.org/v3/index.json", index_file, 2097152, total)]
    resources = [x["@id"] for x in load(index_file)["resources"] if str(x["@type"]).startswith("VulnerabilityInfo/")]
    need(len(set(resources)) == 1, "VULNERABILITY_SOURCE_MISSING_OR_AMBIGUOUS")
    index = root / "index.json"; records.append(bounded_get(ctx, resources[0], index, 2097152, total))
    pages = load(index); need(isinstance(pages, list) and 1 <= len(pages) <= 8, "VULNERABILITY_PAGE_PARTITION")
    selected = {x["id"].lower(): x["version"] for x in specs}; advisory_bytes = 0
    for number, page in enumerate(pages):
        url = page["@id"]
        need(url.startswith("https://api.nuget.org/v3/vulnerabilities/"), "ADVISORY_ORIGIN")
        path = root / (str(number) + ".json")
        record = bounded_get(ctx, url, path, 33554432 - advisory_bytes, total)
        advisory_bytes += record["bytes"]; need(advisory_bytes <= 33554432, "ADVISORY_BYTE_CAP")
        record["updated"] = page.get("@updated"); records.append(record)
        data = load(path, 33554432)
        for identity, version in selected.items():
            for issue in data.get(identity, []):
                need(not in_range(version, issue["versions"]), "CURRENT_ADVISORY_MATCH", identity + " " + issue["versions"] + " " + issue.get("url", ""))
    proof = {"status": "NO_SELECTED_NUGET_ADVISORY_MATCH", "selected": selected, "sources": records,
             "scope": "Current official NuGet feed for exact selected packages; not OS/compiler/general security certification"}
    save(Path(ctx["runRoot"]) / "selected-advisory.json", proof)
    return proof


def test_repository_pin(identity, version, raw_sha512, normalized, signature_file_sha256):
    spec = TEST_PACKAGES.get(identity.lower())
    need(spec is not None and spec["version"] == version, "TEST_SIGNER_PACKAGE_IDENTITY", identity)
    need(raw_sha512 == spec["rawSHA512"], "TEST_SIGNER_RAW_IDENTITY", identity)
    need(normalized == spec["normalized"], "TEST_SIGNER_NORMALIZED_IDENTITY", identity)
    need(signature_file_sha256 == spec["signatureFileSHA256"], "TEST_SIGNER_SIGNATURE_FILE_IDENTITY", identity)
    pin = spec["repositoryCertificate"]
    need(pin is not None and re.fullmatch(r"[0-9A-F]{64}", pin)
         and spec["repositoryProvenance"]["state"] == "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
         "TEST_SIGNER_PROVENANCE_UNKNOWN", identity)
    return pin


def signature_observations(text, selected, exit_code):
    # Pure bounded parser: emit only expected package identities, enums and validated hashes.
    need(len(selected) <= 24 and len(text) <= 524288, "SIGNATURE_DIAGNOSTIC_INPUT_CAP")
    markers = list(re.finditer(r"(?mi)^Verifying\s+([^\r\n]+)\s*$", text))
    expected = {spec["id"].lower() + "." + spec["version"]: spec for spec in selected}
    partition = {}
    unmatched = 0
    for index, marker in enumerate(markers):
        label = marker[1].strip().lower()
        if label not in expected:
            unmatched += 1; continue
        body = text[marker.end():markers[index + 1].start() if index + 1 < len(markers) else len(text)]
        partition.setdefault(label, []).append(body)
    rows = []
    for label, spec in expected.items():
        bodies = partition.get(label, [])
        sections = re.findall(r"Signature type:\s*(Author|Repository)(.*?)(?=Signature type:|\Z)", bodies[0], re.S | re.I) if len(bodies) == 1 else []
        kinds = [kind.lower() for kind, _ in sections]
        fingerprints = {"author": [], "repository": []}
        for kind, section in sections:
            for match in re.finditer(r"(?mi)^\s*SHA256 hash:\s*([0-9A-Fa-f: ]+)\s*$", section):
                value = re.sub(r"[:\s]", "", match[1]).upper()
                if re.fullmatch(r"[0-9A-F]{64}", value) and value not in fingerprints[kind.lower()]:
                    fingerprints[kind.lower()].append(value)
        fingerprints = {kind: values[:8] for kind, values in fingerprints.items()}
        hashes = re.findall(r"(?mi)^Content hash:\s*([A-Za-z0-9+/=]+)\s*$", bodies[0]) if len(bodies) == 1 else []
        normalized = hashes[0] if len(hashes) == 1 and len(hashes[0]) == 88 else None
        if normalized is not None:
            try:
                if len(base64.b64decode(normalized, validate=True)) != 64:
                    normalized = None
            except ValueError:
                normalized = None
        expected_repository = REPO_CERT if spec["implicit"] else spec.get("repositoryCertificate")
        if expected_repository is None:
            category = "PACKAGE_SIGNER_PROVENANCE_UNKNOWN"
        elif len(bodies) != 1 or unmatched or kinds.count("repository") > 1 or not kinds:
            category = "PARSER_PARTITION_UNKNOWN"
        elif "repository" not in kinds:
            category = "ABSENT_REPOSITORY_SECTION"
        elif not fingerprints["repository"]:
            category = "PARSER_FINGERPRINT_FIELD_UNKNOWN"
        elif expected_repository not in fingerprints["repository"]:
            category = "OBSERVED_REPOSITORY_CERT_MISMATCH"
        else:
            category = "OBSERVED_REPOSITORY_PIN_MATCH"
        rows.append({"id": spec["id"], "version": spec["version"], "implicit": spec["implicit"],
            "rawSHA512Expected": spec["rawSHA512"], "normalizedContentHashExpected": spec["normalized"],
            "expectedRepositoryCertificate": expected_repository, "signatureFileSHA256Expected": spec.get("signatureFileSHA256"),
            "normalizedContentHashObserved": normalized, "packageBlockCount": len(bodies),
            "signatureKinds": kinds[:8], "observedFingerprintHexBySection": fingerprints,
            "repositoryObservation": category, "verifyExitCode": exit_code})
    return {"packages": rows, "observedBlockCount": len(markers), "unmatchedBlockCount": unmatched,
            "verifyOutcome": "VERIFY_EXIT_UNKNOWN" if exit_code is None else "VERIFY_EXIT_ZERO" if exit_code == 0 else "VERIFY_EXIT_FAILURE"}


def signature_diagnostic(ctx, selected, inspected, command_failure=None):
    # Read only this command's bounded owned log; never export raw stdout/stderr, paths, queries or env.
    log = Path(ctx["runRoot"]) / "nuget-signatures.log"
    data = b""; complete = False
    if log.is_file() and not log.is_symlink():
        before = log.stat()
        with log.open("rb") as stream:
            data = stream.read(524289)
        after = log.stat()
        complete = len(data) <= 524288 and len(data) == before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns
    exit_code = ctx.get("signatureVerifyExitCode")
    observation = signature_observations(data[:524288].decode("utf-8", errors="replace"), selected, exit_code)
    for row in observation["packages"]:
        raw = inspected[row["id"].lower()]["raw"]
        row["rawObservedBytes"] = raw["bytes"]
        row["rawSHA256Observed"] = raw["sha256"]
        row["rawSHA512Observed"] = raw["sha512"]
        row["signatureFileSHA256Observed"] = inspected[row["id"].lower()].get("signatureFileSHA256")
    report = {"schema": "matching10/nuget-signature-diagnostic/v2", "status": "OBSERVABILITY_ONLY_NOT_ADMISSION",
        "source": ctx["binding"]["source"], "rid": ctx["rid"],
        "controllerSHA256": ctx["binding"]["controllerSHA256"], "payloadSHA256": ctx["binding"]["payloadSHA256"],
        "inputCompleteWithinCap": complete, "inputBytesRead": len(data),
        "inputSHA256": hashlib.sha256(data).hexdigest() if complete else None,
        "commandReturnedSuccessfully": command_failure is None,
        "SDKLaunchAttempts": ctx["SDKLaunchAttempts"], "SDKProcessesStartedByController": ctx["SDKProcessesStarted"],
        "implicitRepositoryCertificate": REPO_CERT, "expectedImplicitAuthorCertificate": MS_CERT,
        **observation, "historicalFailureCause": "UNKNOWN: prior actual verify output was not retained",
        "policy": "Exact per-test-package pins bind id/version/raw/normalized/CMS identity; implicit pins unchanged. Structured public package/hash/kind/exit observations only; no raw stdout/stderr, path, query, environment or inferred admission"}
    need(len(json.dumps(report).encode("utf-8")) <= 131072, "SIGNATURE_DIAGNOSTIC_JSON_CAP")
    save(Path(ctx["runRoot"]) / "nuget-signature-diagnostic.json", report)
    return report


def input_policy(ctx, sdk, sdk_receipt):
    workspace = Path(ctx["workspace"]); root = Path(ctx["runRoot"])
    offline = root / "offline"; offline.mkdir(); packages = root / "packages"; packages.mkdir()
    notices = root / "notices"; notices.mkdir()
    config = root / "NuGet.Config"
    config.write_text('<configuration><packageSources><clear/><add key="own-offline" value="' + str(offline).replace('&', '&amp;')
                      + '"/></packageSources><fallbackPackageFolders><clear/></fallbackPackageFolders><auditSources><clear/>'
                      + '<add key="official-audit" value="https://api.nuget.org/v3/index.json"/></auditSources>'
                      + '<config><add key="signatureValidationMode" value="require"/></config></configuration>', encoding="utf-8")
    env = ctx["environment"]
    env.update({"NUGET_PACKAGES": str(packages), "NUGET_HTTP_CACHE_PATH": str(root / "http"),
                "NUGET_PLUGINS_CACHE_PATH": str(root / "plugins"), "DOTNET_CLI_HOME": str(root / "home"),
                "DOTNET_ROOT": str(sdk.parent), "DOTNET_ROOT_X64": str(sdk.parent),
                "NUGET_CERT_REVOCATION_MODE": "online", "RestoreConfigFile": str(config),
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1", "DOTNET_GENERATE_ASPNET_CERTIFICATE": "false",
                "DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE": "true", "DOTNET_CLI_USE_MSBUILD_SERVER": "0",
                "MSBuildEnableWorkloadResolver": "false", "MSBUILDDISABLENODEREUSE": "1", "DOTNET_CLI_UI_LANGUAGE": "en-US", "UseSharedCompilation": "false", "BuildInParallel": "false", "PYTHONDONTWRITEBYTECODE": "1"})
    graph_path = root / "restore-graph.json"
    command(ctx, [sdk, "msbuild", "PriceTimeMatching.slnx", "-t:GenerateRestoreGraphFile",
                  "-p:RestoreGraphOutputPath=" + str(graph_path), "-p:RestoreConfigFile=" + str(config),
                  "-p:RestoreSources=" + str(offline), "-m:1", "-nodeReuse:false"], "actual-restore-graph", 180, True)
    graph = load(graph_path)
    need(isinstance(graph.get("projects"), dict) and 1 <= len(graph["projects"]) <= 3, "ACTUAL_GRAPH_PROJECT_PARTITION")
    requested = set(); direct = set()
    for path, project in graph["projects"].items():
        need(Path(path).resolve().is_relative_to(workspace), "GRAPH_FOREIGN_PROJECT")
        for framework in project.get("frameworks", {}).values():
            for name in framework.get("dependencies", {}):
                direct.add(name.lower())
            for dep in framework.get("downloadDependencies", []):
                identity = dep["name"].lower(); version = dep["version"].replace(" ", "")
                need(identity in IMPLICIT and version in ("10.0.15", "[10.0.15,10.0.15]"), "UNEXPECTED_IMPLICIT_PACKAGE", identity + "/" + version)
                requested.add(identity)
    need(direct <= set(TEST_PACKAGES), "UNEXPECTED_DIRECT_PACKAGE", repr(direct))
    selected = list(TEST_PACKAGES.values()) + [IMPLICIT[x] for x in sorted(requested)]
    need(len(selected) <= 24, "FIXED_PACKAGE_CLOSURE_CAP")
    total = [int(sdk_receipt["rawArchiveBytes"])]
    inspected = {}; raws = {}
    ctx["nugetAcquisitionDeadlineMono"] = time.monotonic() + 120
    for spec in selected:
        identity = spec["id"].lower(); version = spec["version"]
        raw = offline / (identity + "." + version + ".nupkg")
        url = "https://api.nuget.org/v3-flatcontainer/" + identity + "/" + version + "/" + raw.name
        observed = bounded_get(ctx, url, raw, 67108864, total, spec.get("bytes"), spec["rawSHA512"])
        if spec.get("rawSHA256"):
            need(observed["sha256"] == spec["rawSHA256"], "NUGET_RAW_SHA256")
        directory = notices / identity; directory.mkdir()
        inspected[identity] = safe_package(raw, spec, directory)
        inspected[identity]["raw"] = observed; raws[identity] = raw
    ctx.pop("nugetAcquisitionDeadlineMono")
    try:
        verify = command(ctx, [sdk, "nuget", "verify", "--all", *raws.values()], "nuget-signatures", 180, True)
    except Exception as failure:
        signature_diagnostic(ctx, selected, inspected, failure)
        raise
    signature_report = signature_diagnostic(ctx, selected, inspected)
    need(signature_report["inputCompleteWithinCap"], "SIGNATURE_DIAGNOSTIC_INPUT_CAP")
    blocks = list(re.finditer(r"(?mi)^Verifying\s+([^\r\n]+)\s*$", verify))
    need(len(blocks) == len(selected), "SIGNATURE_RESULT_PARTITION")
    normalized = {}
    specs_by_id = {s["id"].lower(): s for s in selected}
    for index, marker in enumerate(blocks):
        text = verify[marker.end():blocks[index + 1].start() if index + 1 < len(blocks) else len(verify)]
        label = marker[1].strip().lower()
        matches = [key for key, spec in specs_by_id.items() if label == key + "." + spec["version"]]
        need(len(matches) == 1 and matches[0] not in normalized, "SIGNATURE_PACKAGE_IDENTITY")
        identity = matches[0]; spec = specs_by_id[identity]
        hashes = re.findall(r"(?mi)^Content hash:\s*([A-Za-z0-9+/=]+)\s*$", text)
        need(len(hashes) == 1, "NORMALIZED_CONTENT_HASH_MISSING")
        if spec["normalized"] is not None:
            need(hashes[0] == spec["normalized"], "NORMALIZED_HASH_MISMATCH", identity)
        signatures = {kind.lower(): section for kind, section in re.findall(
            r"Signature type:\s*(Author|Repository)(.*?)(?=Signature type:|\Z)", text, re.S | re.I)}
        expected_repository = REPO_CERT if spec["implicit"] else test_repository_pin(
            identity, spec["version"], inspected[identity]["raw"]["sha512"], hashes[0], inspected[identity]["signatureFileSHA256"])
        need("repository" in signatures, "NUGET_REPOSITORY_SIGNATURE_ABSENT", identity)
        need(expected_repository in re.sub(r"\s", "", signatures["repository"]).upper(), "NUGET_REPOSITORY_CERT_MISMATCH", identity)
        if spec["implicit"]:
            need("author" in signatures and MS_CERT in re.sub(r"\s", "", signatures["author"]).upper(), "MICROSOFT_IMPLICIT_SIGNER", identity)
        normalized[identity] = hashes[0]
        inspected[identity]["normalizedContentHash"] = hashes[0]
        inspected[identity]["signaturePolicy"] = {"exitCode": 0, "repositoryCertificate": expected_repository,
                                                   "authorCertificate": MS_CERT if spec["implicit"] else "Exact raw/lock plus NuGetrepository signature policy"}
    advisory_guard(ctx, selected, total)
    command(ctx, [sdk, "restore", "PriceTimeMatching.slnx", "--locked-mode", "--configfile", config,
                  "--packages", packages, "--no-cache", "-m:1", "-p:RestoreFallbackFolders="], "locked-offline-restore", 180, True)
    seen = set()
    for path in packages.iterdir():
        if not path.is_dir():
            continue
        for version_path in path.iterdir():
            need(version_path.is_dir(), "NUGET_CACHE_NODE")
            identity = path.name.lower(); key = identity + "/" + version_path.name
            spec = specs_by_id.get(identity)
            need(spec is not None and version_path.name == spec["version"], "UNEXPECTED_RESTORED_PACKAGE", key)
            meta = load(version_path / ".nupkg.metadata")
            need(meta["contentHash"] == normalized[identity], "RESTORED_NORMALIZED_MISMATCH", key)
            need(sha(version_path / (identity + "." + spec["version"] + ".nupkg"), "sha512") == spec["rawSHA512"], "RESTORED_RAW_MISMATCH", key)
            seen.add(identity)
    need(seen == set(specs_by_id), "LOCKED_CACHE_MEMBERSHIP")
    for project in ("src/Matching", "src/Matching.Cli", "tests/Matching.Tests"):
        assets = load(workspace / project / "obj/project.assets.json", 16777216)
        folders = [Path(x).resolve() for x in assets["packageFolders"]]
        need(folders == [packages.resolve()], "UNEXPECTED_PACKAGE_FOLDER_FALLBACK")
        package_sources = list(assets["project"]["restore"]["sources"])
        need(len(package_sources) == 1 and Path(package_sources[0]).resolve() == offline.resolve(), "PACKAGE_FEED_FALLBACK")
        for key, library in assets["libraries"].items():
            if library["type"] == "package":
                identity, version = key.rsplit("/", 1); identity = identity.lower()
                need(identity in specs_by_id and version == specs_by_id[identity]["version"]
                     and library["sha512"] == normalized[identity], "ASSET_PACKAGE_IDENTITY", key)
    # Original advisory code is run once here, BEFORE any build/package, not silently dropped.
    artifacts = workspace / "artifacts"; artifacts.mkdir(exist_ok=False)
    command(ctx, [sys.executable, workspace / "tools/audit_dependencies.py", "--dotnet", sdk,
                  "--out", artifacts / "dependency-advisories.json"], "original-advisory-check", 180)
    need(load(artifacts / "dependency-advisories.json")["status"] == "NO_KNOWN_ADVISORIES_REPORTED", "ORIGINAL_ADVISORY_FAILED")
    need(sha(workspace / "tests/Matching.Tests/packages.lock.json") == LOCK_SHA, "RESTORE_CHANGED_LOCK")
    result = {"status": "EXACT_PACKAGE_INPUTS_ADMITTED", "graphSHA256": sha(graph_path), "selected": sorted(specs_by_id),
              "requestedImplicit": sorted(requested), "normalized": normalized, "packages": inspected,
              "source": ctx["binding"]["source"], "SDKProcessesStartedByController": ctx["SDKProcessesStarted"],
              "scope": "Actual raw/signature/normalized/member/notices/advisory/offline restore guards, not general security certification"}
    save(Path(ctx["runRoot"]) / "package-admission.json", result)
    return result


def child_context(path, expected):
    need(expected and sha(path) == expected, "CONTEXT_SOURCE_HASH")
    ctx = load(path)
    need(Path(path).resolve().parent == Path(ctx["runRoot"]).resolve()
         and Path(ctx["runRoot"]).resolve().parent == Path(os.environ["RUNNER_TEMP"]).resolve(), "OWN_CONTEXT_PATH")
    need(sha(__file__) == ctx["binding"]["controllerSHA256"], "CONTEXT_CONTROLLER_SOURCE")
    need(sha(Path(ctx["workspace"]) / ".github/ci/matching10-native.ps1") == ctx["binding"]["payloadSHA256"], "CONTEXT_PAYLOAD_SOURCE")
    remaining(ctx)
    return ctx


def consumer_denials(ctx):
    base = [sys.executable, str(Path(__file__).resolve()), "--rid", ctx["rid"], "--preflight-only",
            "--expected-controller-sha256", ctx["binding"]["controllerSHA256"],
            "--expected-payload-sha256", ctx["binding"]["payloadSHA256"]]
    cases = (("controller", "CONTROLLER_SOURCE_IDENTITY"), ("payload", "PAYLOAD_SOURCE_IDENTITY"), ("rid", "NATIVE_ROW_OS_ARCH"))
    results = []
    for name, cause in cases:
        argv = list(base)
        if name == "controller":
            argv[argv.index("--expected-controller-sha256") + 1] = "0" * 64
        elif name == "payload":
            argv[argv.index("--expected-payload-sha256") + 1] = "0" * 64
        else:
            argv[argv.index("--rid") + 1] = "linux-x64" if ctx["rid"] == "win-x64" else "win-x64"
        output = command(ctx, argv, "consumer-denial-" + name, 15, expected=64)
        actual = json.loads(output)
        need(actual["cause"] == cause and actual["SDKProcessesStarted"] == 0 and actual["status"] == "SDK0_DENIED", "ACTUAL_CONSUMER_DENIAL")
        results.append(actual)
    save(Path(ctx["runRoot"]) / "denial-proof.json", {"status": "OWN_CONSUMER_SDK0_DENIALS_OBSERVED", "cases": results,
         "sharedHelperRetested": False, "scope": "Actual separate own entry invocations with changed consumer input, under the same own cap"})


def shared_sdk(ctx):
    workspace = Path(ctx["workspace"])
    for name, digest in SHARED.items():
        need(sha(workspace / "tools" / name) == digest, "SHARED_INTERFACE_PIN", name)
    deadline = min(math.floor(time.time() + remaining(ctx)), math.floor(time.time()) + 300)
    command(ctx, [sys.executable, workspace / "tools/sdk10_hosted_inputs.py", "--project-id", "10",
                  "--rid", ctx["rid"], "--deadline-unix", deadline], "sdk10-materialization", 300)
    receipt_path = Path(ctx["sdkStage"]) / "evidence" / ("sdk-materialization-" + ctx["rid"] + ".json")
    receipt = load(receipt_path)
    need(receipt["status"] == "EXACT_SDK_MATERIALIZED_ALL_FILES_MATCH_SEALED_INVENTORY"
         and receipt["projectId"] == "10" and receipt["rid"] == ctx["rid"] and receipt["executedSdk"] is False
         and receipt["fullDiskMemberSetChecked"] is True and receipt["noLinks"] is True, "SHARED_SDK_RECEIPT")
    need(receipt["sourceSha256"] == SHARED["sdk10_hosted_inputs.py"]
         and receipt["catalogSha256"] == SHARED["sdk10-inputs.lock.json"]
         and receipt["inventorySha256"] == SHARED["sdk10-members.jsonl"], "SHARED_SDK_RECEIPT_SOURCE")
    need(Path(receipt["sdkRoot"]).resolve() == (Path(ctx["sdkStage"]) / "sdk").resolve(), "FRESH_OWN_SDK_ROOT")
    sdk = Path(receipt["sdkRoot"]) / ("dotnet.exe" if ctx["rid"] == "win-x64" else "dotnet")
    need(sha(sdk) == HOST_SHA[ctx["rid"]], "SDK_HOST_BYTES")
    receipt["rawArchiveBytes"] = Path(receipt["rawArchive"]).stat().st_size
    ctx["environment"]["MATCHING10_SDK_GUARD"] = str(receipt_path)
    return sdk, receipt


def worker(path, expected):
    ctx = child_context(path, expected)
    run = Path(ctx["runRoot"])
    ctx["SDKLaunchAttempts"] = 0; ctx["SDKProcessesStarted"] = 0; ctx["payloadReleased"] = False
    pid = os.getpid(); error = None; members = None
    try:
        if ctx["rid"] == "linux-x64":
            identity = linux_identity(pid, ctx["unit"], ctx["uid"], ctx["gid"])
        else:
            K, _, _, _, _, _, _, birth, _ = windows_api()
            identity = {"pid": pid, "start": birth(K.GetCurrentProcess())}
        save(run / "held-ready.json", {**identity, "nonce": ctx["nonce"], "source": ctx["binding"]["source"],
             "controllerSHA256": ctx["binding"]["controllerSHA256"], "SDKProcessesStarted": 0})
        until = time.monotonic() + min(15, remaining(ctx))
        while not (run / "release.json").exists():
            need(time.monotonic() < until, "PARENT_HELD_RELEASE_TIMEOUT")
            time.sleep(0.05)
        need(load(run / "release.json") == {"pid": pid, "start": identity["start"], "nonce": ctx["nonce"]}, "PARENT_RELEASE_IDENTITY")
        if ctx["rid"] == "linux-x64":
            need(linux_identity(pid, ctx["unit"], ctx["uid"], ctx["gid"])["start"] == identity["start"], "ACTUAL_START_OR_CAP_CHANGED")
        temporary = run / "tmp"; temporary.mkdir(exist_ok=False)
        ctx["environment"].update({"TMPDIR": str(temporary), "TEMP": str(temporary), "TMP": str(temporary)})
        consumer_denials(ctx)
        sdk, sdk_receipt = shared_sdk(ctx)
        input_policy(ctx, sdk, sdk_receipt)
        admission = load(run / "package-admission.json")
        need(admission["status"] == "EXACT_PACKAGE_INPUTS_ADMITTED" and admission["source"] == ctx["binding"]["source"], "PACKAGE_ADMISSION_BEFORE_BUILD")
        env = ctx["environment"]
        env.update({"MATCHING10_PACKAGE_ADMISSION": str(run / "package-admission.json"), "MATCHING10_CONTEXT": str(path),
                    "MATCHING10_CONTEXT_SHA256": expected, "PATH": str(sdk.parent) + os.pathsep + env["PATH"],
                    "MATCHING10_RID": ctx["rid"], "TMPDIR": str(run / "tmp"), "TEMP": str(run / "tmp"), "TMP": str(run / "tmp")})
        (run / "tmp").mkdir(exist_ok=True)
        pwsh = shutil.which("pwsh"); need(pwsh, "HOSTED_PWSH_MISSING")
        ctx["payloadReleased"] = True
        command(ctx, [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", Path(ctx["workspace"]) / ".github/ci/matching10-native.ps1"],
                "original-native-payload", min(remaining(ctx), 900))
        if ctx["rid"] == "linux-x64":
            group = Path(identity["cgroup"])
            members = sorted(int(x) for x in (group / "cgroup.procs").read_text().split())
            need(members == [pid], "LINUX_DESCENDANTS_REMAINING_BEFORE_EXIT", repr(members))
        budget(ctx, True)
    except Exception as failure:
        error = {"cause": getattr(failure, "cause", "WORKER_EXCEPTION"), "detail": str(failure)[:2048]}
    result = {"status": "PASS" if error is None else "FAIL_INCOMPLETE", "error": error, "actualPID": pid,
              "actualStart": identity["start"] if "identity" in locals() else None,
              "SDKLaunchAttempts": ctx["SDKLaunchAttempts"], "SDKProcessesStartedByController": ctx["SDKProcessesStarted"],
              "sdk0": ctx["SDKProcessesStarted"] == 0, "payloadReleased": ctx["payloadReleased"],
              "naturalMembersBeforeExit": members, "source": ctx["binding"]["source"]}
    save(run / "child-result.json", result)
    return 0 if error is None else 1


def export_evidence(ctx):
    target = Path(ctx["workspace"]) / "artifacts/hosted-cap-proof"
    target.mkdir(parents=True, exist_ok=True)
    total = 0
    for name in ("nuget-signature-diagnostic.json", "host-observation.json", "caps.json", "held-ready.json", "release.json", "package-admission.json", "selected-advisory.json", "denial-proof.json", "child-result.json", "parent-terminal.json"):
        source = Path(ctx["runRoot"]) / name
        if source.exists():
            total += source.stat().st_size; need(total <= 2097152, "INCREMENTAL_PROOF_CAP")
            with (target / name).open("xb") as out:
                out.write(source.read_bytes())
    source = Path(ctx["sdkStage"]) / "evidence" / ("sdk-materialization-" + ctx["rid"] + ".json")
    if source.exists():
        total += source.stat().st_size; need(total <= 2097152, "INCREMENTAL_PROOF_CAP")
        with (target / source.name).open("xb") as out:
            out.write(source.read_bytes())


def parent(args):
    workspace, payload, binding = source_event(args.expected_controller_sha256, args.expected_payload_sha256, args.rid)
    if args.preflight_only:
        print(json.dumps({"status": "SOURCE_PREFLIGHT_ONLY", "SDKProcessesStarted": 0})); return 0
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    nonce = secrets.token_hex(12); run = temporary / ("matching10-" + nonce); run.mkdir(exist_ok=False)
    now = time.monotonic()
    allowed = ("PATH", "LANG", "LC_ALL", "HOME", "USER", "USERPROFILE", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT",
               "APPDATA", "LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)", "GITHUB_ACTIONS", "GITHUB_WORKSPACE", "GITHUB_REPOSITORY",
               "GITHUB_SHA", "GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
               "RUNNER_TEMP", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "ImageOS", "ImageVersion")
    env = {key: os.environ[key] for key in allowed if key in os.environ}
    ctx = {"rid": args.rid, "nonce": nonce, "workspace": str(workspace), "runRoot": str(run), "binding": binding,
           "sdkStage": str(temporary / ("sdk10-input-10-" + args.rid)), "deadlineMono": now + 1140,
           "unit": "matching10-ci-" + nonce + ".service", "uid": os.getuid() if hasattr(os, "getuid") else None,
           "gid": os.getgid() if hasattr(os, "getgid") else None, "environment": env, "SDKProcessesStarted": 0}
    host_proof = run / "host-observation.json"
    save(host_proof, {"status": "SUPPORTED_HOSTED_NATIVE_OS_OBSERVED", "source": binding["source"],
                      "controllerSHA256": binding["controllerSHA256"], "payloadSHA256": binding["payloadSHA256"],
                      **binding["hostObservation"]})
    ctx["environment"]["MATCHING10_HOST_OBSERVATION"] = str(host_proof)
    path = run / "context.json"; save(path, ctx)
    argv = [sys.executable, str(Path(__file__).resolve()), "--child", str(path), "--context-sha256", sha(path)]
    try:
        result = windows_parent(ctx, argv) if args.rid == "win-x64" else linux_parent(ctx, argv)
    except Exception as failure:
        result = {"status": "FAIL_INCOMPLETE", "error": {"cause": getattr(failure, "cause", "PARENT_TERMINAL_EXCEPTION"),
                  "detail": str(failure)[:2048]}, "allOwnedTerminal": "UNKNOWN", "forcedCleanup": "SEE_ORIGINAL_HANDLE_UNIT_PROOF"}
        if not (run / "parent-terminal.json").exists():
            save(run / "parent-terminal.json", result)
    export_evidence(ctx)
    need(result["status"] == "PASS", "OWN_ROW_FAILED_OR_INCOMPLETE", repr(result["error"]))
    need(load(run / "child-result.json")["status"] == "PASS", "CHILD_RESULT_FAILED")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-controller-sha256")
    parser.add_argument("--expected-payload-sha256")
    parser.add_argument("--rid", choices=("win-x64", "linux-x64"))
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--child", type=Path)
    parser.add_argument("--context", type=Path)
    parser.add_argument("--context-sha256")
    parser.add_argument("--mark-stage", choices=("build", "unit", "model", "modelcheck", "package", "verifier", "packagecheck", "native-demo"))
    args = parser.parse_args()
    try:
        if args.child:
            if os.name != "nt":
                signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(Failure("OWN_WORKER_SIGTERM")))
            return worker(args.child, args.context_sha256)
        if args.mark_stage:
            ctx = child_context(args.context, args.context_sha256)
            stage(ctx, args.mark_stage, 900 if args.mark_stage in ("build", "package") else 180)
            return 0
        need(args.rid and args.expected_controller_sha256 and args.expected_payload_sha256, "FIXED_ENTRY_ARGUMENTS")
        return parent(args)
    except Exception as failure:
        print(json.dumps({"status": "SDK0_DENIED" if args.preflight_only else "FAIL_INCOMPLETE",
                          "cause": getattr(failure, "cause", "ENTRY_EXCEPTION"), "detail": str(failure)[:2048],
                          "SDKProcessesStarted": 0 if args.preflight_only else "SEE_ACTUAL_CHILD_RECEIPT"}))
        return 64 if args.preflight_only else 1

TEST_PACKAGES = json.loads(r'''{
  "xunit.v3": {
    "rawSHA512": "72910d8c1348d6122b4c9ac373818ac7ce7df1aed3d578077fc03dd533844a3ed10929eacaec9c2e10d884a79d08ab9d7ae6074bca5954faea4113662b459803",
    "id": "xunit.v3",
    "bytes": 32099,
    "rawSHA256": "cc54f2fa01f64df2c7e25cc826e81db08f9e1d9ebce2f41fd22adcb11d39eb8e",
    "version": "4.0.3",
    "normalized": "GxBopTuV5aU7NS0iE1P6I6YCQscIAP0iIyyZqZhs1c8Ry3cdiOouEtQQpX8cA7E1gEnKGRMNA+7NlhBy13AEyg==",
    "implicit": false,
    "signatureFileSHA256": "94e6a1a583585d36403d7a6c40ab6cf8237010b21b29b1848130551f1af975e6",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "microsoft.applicationinsights": {
    "rawSHA512": "dd497bfad0c65e54a4f78d2a1644f3d0854d4cd01dd83ba506f8d5d53635e28152c7c13210dd5dd3985780aab146a7620de3ebaead8ef12c6f87088676c2157f",
    "id": "microsoft.applicationinsights",
    "bytes": 1737910,
    "rawSHA256": "e6c7f76e0ec26598c7b1e2be1777e839c84486655e8a878fc4c655bd2e918dbd",
    "version": "2.23.0",
    "normalized": "nWArUZTdU7iqZLycLKWe0TDms48KKGE6pONH2terYNa8REXiqixrMOkf1sk5DHGMaUTqONU2YkS4SAXBhLStgw==",
    "implicit": false,
    "signatureFileSHA256": "1e9781ba812b702fcd4bfcbf4009cac880eb17215844c7cdfd840a6d9bb62197",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "microsoft.bcl.asyncinterfaces": {
    "rawSHA512": "221a05a0c910f7a87b620d8f3831ed392b4eb95d112bee274d35f27009ad2a26445de9d7cd235fe6fb4a03f2550874bda3be3dddd96edaf9c0852a9c23d7b099",
    "id": "microsoft.bcl.asyncinterfaces",
    "bytes": 76354,
    "rawSHA256": "e3df87fe2170a7e01f0880af59caa8f6eb380b3c40a4f282dfb43912aaf0f895",
    "version": "6.0.0",
    "normalized": "UcSjPsst+DfAdJGVDsu346FX0ci0ah+lw3WRtn18NUwEqRt70HaOQ7lI72vy3+1LxtqI3T5GWwV39rQSrCzAeg==",
    "implicit": false,
    "signatureFileSHA256": "1be128d1337424fcd896cd7ce872698c714bc998ffa6793eacf50bcf4d6e92f2",
    "repositoryCertificate": "5A2901D6ADA3D18260B9C6DFE2133C95D74B9EEF6AE0E5DC334C8454D1477DF4",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "5A2901D6ADA3D18260B9C6DFE2133C95D74B9EEF6AE0E5DC334C8454D1477DF4",
          "notBefore": "2021-02-16T00:00:00.0000000Z",
          "notAfter": "2024-05-15T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "microsoft.testing.extensions.telemetry": {
    "rawSHA512": "9a372a18499687500c9f33fd324450d7f6fc96f78ac86be08b7f39f5bc2f7cd9137eb6513550df82d2b6be4d03cddbf82dc4873cf098e4d3bd0d38bf8338c99c",
    "id": "microsoft.testing.extensions.telemetry",
    "bytes": 517775,
    "rawSHA256": "fdc508edfbba0741f92d0c298b4688129c200b979ae1d057debc5f88565c458a",
    "version": "2.5.2",
    "normalized": "j1XGKCBrmfNm0tmotMa05GlqVtb2cW5UaMkKCFHPyyFHz5rdOy7TD0SVXnZJ+QMrjPAHjRoRqn5qcsUjICSWwg==",
    "implicit": false,
    "signatureFileSHA256": "c478464a1e34bb7e377310a84e38afca108678d8a4a38319595eaea888416c64",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "microsoft.testing.extensions.trxreport.abstractions": {
    "rawSHA512": "74fbdeaf0f237c21dd5eb8edbf5dffa5b7c46625d2d2b29eb26e172d19002e31b476aa8a51dd5bfa560ea241830ec6b710974fd63f719950a16cc741b2e6ac28",
    "id": "microsoft.testing.extensions.trxreport.abstractions",
    "bytes": 114290,
    "rawSHA256": "915a82acf3d3af17ca0ff856adb8a536d01a134a443a462946d9564a08b22e9d",
    "version": "2.5.2",
    "normalized": "+xTIaIU9H44GxOyjrfieMSZnxltGvleA3jCRtdEAzlXKb85pMmVYMLUv2JS8KwD+U2wQHUgvy5YfQfWoPEfVdQ==",
    "implicit": false,
    "signatureFileSHA256": "af3626d703c32776298be8f9a7aa4bb2a6df7ed8004f50cacdbafd9aaa8de00b",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "microsoft.testing.platform": {
    "rawSHA512": "e8aa808d280c15589f50e11bb9191bd5b81a797ed7d7c24286933ef8d596d6e001a5c9b9665712de50a7f4454cbd35faf84d8f610316840313efe41e1ad1fd7a",
    "id": "microsoft.testing.platform",
    "bytes": 3792942,
    "rawSHA256": "9ac2d8d4ff97a506eeba446ba1bc5b7a77e882d1823fb45373a60dfd0b7d2463",
    "version": "2.5.2",
    "normalized": "ocX0rgGY78dKfmZlZe4hB0/dvlh7wJgUAWS+KfwrqxB9DpNsjshnne9dppCKnFNEOkX4QYsrdUU++NInFPiCBw==",
    "implicit": false,
    "signatureFileSHA256": "5dea3881a71249bdef669ef9181b2a604f59b0a517184b10ab7a49ab4f043144",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "microsoft.testing.platform.msbuild": {
    "rawSHA512": "08afa4b6a9a8709b22ec1f8b35a56c859c6fec269c561e0dca3eedbec8eec6615e6b9d8e7739b127b115eed705c8809fa92ab13e643595e9a85ff6dcecd39174",
    "id": "microsoft.testing.platform.msbuild",
    "bytes": 2279673,
    "rawSHA256": "04616888e7eee8e5e6e042354eeb41f5ad34d60bfb015681596a372a0f904e64",
    "version": "2.5.2",
    "normalized": "Jey2v0hd7WHHa7pr6MRNKtA07FvxcOMTCtIhTI7uBZ/qR5m1mgCVCo5L1rtVAtqgMhGA205bUwq9+is4LiCzpw==",
    "implicit": false,
    "signatureFileSHA256": "e1ff42502ea5f5885dbdf83c99353be6556a8bdcc0da032f575a7c8560bccaf6",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "microsoft.win32.registry": {
    "rawSHA512": "471e66567ce59cc86475aece7815d05261264ce114e0c1688ba2551dd51494901fa72dd7a8f74f8e8f0f3dba74af8595f177552f3c06abb4bfce76692197076e",
    "id": "microsoft.win32.registry",
    "bytes": 354731,
    "rawSHA256": "f64ca53c67ca65ce7cc85a8d29aefbb2da2672836731e1115e8cd62730dc5080",
    "version": "5.0.0",
    "normalized": "dDoKi0PnDz31yAyETfRntsLArTlVAVzUzCIvvEDsDsucrl33Dl8pIJG06ePTJTI3tGpeyHS9Cq7Foc/s4EeKcg==",
    "implicit": false,
    "signatureFileSHA256": "eb36362b3b0f9390d9b29f618f0dd3a9adf2bf72309a7b25e8b87439dfc8b781",
    "repositoryCertificate": "0E5F38F57DC1BCC806D8494F4F90FBCEDD988B46760709CBEEC6F4219AA6157D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "0E5F38F57DC1BCC806D8494F4F90FBCEDD988B46760709CBEEC6F4219AA6157D",
          "notBefore": "2018-04-10T00:00:00.0000000Z",
          "notAfter": "2021-04-14T12:00:00.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Manager reported root opening the official repository-signatures-resource and matching sample lines104-115: exact0E5F fingerprint/subject/2018-04-10..2021-04-14T12:00:00Z. No consumer network or actual signature/timestamp/chain verification in this source amendment.",
      "signatureAndTimestampVerified": false
    }
  },
  "system.security.accesscontrol": {
    "rawSHA512": "e1beba70b45f8cc5ae06fdecf365f0bb5b58b9af6d7c79accfef15b5a7c7bbef65e10cf9f299418eb413aac86ffefaa0eab9d91650ce77cc398d390f0597ed42",
    "id": "system.security.accesscontrol",
    "bytes": 235270,
    "rawSHA256": "462e26f796417e8a4350655a85bbd4233b94cbd0f7150c1c5e9acfd88e885141",
    "version": "6.0.1",
    "normalized": "IQ4NXP/B3Ayzvw0rDQzVTYsCKyy0Jp9KI6aYcK7UnGVlR9+Awz++TIPCQtPYfLJfOpm8ajowMR09V7quD3sEHw==",
    "implicit": false,
    "signatureFileSHA256": "1ffaa791e75a090ba956931b6126399b2a7aef8bd289bee689ca90656b7f6556",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "xunit.analyzers": {
    "rawSHA512": "0a9a735543bcc89eaf52b2b84c0cfabd914a9e040377fedc16ab8d73ce6ef66b782b710bf69077dfabae0ae5c4c842d1850f803f7ace0436c399231b5a69d232",
    "id": "xunit.analyzers",
    "bytes": 341517,
    "rawSHA256": "9a61efc10e4b2e99306ca34b61733af7db0d5eaf750eb6d7902064539a7bf9f7",
    "version": "2.3.0",
    "normalized": "FcuLqoNBgQA4MmQXOdNWsDnlw+LBysWUcWOql6MCTXXFJZPn+qjbxHA9F9KBRiPH0Y97MLr1VE6LxdH8MgKUoQ==",
    "implicit": false,
    "signatureFileSHA256": "16d96a1810014a3aa02bceca6c4a6f3cb902f915215345ee9416d0acadb286f4",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "xunit.v3.assert": {
    "rawSHA512": "177366f17701e99d5ee6d8cbec8065818cd1ef28023e012616620f5f034f1e9bdf5ccdb62d5a2052b70be4c007a5359484fd3b0830de6b8ace68b9f73256666b",
    "id": "xunit.v3.assert",
    "bytes": 293921,
    "rawSHA256": "46cbfedd6f8970cccd49e11730f045b8f2017872fcf370c463224e41f3babaa9",
    "version": "4.0.3",
    "normalized": "RrlWQ3yXla+ud9JBWDIY9GnUS/DS44r3ObqqV7wdWt1GhS+SveCe0MBDL238VXYoV2mWnX/DhO2LdTq5FTlT7g==",
    "implicit": false,
    "signatureFileSHA256": "71e98b1da0d196791f72b03c6d452f3fb695638787d391d39f11c7f8c89a0c2b",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "xunit.v3.common": {
    "rawSHA512": "d3bee9c5d2a6b9b38f8a665892cf2f9e32cd148a8d6d6290017c559cda941bbe421d4124d5b40f528095141d182188ec5cb4a2a9c3d038410b3ff916751c0aa4",
    "id": "xunit.v3.common",
    "bytes": 170002,
    "rawSHA256": "21f09821aad3f50e9f99231f61b67a5b5689bc448a9aabe06a1dcd6e9d59e91d",
    "version": "4.0.3",
    "normalized": "+2qGz3rcveIxzbXeZVHU8dhMyaawt01mgm/zv1FJH2FPcvJpfTUqc1vQ3hK2V5zVt8QEDddA+B6fkf9/LWf/Pg==",
    "implicit": false,
    "signatureFileSHA256": "b10f318a8dec4d53007f0caec24e0222ee319f2a7f18ec60b09d49994cf9b82f",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "xunit.v3.core.mtp-v2": {
    "rawSHA512": "8f01179acb34758aeb620a0a26a3842e0c7c75d8db44cad726d574b97f0b480bb00bb55c652a144b228cc1856a7fcc7f9fd57c9f7cfef2f0748ae2d7030e413a",
    "id": "xunit.v3.core.mtp-v2",
    "bytes": 434468,
    "rawSHA256": "fd5c27e51806ff166887948b15d9e52f22bb2ea1490ce446e04a1b38d2ab89c3",
    "version": "4.0.3",
    "normalized": "CsmxEanMln1chMExl6TUjnH5kF0XUDb/SqWKXqnGD8UjpkZARAXi8JDtsUYdxuROcIIdwEfs3iHZeHmTeA8DUA==",
    "implicit": false,
    "signatureFileSHA256": "1377efea846909a5eab097004d17b7c767d9d0236b214f380aa3ebd9934311bb",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "xunit.v3.extensibility.core": {
    "rawSHA512": "3f514cd8afaada1a22864fa845cdb3ab7b7d74f7585cead3e4d6eddbfac1ece4835b418dac964c7c83ced9370bc033ca953f6e44c499f4a2e28b1bd85b9eeefa",
    "id": "xunit.v3.extensibility.core",
    "bytes": 383461,
    "rawSHA256": "333b23b0a2ead5314ba03e88e07fd7365f745ae72faf22fecb2d2fd5749c47aa",
    "version": "4.0.3",
    "normalized": "TBYqQKyT+XBDLSHjG6PnmQpooqatflBcWvNiESVS5ptQxWXVf/FGlkUfkNyHKRCUDSCxxHIJNgwO+SRosUmZEw==",
    "implicit": false,
    "signatureFileSHA256": "2005610cee6a5fff013ddccf65fd618c0bf0935280bf031d6d267594e56627fa",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "xunit.v3.mtp-v2": {
    "rawSHA512": "04bc0703bd22cc59c8719d5ca3e680dc5008f8cdeb865d46b930f20dbdfa059c77bdcacecf804d4a0d6920099ae76929c439ebc428fa234e38817f0c1a31a1e3",
    "id": "xunit.v3.mtp-v2",
    "bytes": 32233,
    "rawSHA256": "95aa4b3557071c076bb030474aa120e35b3458da82f8a025e91b045c0cadc9b7",
    "version": "4.0.3",
    "normalized": "lad1hGmodKkfp3AgIwHVVIYeA9GfW125tnkYj7HvOyiwbDH8gpMKPPhzHRC1wc0w4a+0UsOHx2Ero/DtLXvtqA==",
    "implicit": false,
    "signatureFileSHA256": "ad21043712a9d07043088b3f44bf77a320629d512e32287e86a55ab26ba5dbb3",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "xunit.v3.runner.common": {
    "rawSHA512": "c490d10b8f110b27625975a6e7e0add5d1eee269f844483fe5f01a0ae50ffa12d591c29550553cfca4f50ebdfc4c2fdfa2c1d50ead2940ffb15b8543240eac26",
    "id": "xunit.v3.runner.common",
    "bytes": 531944,
    "rawSHA256": "e19f2f84b3a22d915d20cf29f69b3e2b91d390c0dc82e9071d3f278a160a615a",
    "version": "4.0.3",
    "normalized": "J/kkhBgJg3wu1xI8gY2Esm3oRE47gNrGmKpT/XZDPOzZ3/F33yTK/ZH1CM6qDpAHoTT3GY/JgrVbS4T1JEKYiQ==",
    "implicit": false,
    "signatureFileSHA256": "a863f6241c86d2820d16ddf812b7a30b6acbf29c9a223e0b316eaca74276abb5",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  },
  "xunit.v3.runner.inproc.console": {
    "rawSHA512": "2eaadc0e4acf32baa403bfad007eeff518134e6602c819037c0e8c814b37cd7c86081e04725e102872d5eb5e224fc054010813a5c028097fd5bec14f968644ca",
    "id": "xunit.v3.runner.inproc.console",
    "bytes": 134619,
    "rawSHA256": "7fe4577b94c5a044aab93c61b84441cb3076906a70769096f2987c9ffe949799",
    "version": "4.0.3",
    "normalized": "lDvNs5exa8rBdWXX/wdapPTp81SNCvUarXC5iXzr1qvO168+Sx/Ytrk9VSLbSD3Y9KNK8PcOjMl1q7JfCoo3LQ==",
    "implicit": false,
    "signatureFileSHA256": "967d9037780c61f4050c64da302242afb0fad74766116dfa8947f29888f7776e",
    "repositoryCertificate": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
    "repositoryProvenance": {
      "state": "EXACT_RETAINED_CMS_DATA_AND_COORDINATOR_OFFICIAL_CERT_REFERENCE",
      "retainedCmsRepositoryData": [
        {
          "role": "counter",
          "certificateSHA256": "1F4B311D9ACC115C8DC8018B5A49E00FCE6DA8E2855F9F014CA6F34570BC482D",
          "notBefore": "2024-02-23T00:00:00.0000000Z",
          "notAfter": "2027-05-18T23:59:59.0000000Z",
          "repositoryAttributeOid": "1.3.6.1.4.1.311.84.2.1.1.1",
          "timestampAttributePresent": true
        }
      ],
      "officialCertificateReference": "https://learn.microsoft.com/en-us/nuget/api/repository-signatures-resource",
      "timestampPolicyReference": "https://learn.microsoft.com/en-us/nuget/reference/signed-packages-reference",
      "referenceScope": "Coordinator-supplied official certificate provenance; not fetched or cryptographically revalidated this stage",
      "signatureAndTimestampVerified": false
    }
  }
}''')
IMPLICIT = json.loads(r'''{"microsoft.netcore.app.runtime.linux-x64":{"rawSHA512":"024eb2dc412ac0d4ff64be56100a066e3c63bbc322b17a67471611ca74627e8b5a28469d8615a4e7fcf6293bcd6e747202f32aadb376d534a7258e0dc594a1c5","id":"microsoft.netcore.app.runtime.linux-x64","bytes":40105291,"rawSHA256":"4f48051ab89575999f426340665f1fa0f7545829b331902a9d993d513fe4a338","version":"10.0.15","normalized":"ALsQzH86bVhGmWjv/sESo973cpasVCDicswfJt3bDB7/IUkEs17ilOCyxXbiAGDyCFylNDSAEaFyNwdoU/mAQw==","implicit":true},"microsoft.netcore.app.runtime.win-x64":{"rawSHA512":"304180911187ac05d8036b7f2e8d260f11fefcee4d2ea8164dc561ef488e6494e9a0e08bfe329f3a00ea6280e2dd6f56727be22f80e1325fb99560bc731b6d4b","id":"microsoft.netcore.app.runtime.win-x64","bytes":39989758,"rawSHA256":"7423f58917342b9e4bf276fb164d5726d2c90fe2fe989c552b9e39056256a035","version":"10.0.15","normalized":"vzCVKwBmeXZ31VkaU956oQE1zda/pweaw1q0vtnRWzivoPa4jyz9zVrmhrora1UJlPkzfBteQHf9bOYAF2ZuVw==","implicit":true},"microsoft.aspnetcore.app.runtime.linux-x64":{"rawSHA512":"398f616b0ac01449e1d45d256ca3007174404cc4cf3a83035b06b64b6dc4d0c3e9b722e019c05541e1448775dad81dd23079410d8a6328901ba24ac95da99fa3","id":"microsoft.aspnetcore.app.runtime.linux-x64","bytes":12966962,"rawSHA256":null,"version":"10.0.15","normalized":null,"implicit":true},"microsoft.aspnetcore.app.runtime.win-x64":{"rawSHA512":"19b0b506c3ba8ea54e8fb2eb01a806ef1e108bdac5b7bca53841ea5e6670fa4f7378a30096df00e10047b740ba5c383f70df772c1b0bfd65933c46409c4589ee","id":"microsoft.aspnetcore.app.runtime.win-x64","bytes":12795364,"rawSHA256":null,"version":"10.0.15","normalized":null,"implicit":true},"microsoft.netcore.app.host.linux-x64":{"rawSHA512":"bb66a8280ab889b6b260b0e86b8f2a111b4da3a6d067154dafe0c28fd3d26b6e67b17055cdb3719f245b416719add0065def63f38f6f4f186a0652a1af352b4c","id":"microsoft.netcore.app.host.linux-x64","bytes":5566814,"rawSHA256":null,"version":"10.0.15","normalized":null,"implicit":true},"microsoft.netcore.app.host.win-x64":{"rawSHA512":"57c812c49749de9d7aec1e0f6cd349c9372413cf62bfbe13e1a749997d55dddf8aa3c1e65d52d9c42a1825e3633b998447dc261bcdce5681732861b03deefbd8","id":"microsoft.netcore.app.host.win-x64","bytes":5800874,"rawSHA256":null,"version":"10.0.15","normalized":null,"implicit":true},"microsoft.windowsdesktop.app.runtime.win-x64":{"rawSHA512":"bd4a7efb7cfbd8e36e065cc2a654e18a264776e9d820b187dfb6df2a3cf3586ef99ec96589eabd9badc348691fe9bb9dcc080e5d0f7ffa358179a4b8aa551413","id":"microsoft.windowsdesktop.app.runtime.win-x64","bytes":39196103,"rawSHA256":null,"version":"10.0.15","normalized":null,"implicit":true}}''')

if __name__ == '__main__':
    raise SystemExit(main())
