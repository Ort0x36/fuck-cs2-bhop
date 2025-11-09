import ctypes
import ctypes.wintypes as wintypes
import time
import re
import requests
import sys
import logging
import struct
import psutil

from typing import List

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)

log = logging.getLogger("bhop")

VERSION = "1.0.4"
jump_flag = False

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
psapi = ctypes.WinDLL('psapi', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
LIST_MODULES_ALL = 0x03

LPDWORD = ctypes.POINTER(wintypes.DWORD)
HMODULE = wintypes.HMODULE
SIZE_T = ctypes.c_size_t

kernel32.OpenProcess.argtypes = (
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD
)

kernel32.OpenProcess.restype = wintypes.HANDLE

psapi.EnumProcessModulesEx.argtypes = (
    wintypes.HANDLE,
    ctypes.POINTER(HMODULE),
    wintypes.DWORD,
    LPDWORD,
    wintypes.DWORD
)

psapi.EnumProcessModulesEx.restype = wintypes.BOOL

psapi.GetModuleFileNameExW.argtypes = (
    wintypes.HANDLE,
    HMODULE,
    wintypes.LPWSTR,
    wintypes.DWORD
)

psapi.GetModuleFileNameExW.restype = wintypes.DWORD

kernel32.WriteProcessMemory.argtypes = (
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    SIZE_T,
    ctypes.POINTER(SIZE_T)
)

kernel32.WriteProcessMemory.restype = wintypes.BOOL

user32.GetAsyncKeyState.argtypes = (wintypes.INT,)
user32.GetAsyncKeyState.restype = wintypes.SHORT

kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
kernel32.CloseHandle.restype = wintypes.BOOL


class Offsets:
    dwForceJump = 0

    @staticmethod
    def load() -> None:
        try:
            url = (
                "https://raw.githubusercontent.com/a2x/cs2-dumper",
                "/refs/heads/main/output/buttons.hpp"
            )

            log.info("Retrieving jump offset from %s", url)
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            content = r.text
            m = re.search(
                r'constexpr\s+std::ptrdiff_t\s+jump\s*=\s*(0x[0-9A-Fa-f]+);',
                content
            )

            if m:
                Offsets.dwForceJump = int(m.group(1), 16)
                log.info("dwForceJump: 0x%X", Offsets.dwForceJump)
            else:
                raise RuntimeError("jump offset not found in remote file")
        except Exception as e:
            log.error("Failed to load offsets: %s", e)
            Offsets.dwForceJump = 0


def find_process_by_name(name: str) -> int | None:
    name_no_ext = name.lower().rstrip(".exe")
    for p in psutil.process_iter(['pid', 'name']):
        try:
            if (p.info['name'] and
                    p.info['name'].lower().rstrip(".exe") == name_no_ext):
                return p.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


class Memory:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.handle = None
        self.client_base = 0

    def open(self) -> None:
        log.debug("Opening process PID %d", self.pid)
        h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, int(self.pid))
        if not h:
            err = ctypes.get_last_error()
            raise OSError(f"OpenProcess failed (code {err})")
        self.handle = h
        log.info(
            "Process handle: %s",
            hex(
                ctypes.cast(
                    h,
                    ctypes.c_void_p).value
            )
        )

    def close(self) -> None:
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def enum_modules(self) -> List[HMODULE]:
        if not self.handle:
            raise RuntimeError("process handle not open")

        arr_count = 1024
        HMODULE_ARR = HMODULE * arr_count
        arr = HMODULE_ARR()
        needed = wintypes.DWORD(0)

        ok = psapi.EnumProcessModulesEx(
            self.handle,
            arr,
            ctypes.sizeof(arr),
            ctypes.byref(needed),
            LIST_MODULES_ALL
        )

        if not ok:
            err = ctypes.get_last_error()
            raise OSError(f"EnumProcessModulesEx failed (code {err})")

        module_count = needed.value // ctypes.sizeof(HMODULE)
        modules = [arr[i] for i in range(module_count)]
        return modules

    def get_module_base(self, modulename: str) -> int:
        if not self.handle:
            raise RuntimeError("Process handle is not open")
        modules = self.enum_modules()
        target = modulename.lower()
        for hmod in modules:
            buf = ctypes.create_unicode_buffer(260)
            ret = psapi.GetModuleFileNameExW(
                self.handle,
                hmod,
                buf,
                ctypes.sizeof(buf),
            )
            if ret == 0:
                continue

            fullpath = buf.value.lower()
            ends_with_name = fullpath.endswith(f"\\{target}")
            contains_name = target in fullpath

            if ends_with_name or contains_name:
                return ctypes.cast(hmod, ctypes.c_void_p).value
        return 0

    def write_int(
        self,
        address: int,
        value: int,
        size_bytes: int = 4
    ) -> int:
        if not self.handle:
            raise RuntimeError("process handle not open")
        addr = ctypes.c_void_p(int(address))
        if size_bytes == 4:
            buf = ctypes.c_uint32(int(value))
        elif size_bytes == 8:
            buf = ctypes.c_uint64(int(value))
        else:
            # pack according to required size (fallback)
            packed = struct.pack("<Q" if size_bytes == 8 else "<I", int(value))
            cbuf = ctypes.create_string_buffer(packed)
            written = SIZE_T(0)
            ok = kernel32.WriteProcessMemory(
                self.handle,
                addr,
                cbuf,
                SIZE_T(size_bytes),
                ctypes.byref(written)
            )
            if not ok:
                raise OSError(
                    f"WriteProcessMemory failed (code {ctypes.get_last_error()})"
                )
            return written.value

        written = SIZE_T(0)
        ok = kernel32.WriteProcessMemory(
            self.handle,
            addr,
            ctypes.byref(buf),
            SIZE_T(size_bytes),
            ctypes.byref(written)
        )

        if not ok:
            raise OSError(
                f"WriteProcessMemory failed (code {ctypes.get_last_error()})"
            )
        return written.value


def perform_bhop(mem: Memory) -> None:
    global jump_flag
    try:
        if not jump_flag:
            time.sleep(0.01)
            addr = mem.client_base + Offsets.dwForceJump
            log.info("Writing JUMP_ON (65537) to %s", hex(addr))
            mem.write_int(addr, 65537, size_bytes=4)
            jump_flag = True
        else:
            time.sleep(0.01)
            addr = mem.client_base + Offsets.dwForceJump
            log.info("Writing JUMP_OFF (256) to %s", hex(addr))
            mem.write_int(addr, 256, size_bytes=4)
            jump_flag = False
    except Exception as e:
        log.error("perform_bhop error: %s", e)


def check_for_updates() -> None:
    try:
        log.info("Checking for updates...")
        headers = {'User-Agent': 'CS2-Bhop-Utility'}
        r = requests.get(
            "https://api.github.com/repos/Jesewe/cs2-bhop/tags",
            headers=headers,
            timeout=8
        )
        r.raise_for_status()
        tags = r.json()
        if tags:
            latest = tags[0].get('name', '')
            latest = latest.lstrip('vV')
            if latest != VERSION:
                log.warning(
                    "Update available: current %s vs latest %s",
                    VERSION,
                    latest
                )
            else:
                log.info("You are running the latest version.")
        else:
            log.info("Repository has no tags.")
    except Exception as e:
        log.error("Update check failed: %s", e)


def main() -> None:
    Offsets.load()
    if Offsets.dwForceJump == 0:
        log.error("dwForceJump is 0 — cannot continue.")
        return

    check_for_updates() 
    target_name = "cs2.exe"
    log.info("Searching for process %s ...", target_name)
    pid = find_process_by_name(target_name)
    if not pid:
        log.error("Process %s not found. Exiting — check the name.", target_name)
        return

    log.info("Found %s (PID %d). Opening...", target_name, pid)
    mem = Memory(pid)
    try:
        mem.open()
    except Exception as e:
        log.error("Failed to open process: %s", e)
        return

    try:
        base = mem.get_module_base("client.dll")
    except Exception as e:
        log.error("Error listing modules: %s", e)
        mem.close()
        return

    if not base:
        log.error("client.dll not found in the process.")
        mem.close()
        return

    mem.client_base = base
    log.info("client.dll base address: %s", hex(mem.client_base))
    log.info("Press SPACE to perform bhop (CTRL+C to exit).")

    try:
        while True:
            state = user32.GetAsyncKeyState(0x20)
            if state & 0x8000:
                perform_bhop(mem)
                time.sleep(0.05)
            time.sleep(0.003)
    except KeyboardInterrupt:
        log.info("Exiting due to KeyboardInterrupt.")
    finally:
        mem.close()


if __name__ == "__main__":
    main()
    