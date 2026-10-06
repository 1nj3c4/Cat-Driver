/*
 * catdriver.h — Shared Header for CatDriver Kernel Communication
 * ================================================================
 * This header is included by BOTH the kernel driver (catdriver.c)
 * and the usermode client (catclient.cpp). It defines the IOCTL
 * codes, request/response structures, and device naming.
 *
 * "Every cat needs a door. This is ours." — ENI, 2026
 * ================================================================
 */

#pragma once

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#endif

/* ================================================================
 * Device naming — the cat's front door
 * ================================================================ */
#define CAT_DEVICE_NAME     L"\\Device\\CatDriver"
#define CAT_SYMLINK_NAME    L"\\DosDevices\\CatDriver"
/* Open the device via the raw object namespace through GLOBALROOT. This
 * sidesteps the per-session DosDevices symlink lookup, which can fail
 * silently when the driver was loaded in one session and the client runs
 * in another (as happens with kdmapper + non-interactive logons, e.g.
 * vmrun impersonation). The device itself always lives at
 * \Device\CatDriver regardless of symlink visibility. */
#define CAT_USERMODE_PATH   "\\\\.\\GLOBALROOT\\Device\\CatDriver"

/* ================================================================
 * IOCTL codes — what we can ask the cat to do
 * CTL_CODE(DeviceType, Function, Method, Access)
 *   - FILE_DEVICE_UNKNOWN = 0x22
 *   - METHOD_BUFFERED = 0 (safest, kernel copies buffers for us)
 *   - FILE_ANY_ACCESS = 0
 *   - Function codes 0x800-0x803 (user-defined range starts at 0x800)
 * ================================================================ */
#define IOCTL_CAT_READ_MEMORY      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_WRITE_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_GET_PID          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_GET_MODULE_BASE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_UNLOAD           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_DIAG_READ        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_ATTACHED_READ    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_ALLOC_MEM        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_CREATE_THREAD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_APC_INJECT       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_HIJACK_THREAD    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_SPECIAL_APC      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_FREEZE_PROCESS   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_THAW_PROCESS     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_INSTRUMENT       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_GET_TEB          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_GET_TEBS_BULK    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_PING             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_PROTECT_MEM      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_WRITE_MDL        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CAT_CLEAR_ACG        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* --- CLEAR_ACG — Disable ACG (Arbitrary Code Guard) on target process.
 * Clears MitigationFlags bits 8-11 (DisableDynamicCode variants) and
 * Flags bit 4 (ManageExecutableMemoryWrites) in EPROCESS.
 *
 * Win11 24H2 (build 26100) EPROCESS offsets (per Vergilius Project):
 *   +0x1F4  Flags           (ULONG union; bit 4 = ManageExecutableMemoryWrites)
 *   +0x750  MitigationFlags (ULONG union; bits 8-11 = DisableDynamicCode*)
 *
 * After this call, user-mode code in the target process can run from
 * dynamically-allocated executable memory (e.g. PoolParty-mapped DLLs).
 */
typedef struct _CAT_ACG_REQUEST {
    ULONG       ProcessId;
    ULONG       Reserved;
} CAT_ACG_REQUEST, *PCAT_ACG_REQUEST;

typedef struct _CAT_ACG_RESPONSE {
    ULONG       OldFlags;              // previous Flags value
    ULONG       OldMitigationFlags;    // previous MitigationFlags value
    ULONG       NewFlags;              // Flags after clear
    ULONG       NewMitigationFlags;    // MitigationFlags after clear
    LONG        NtStatus;
} CAT_ACG_RESPONSE, *PCAT_ACG_RESPONSE;

#define CAT_ACG_INPUT_SIZE      sizeof(CAT_ACG_REQUEST)
#define CAT_ACG_OUTPUT_SIZE     sizeof(CAT_ACG_RESPONSE)

/* --- FREEZE / THAW process — separate so caller can hold freeze
 * across multiple driver operations. */
typedef struct _CAT_FREEZE_REQUEST {
    ULONG       ProcessId;
} CAT_FREEZE_REQUEST, *PCAT_FREEZE_REQUEST;

typedef struct _CAT_FREEZE_RESPONSE {
    ULONG       Success;
    LONG        NtStatus;
} CAT_FREEZE_RESPONSE, *PCAT_FREEZE_RESPONSE;

/* ================================================================
 * Request / Response structures
 * All communication goes through the IOCTL SystemBuffer.
 * We use a union approach: request is written into the buffer,
 * response is written back into the same buffer. The kernel copies
 * both ways for METHOD_BUFFERED.
 * ================================================================ */

/* --- READ_MEMORY ---
 * Client sends: pid, address, size
 * Driver fills: data[] at the start of the output buffer
 * Output buffer must be at least 'size' bytes.
 */
#pragma pack(push, 1)

typedef struct _CAT_READ_REQUEST {
    ULONG       ProcessId;          // Target process ID
    ULONGLONG   Address;            // Virtual address to read from
    ULONG       Size;               // Number of bytes to read
} CAT_READ_REQUEST, *PCAT_READ_REQUEST;

/* No separate response struct — the output buffer IS the data.
 * The driver writes 'Size' bytes directly into SystemBuffer.
 * Client provides an output buffer >= Size bytes.
 * We use a wrapper for the combined in/out buffer: */

typedef struct _CAT_READ_BUFFER {
    CAT_READ_REQUEST Request;       // Input: what to read
    // Output: raw bytes follow the request in the output buffer
    // (actually, the driver writes to the START of SystemBuffer)
} CAT_READ_BUFFER, *PCAT_READ_BUFFER;

/* --- WRITE_MEMORY ---
 * Client sends: pid, address, size, then data[] immediately after
 * No meaningful response (status in NTSTATUS return)
 */
typedef struct _CAT_WRITE_REQUEST {
    ULONG       ProcessId;          // Target process ID
    ULONGLONG   Address;            // Virtual address to write to
    ULONG       Size;               // Number of bytes to write
    UCHAR       Data[1];            // Variable-length data (flexible array member)
                                    // Actual data starts here, extends for 'Size' bytes
} CAT_WRITE_REQUEST, *PCAT_WRITE_REQUEST;

/* --- GET_PID ---
 * Client sends: process name (wide string, e.g. L"RobloxPlayerBeta.exe")
 * Driver returns: the process ID
 */
typedef struct _CAT_GET_PID_REQUEST {
    WCHAR       ProcessName[260];   // Null-terminated wide process name
} CAT_GET_PID_REQUEST, *PCAT_GET_PID_REQUEST;

typedef struct _CAT_GET_PID_RESPONSE {
    ULONG       ProcessId;          // Found PID, or 0 if not found
} CAT_GET_PID_RESPONSE, *PCAT_GET_PID_RESPONSE;

/* --- GET_MODULE_BASE ---
 * Client sends: PID of the target process
 * Driver returns: base address and size of the main module (first entry in PEB->Ldr)
 */
typedef struct _CAT_MODULE_BASE_REQUEST {
    ULONG       ProcessId;          // Target process ID
} CAT_MODULE_BASE_REQUEST, *PCAT_MODULE_BASE_REQUEST;

typedef struct _CAT_MODULE_BASE_RESPONSE {
    ULONGLONG   BaseAddress;        // Main module base address
    ULONG       ImageSize;          // Size of the module image
} CAT_MODULE_BASE_RESPONSE, *PCAT_MODULE_BASE_RESPONSE;

/* --- DIAG_READ ---
 * Tests all read methods on a single address and reports what each one did.
 * Returns status from each method + page table walk details.
 */
#define CAT_DIAG_DATA_SIZE 64

typedef struct _CAT_DIAG_REQUEST {
    ULONG       ProcessId;
    ULONGLONG   Address;
} CAT_DIAG_REQUEST, *PCAT_DIAG_REQUEST;

typedef struct _CAT_DIAG_RESPONSE {
    LONG        mmCopyStatus;       // NTSTATUS from MmCopyVirtualMemory
    LONG        mdlStatus;          // NTSTATUS from MDL-based read
    LONG        physStatus;         // NTSTATUS from MmGetPhysicalAddress path
    LONG        pageWalkStatus;     // NTSTATUS from CR3 page table walk
    ULONGLONG   cr3Value;           // DirectoryTableBase from EPROCESS
    ULONGLONG   pml4Entry;          // raw PML4 entry
    ULONGLONG   pdptEntry;          // raw PDPT entry
    ULONGLONG   pdEntry;            // raw PD entry
    ULONGLONG   ptEntry;            // raw PT entry
    ULONGLONG   physAddress;        // resolved physical address
    ULONG       whichWorked;        // 1=mmcopy, 2=mdl, 3=phys, 4=pagewalk, 0=none
    UCHAR       data[CAT_DIAG_DATA_SIZE];
} CAT_DIAG_RESPONSE, *PCAT_DIAG_RESPONSE;

#define CAT_DIAG_INPUT_SIZE   sizeof(CAT_DIAG_REQUEST)
#define CAT_DIAG_OUTPUT_SIZE  sizeof(CAT_DIAG_RESPONSE)

/* --- ALLOC_MEM ---
 * Allocates memory in target process (RWX or whatever protection).
 */
typedef struct _CAT_ALLOC_REQUEST {
    ULONG       ProcessId;
    ULONG       Size;               // Bytes to allocate
    ULONG       Protection;         // PAGE_EXECUTE_READWRITE = 0x40, etc.
} CAT_ALLOC_REQUEST, *PCAT_ALLOC_REQUEST;

typedef struct _CAT_ALLOC_RESPONSE {
    ULONGLONG   AllocatedAddress;
    ULONG       AllocatedSize;      // Actual allocated size (page-rounded)
} CAT_ALLOC_RESPONSE, *PCAT_ALLOC_RESPONSE;

#define CAT_ALLOC_INPUT_SIZE    sizeof(CAT_ALLOC_REQUEST)
#define CAT_ALLOC_OUTPUT_SIZE   sizeof(CAT_ALLOC_RESPONSE)

/* --- PROTECT_MEM ---
 * Change page protection in the target process via ZwProtectVirtualMemory
 * against a KernelMode-opened process handle. Needed for injecting a
 * trampoline into .text (which is PAGE_EXECUTE_READ by default) —
 * MmCopyVirtualMemory in KernelMode still respects PTE protection, so
 * we have to flip the page to PAGE_EXECUTE_READWRITE first, write, then
 * flip back if we want to be tidy.
 */
typedef struct _CAT_PROTECT_REQUEST {
    ULONG       ProcessId;
    ULONGLONG   Address;
    ULONG       Size;
    ULONG       NewProtection;      // PAGE_EXECUTE_READWRITE = 0x40, etc.
} CAT_PROTECT_REQUEST, *PCAT_PROTECT_REQUEST;

typedef struct _CAT_PROTECT_RESPONSE {
    ULONG       OldProtection;
    LONG        NtStatus;
} CAT_PROTECT_RESPONSE, *PCAT_PROTECT_RESPONSE;

#define CAT_PROTECT_INPUT_SIZE  sizeof(CAT_PROTECT_REQUEST)
#define CAT_PROTECT_OUTPUT_SIZE sizeof(CAT_PROTECT_RESPONSE)

/* --- CREATE_THREAD ---
 * Creates a user-mode thread in target process at StartAddress(Parameter).
 */
typedef struct _CAT_THREAD_REQUEST {
    ULONG       ProcessId;
    ULONGLONG   StartAddress;       // Thread entry point in target process
    ULONGLONG   Parameter;          // Argument passed to thread function
} CAT_THREAD_REQUEST, *PCAT_THREAD_REQUEST;

typedef struct _CAT_THREAD_RESPONSE {
    ULONG       ThreadId;
} CAT_THREAD_RESPONSE, *PCAT_THREAD_RESPONSE;

#define CAT_THREAD_INPUT_SIZE   sizeof(CAT_THREAD_REQUEST)
#define CAT_THREAD_OUTPUT_SIZE  sizeof(CAT_THREAD_RESPONSE)

/* --- APC_INJECT ---
 * Queue a user-mode APC on an existing thread. Stealthier than thread creation.
 * Usermode enumerates threads, passes a TID + function + arg.
 * Driver queues APC via KeInitializeApc + KeInsertQueueApc.
 */
typedef struct _CAT_APC_REQUEST {
    ULONG       ProcessId;
    ULONG       ThreadId;           // Target thread to queue APC on
    ULONGLONG   ApcRoutine;         // User-mode function (e.g. LoadLibraryA)
    ULONGLONG   ApcArgument;        // Argument (e.g. DLL path pointer)
} CAT_APC_REQUEST, *PCAT_APC_REQUEST;

typedef struct _CAT_APC_RESPONSE {
    ULONG       Queued;             // 1 = APC queued successfully
    LONG        NtStatus;           // NTSTATUS from internal ops
} CAT_APC_RESPONSE, *PCAT_APC_RESPONSE;

#define CAT_APC_INPUT_SIZE      sizeof(CAT_APC_REQUEST)
#define CAT_APC_OUTPUT_SIZE     sizeof(CAT_APC_RESPONSE)

/* --- HIJACK_THREAD ---
 * Suspend a thread, redirect RIP to shellcode, resume.
 * Shellcode gets params pointer in RCX.
 * Driver saves original context into the params struct so
 * shellcode can restore and return cleanly.
 */
typedef struct _CAT_HIJACK_REQUEST {
    ULONG       ProcessId;
    ULONG       ThreadId;
    ULONGLONG   ShellcodeAddr;      // RWX memory with our code
    ULONGLONG   ParamsAddr;         // RW memory with ScanParams struct
} CAT_HIJACK_REQUEST, *PCAT_HIJACK_REQUEST;

typedef struct _CAT_HIJACK_RESPONSE {
    ULONG       Success;
    LONG        NtStatus;
    ULONGLONG   OriginalRip;        // For diagnostics
} CAT_HIJACK_RESPONSE, *PCAT_HIJACK_RESPONSE;

#define CAT_HIJACK_INPUT_SIZE   sizeof(CAT_HIJACK_REQUEST)
#define CAT_HIJACK_OUTPUT_SIZE  sizeof(CAT_HIJACK_RESPONSE)

/* --- INSTRUMENT ---
 * Set process instrumentation callback — fires on EVERY syscall return.
 * Bypasses APC delivery entirely. CallbackAddr=0 to clear.
 */
typedef struct _CAT_INSTRUMENT_REQUEST {
    ULONG       ProcessId;
    ULONGLONG   CallbackAddr;       // user-mode callback (0 to clear)
} CAT_INSTRUMENT_REQUEST, *PCAT_INSTRUMENT_REQUEST;

typedef struct _CAT_INSTRUMENT_RESPONSE {
    ULONG       Success;
    LONG        NtStatus;
} CAT_INSTRUMENT_RESPONSE, *PCAT_INSTRUMENT_RESPONSE;

#define CAT_INSTRUMENT_INPUT_SIZE   sizeof(CAT_INSTRUMENT_REQUEST)
#define CAT_INSTRUMENT_OUTPUT_SIZE  sizeof(CAT_INSTRUMENT_RESPONSE)

#pragma pack(pop)

/* ================================================================
 * Size validation helpers — because cats are precise
 * ================================================================ */
#pragma pack(push, 1)

/* --- GET_TEB ---
 * Resolves a thread's TEB inside the kernel (PsGetThreadTeb) — immune to
 * usermode NtQueryInformationThread hooking / handle stripping.
 * Client sends: target pid + tid. Driver returns: TEB linear address.
 */
typedef struct _CAT_TEB_REQUEST {
    ULONG       ProcessId;          // owning process (sanity check)
    ULONG       ThreadId;           // thread to resolve
} CAT_TEB_REQUEST, *PCAT_TEB_REQUEST;

typedef struct _CAT_TEB_RESPONSE {
    ULONGLONG   TebAddress;         // 0 = failed
    LONG        NtStatus;
} CAT_TEB_RESPONSE, *PCAT_TEB_RESPONSE;

#pragma pack(pop)

#define CAT_TEB_INPUT_SIZE      sizeof(CAT_TEB_REQUEST)
#define CAT_TEB_OUTPUT_SIZE     sizeof(CAT_TEB_RESPONSE)

/* --- GET_TEBS_BULK ---
 * Walks the target process's ThreadListHead (EPROCESS) in-kernel and
 * returns every thread's TEB. Bypasses PspCidTable entirely — immune to
 * CID-table tampering and thread hiding. Offsets are DISCOVERED at runtime
 * from the calling context (no hardcoded build offsets).
 */
typedef struct _CAT_TEBS_REQUEST {
    ULONG       ProcessId;
    ULONG       MaxTebs;            // capacity of array below (<= 512)
    ULONGLONG   ClientTeb;          // caller's own TEB (NtCurrentTeb) — discovery anchor
} CAT_TEBS_REQUEST, *PCAT_TEBS_REQUEST;

typedef struct _CAT_TEBS_RESPONSE {
    ULONG       Count;              // TEBs written
    LONG        NtStatus;
    ULONGLONG   Tebs[512];
} CAT_TEBS_RESPONSE, *PCAT_TEBS_RESPONSE;

#define CAT_TEBS_INPUT_SIZE     sizeof(CAT_TEBS_REQUEST)
#define CAT_TEBS_OUTPUT_SIZE    sizeof(CAT_TEBS_RESPONSE)

/* --- PING ---
 * Returns driver build id + live thread-walk offset discovery state +
 * discovered OS build number. Lets tools verify WHICH driver build is
 * loaded, which Windows build it detected, and why discovery failed —
 * without DebugView.
 *
 * Optional: client may set `ResetCookie` to CAT_PING_RESET_DISCOVERY in
 * the INPUT buffer to force the TEBS_BULK offsets back to -1 so the next
 * caller re-runs CatDiscoverThreadOffsets. Guards against a sticky bad
 * first-caller setting wrong offsets for the rest of the driver load.
 */
typedef struct _CAT_PING_REQUEST {
    ULONG       ResetCookie;        // CAT_PING_RESET_DISCOVERY = reset
} CAT_PING_REQUEST, *PCAT_PING_REQUEST;

typedef struct _CAT_PING_RESPONSE {
    ULONG       BuildLen;           // bytes valid in BuildId
    CHAR        BuildId[32];        // compile timestamp
    LONG        TebOff;             // -1 = discovery not run/failed
    LONG        CidOff;
    LONG        ListHeadOff;
    LONG        ListEntryOff;
    ULONG       OsBuildNumber;      // RtlGetVersion->dwBuildNumber (0 if not discovered)
} CAT_PING_RESPONSE, *PCAT_PING_RESPONSE;

#define CAT_PING_RESET_DISCOVERY    0xCA7CA701UL

#define CAT_PING_OUTPUT_SIZE    sizeof(CAT_PING_RESPONSE)

#define CAT_READ_INPUT_SIZE     sizeof(CAT_READ_REQUEST)
#define CAT_WRITE_MIN_SIZE      (sizeof(CAT_WRITE_REQUEST) - 1) // minus flexible array
#define CAT_PID_INPUT_SIZE      sizeof(CAT_GET_PID_REQUEST)
#define CAT_PID_OUTPUT_SIZE     sizeof(CAT_GET_PID_RESPONSE)
#define CAT_MODULE_INPUT_SIZE   sizeof(CAT_MODULE_BASE_REQUEST)
#define CAT_MODULE_OUTPUT_SIZE  sizeof(CAT_MODULE_BASE_RESPONSE)

/* Max memory R/W per IOCTL — 16MB should be enough for anyone.
 * (Bill Gates probably said that about 640K, but we're cats, not humans) */
#define CAT_MAX_TRANSFER_SIZE   (16 * 1024 * 1024)
