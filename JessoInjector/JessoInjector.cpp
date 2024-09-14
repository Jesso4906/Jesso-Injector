#include "JessoInjector.h"

bool FreezeAllThreads(HANDLE procHandle, bool resume)
{
    DWORD procId = GetProcessId(procHandle);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == procId)
            {
                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (!thread) { continue; }

                if (resume) { ResumeThread(thread); }
                else { SuspendThread(thread); }
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return true;
}

HANDLE GetFirstThread(HANDLE procHandle)
{
    DWORD procId = GetProcessId(procHandle);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (!snap)
    {
        return 0;
    }

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == procId)
            {
                CloseHandle(snap);
                return OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return 0;
}

InjectionResult InjectByLoadLibraryA(HANDLE procHandle, const char* dllPath)
{
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES)
    {
        return FileNotFound;
    }
    
    void* dllPathLocation = VirtualAllocEx(procHandle, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!dllPathLocation)
    {
        return FailedVirtualAllocEx;
    }

    if (!WriteProcessMemory(procHandle, dllPathLocation, dllPath, strlen(dllPath) + 1, 0)) 
    {
        return FailedWriteProcessMemory;
    }

    HANDLE threadHandle = CreateRemoteThread(procHandle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, dllPathLocation, 0, 0);

    if (threadHandle && threadHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(threadHandle);
    }
    else
    {
        VirtualFreeEx(procHandle, dllPathLocation, 0, MEM_RELEASE);
        return FailedCreateRemoteThread;
    }

    Sleep(500);

    VirtualFreeEx(procHandle, dllPathLocation, 0, MEM_RELEASE);

    return Success;
}

InjectionResult InjectByThreadHijack(HANDLE procHandle, const char* dllPath, int threadId)
{
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES)
    {
        return FileNotFound;
    }

    void* dllPathLocation = VirtualAllocEx(procHandle, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!dllPathLocation)
    {
        return FailedVirtualAllocEx;
    }

    if (!WriteProcessMemory(procHandle, dllPathLocation, dllPath, strlen(dllPath) + 1, 0))
    {
        return FailedWriteProcessMemory;
    }

#if _WIN64
    const char shellCodeLen = 70;
    const char dllPathIndex = 6;
    const char loadLibIndex = 19;
    const char getThreadIndex = 31;
    const char savedCtxIndex = 46;
    const char setCtxIndex = 56;
    unsigned char shellCodeBuffer[shellCodeLen] =
        "\x48\x83\xEC\x28"                          // sub rsp, 0x28
        "\x48\xBB\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rbx, dllPathLocation
        "\x48\x89\xD9"                              // mov rcx, rbx
        "\x48\xB8\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rax, LoadLibraryA
        "\xFF\xD0"                                  // call rax
        "\x48\xB8\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rax, GetCurrentThread
        "\xFF\xD0"                                  // call rax
        "\x48\x89\xC1"                              // mov rcx, rax
        "\x48\xBA\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rdx, savedCtxLocation
        "\x48\xB8\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rax, SetThreadContext
        "\xC6\x03\x00"                              // mov byte ptr [rbx], 0x0
        "\xFF\xD0";                                 // call rax
#else
    const char shellCodeLen = 37;
    const char dllPathIndex = 1;
    const char loadLibIndex = 7;
    const char getThreadIndex = 14;
    const char savedCtxIndex = 21;
    const char setCtxIndex = 27;
    unsigned char shellCodeBuffer[shellCodeLen] =
        "\xBB\x95\x32\x1E\x77"  // mov ebx, dllPathLocation
        "\x53"                  // push ebx
        "\xB8\x00\x00\x00\x00"  // mov eax, LoadLibraryA
        "\xFF\xD0"              // call eax
        "\xB8\x00\x00\x00\x00"  // mov eax, GetCurrentThread
        "\xFF\xD0"              // call eax
        "\x68\x00\x00\x00\x00"  // push savedCtxLocation
        "\x50"                  // push eax
        "\xB8\x00\x00\x00\x00"  // mov eax, SetThreadContext
        "\xC6\x03\x00"          // mov byte ptr [ebx], 0x0
        "\xFF\xD0";             // call eax
#endif
    void* shellCodeLocation = VirtualAllocEx(procHandle, 0, shellCodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellCodeLocation)
    {
        return FailedVirtualAllocEx;
    }

    void* savedCtxLocation = VirtualAllocEx(procHandle, 0, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!savedCtxLocation)
    {
        VirtualFreeEx(procHandle, shellCodeLocation, 0, MEM_RELEASE);
        return FailedVirtualAllocEx;
    }

    for (int i = 0; i < sizeof(uintptr_t); i++)
    {
        shellCodeBuffer[i + dllPathIndex] = ((uintptr_t)dllPathLocation >> (i * 8)) & 0xFF;
        shellCodeBuffer[i + loadLibIndex] = ((uintptr_t)&LoadLibraryA >> (i * 8)) & 0xFF;
        shellCodeBuffer[i + getThreadIndex] = ((uintptr_t)&GetCurrentThread >> (i * 8)) & 0xFF;
        shellCodeBuffer[i + savedCtxIndex] = ((uintptr_t)savedCtxLocation >> (i * 8)) & 0xFF;
        shellCodeBuffer[i + setCtxIndex] = ((uintptr_t)&SetThreadContext >> (i * 8)) & 0xFF;
    }

    HANDLE threadHandle = 0;
    if (threadId == -1) { threadHandle = GetFirstThread(procHandle); }
    else { threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId); }

    if (!threadHandle)
    {
        VirtualFreeEx(procHandle, shellCodeLocation, 0, MEM_RELEASE);
        VirtualFreeEx(procHandle, savedCtxLocation, 0, MEM_RELEASE);
        return FailedOpenThread;
    }

    if (!FreezeAllThreads(procHandle, false))
    {
        CloseHandle(threadHandle);
        VirtualFreeEx(procHandle, shellCodeLocation, 0, MEM_RELEASE);
        VirtualFreeEx(procHandle, savedCtxLocation, 0, MEM_RELEASE);
        return FailedCreateThreadSnapshot;
    }

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(threadHandle, &ctx))
    {
        FreezeAllThreads(procHandle, true);
        CloseHandle(threadHandle);
        VirtualFreeEx(procHandle, shellCodeLocation, 0, MEM_RELEASE);
        VirtualFreeEx(procHandle, savedCtxLocation, 0, MEM_RELEASE);
        return FailedGetThreadContext;
    }

    WriteProcessMemory(procHandle, shellCodeLocation, shellCodeBuffer, shellCodeLen, nullptr);
    WriteProcessMemory(procHandle, savedCtxLocation, &ctx, sizeof(ctx), nullptr);
#if _WIN64
    ctx.Rip = (uintptr_t)shellCodeLocation;
#else
    ctx.Eip = (uintptr_t)shellCodeLocation;
#endif
    SetThreadContext(threadHandle, &ctx);

    FreezeAllThreads(procHandle, true);

    bool injected = false;
    while (!injected)
    {
        char result = 1;
        ReadProcessMemory(procHandle, dllPathLocation, &result, sizeof(result), nullptr);
        injected = result == 0; // set to zero in shell code
        Sleep(100);
    }

    CloseHandle(threadHandle);
    VirtualFreeEx(procHandle, shellCodeLocation, 0, MEM_RELEASE);
    VirtualFreeEx(procHandle, savedCtxLocation, 0, MEM_RELEASE);

    VirtualFreeEx(procHandle, dllPathLocation, 0, MEM_RELEASE);

    return Success;
}

InjectionResult InjectByManuallyMapping(HANDLE procHandle, const char* dllPath, bool hijackThread, int threadId)
{
    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES)
    {
        return FileNotFound;
    }

    // Read the dll file

    std::ifstream file(dllPath, std::ios::binary | std::ios::ate);

    if (file.fail())
    {
        file.close();
        return FailedToOpenFile;
    }

    DWORD fileSize = file.tellg(); // get pointer will be at the end of the file
    if (fileSize < 0x1000)
    {
        file.close();
        return FailedToOpenFile;
    }

    char* dllFileData = new char[fileSize];

    file.seekg(0, std::ios::beg); // set the get pointer to the beginning
    file.read(dllFileData, fileSize);
    file.close();

    IMAGE_DOS_HEADER* imageDosHeader = (IMAGE_DOS_HEADER*)dllFileData; // image dos header is at the very beginning of PE files

    if (imageDosHeader->e_magic != 0x5A4D) // 0x5A4D = "MZ"; this is a magic number to check the file is a valid PE file
    {
        delete[] dllFileData;
        return FailedToOpenFile;
    }

    // Allocating memory in the proccess for the dll file

    IMAGE_NT_HEADERS* imageNtHeaders = (IMAGE_NT_HEADERS*)(dllFileData + imageDosHeader->e_lfanew); // e_lfanew is a file offset to the IMAGE_NT_HEADERS struct
    IMAGE_OPTIONAL_HEADER* imageOptHeader = &imageNtHeaders->OptionalHeader;
    IMAGE_FILE_HEADER* imageFileHeader = &imageNtHeaders->FileHeader;

    // ImageBase is the address where the PE file would prefer to be loaded
    char* dllBaseAddress = (char*)VirtualAllocEx(procHandle, (void*)imageOptHeader->ImageBase, imageOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!dllBaseAddress)
    {
        // If it can't be loaded there, let VirtualAllocEx put it where it wants. Relocation data will be used later to adjust for this
        dllBaseAddress = (char*)VirtualAllocEx(procHandle, nullptr, imageOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        if (!dllBaseAddress)
        {
            delete[] dllFileData;
            return FailedVirtualAllocEx;
        }
    }

    // Writing section data into the process

    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(imageNtHeaders);

    for (int i = 0; i < imageFileHeader->NumberOfSections; i++)
    {
        if (section->SizeOfRawData != 0) // Only write it if it has data
        {
            if (!WriteProcessMemory(procHandle, dllBaseAddress + section->VirtualAddress, dllFileData + section->PointerToRawData, section->SizeOfRawData, nullptr))
            {
                delete[] dllFileData;
                VirtualFreeEx(procHandle, dllBaseAddress, 0, MEM_RELEASE);
                return FailedWriteProcessMemory;
            }
        }
        section++;
    }

    WriteProcessMemory(procHandle, dllBaseAddress, dllFileData, 0x1000, nullptr);

    delete[] dllFileData;

    void* internalCodeLocation = VirtualAllocEx(procHandle, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!internalCodeLocation)
    {
        VirtualFreeEx(procHandle, dllBaseAddress, 0, MEM_RELEASE);
        return FailedVirtualAllocEx;
    }

    void* internalCodeParamLocation = VirtualAllocEx(procHandle, 0, sizeof(InternalManualMapParameter), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!internalCodeParamLocation)
    {
        VirtualFreeEx(procHandle, dllBaseAddress, 0, MEM_RELEASE);
        VirtualFreeEx(procHandle, internalCodeLocation, 0, MEM_RELEASE);
        return FailedVirtualAllocEx;
    }

    WriteProcessMemory(procHandle, internalCodeLocation, InternalManualMapCode, 0x1000, nullptr);

    InternalManualMapParameter internalParam = {};
    internalParam.dllBaseAddress = dllBaseAddress;
    internalParam.loadLibA = LoadLibraryA; // the internal code will not have access to these functions so they must be passed as a parameter
    internalParam.getProcAddr = GetProcAddress;

    WriteProcessMemory(procHandle, internalCodeParamLocation, &internalParam, sizeof(InternalManualMapParameter), nullptr);

    void* savedCtxLocation = nullptr;
    void* shellCodeLocation = nullptr;
    if (hijackThread)
    {
        HANDLE threadHandle = 0;
        if (threadId == -1) { threadHandle = GetFirstThread(procHandle); }
        else { threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId); }

        if (!threadHandle)
        {
            VirtualFreeEx(procHandle, dllBaseAddress, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeLocation, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeParamLocation, 0, MEM_RELEASE);
            return FailedOpenThread;
        }

        if (!FreezeAllThreads(procHandle, false))
        {
            CloseHandle(threadHandle);
            VirtualFreeEx(procHandle, dllBaseAddress, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeLocation, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeParamLocation, 0, MEM_RELEASE);
            return FailedCreateThreadSnapshot;
        }

        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(threadHandle, &ctx))
        {
            FreezeAllThreads(procHandle, true);
            CloseHandle(threadHandle);
            VirtualFreeEx(procHandle, dllBaseAddress, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeLocation, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeParamLocation, 0, MEM_RELEASE);
            return FailedGetThreadContext;
        }

#if _WIN64
        const char shellCodeLen = 64;
        const char paramIndex = 6;
        const char internalCodeIndex = 16;
        const char getThreadIndex = 28;
        const char savedCtxIndex = 43;
        const char setCtxIndex = 53;
        unsigned char shellCodeBuffer[shellCodeLen] =
            "\x48\x83\xEC\x28"                          // sub rsp, 0x28
            "\x48\xB9\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rcx, internalCodeParam
            "\x48\xB8\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rax, InternalManualMapCode
            "\xFF\xD0"                                  // call rax
            "\x48\xB8\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rax, GetCurrentThread
            "\xFF\xD0"                                  // call rax
            "\x48\x89\xC1"                              // mov rcx, rax
            "\x48\xBA\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rdx, savedCtxLocation
            "\x48\xB8\xA8\x0F\xB1\xE6\x00\x00\x00\x00"  // movabs rax, SetThreadContext
            "\xFF\xD0";                                 // call rax
#else
        const char shellCodeLen = 33;
        const char paramIndex = 1;
        const char internalCodeIndex = 6;
        const char getThreadIndex = 13;
        const char savedCtxIndex = 20;
        const char setCtxIndex = 26;
        unsigned char shellCodeBuffer[shellCodeLen] =
            "\x68\x00\x00\x00\x00"  // push internalCodeParam
            "\xB8\x00\x00\x00\x00"  // mov eax, InternalManualMapCode
            "\xFF\xD0"              // call eax
            "\xB8\x00\x00\x00\x00"  // mov eax, GetCurrentThread
            "\xFF\xD0"              // call eax
            "\x68\x00\x00\x00\x00"  // push savedCtxLocation
            "\x50"                  // push eax
            "\xB8\x00\x00\x00\x00"  // mov eax, SetThreadContext
            "\xFF\xD0";             // call eax
#endif

        savedCtxLocation = VirtualAllocEx(procHandle, 0, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!savedCtxLocation)
        {
            FreezeAllThreads(procHandle, true);
            CloseHandle(threadHandle);
            VirtualFreeEx(procHandle, dllBaseAddress, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeLocation, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeParamLocation, 0, MEM_RELEASE);
            return FailedVirtualAllocEx;
        }

        shellCodeLocation = VirtualAllocEx(procHandle, 0, shellCodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shellCodeLocation)
        {
            FreezeAllThreads(procHandle, true);
            CloseHandle(threadHandle);
            VirtualFreeEx(procHandle, dllBaseAddress, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeLocation, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeParamLocation, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, savedCtxLocation, 0, MEM_RELEASE);
            return FailedVirtualAllocEx;
        }

        for (int i = 0; i < sizeof(uintptr_t); i++)
        {
            shellCodeBuffer[i + paramIndex] = ((uintptr_t)internalCodeParamLocation >> (i * 8)) & 0xFF;
            shellCodeBuffer[i + internalCodeIndex] = ((uintptr_t)internalCodeLocation >> (i * 8)) & 0xFF;
            shellCodeBuffer[i + getThreadIndex] = ((uintptr_t)&GetCurrentThread >> (i * 8)) & 0xFF;
            shellCodeBuffer[i + savedCtxIndex] = ((uintptr_t)savedCtxLocation >> (i * 8)) & 0xFF;
            shellCodeBuffer[i + setCtxIndex] = ((uintptr_t)&SetThreadContext >> (i * 8)) & 0xFF;
        }

        WriteProcessMemory(procHandle, shellCodeLocation, shellCodeBuffer, shellCodeLen, nullptr);
        WriteProcessMemory(procHandle, savedCtxLocation, &ctx, sizeof(ctx), nullptr);

#if _WIN64
        ctx.Rip = (uintptr_t)shellCodeLocation;
#else
        ctx.Eip = (uintptr_t)shellCodeLocation;
#endif
        SetThreadContext(threadHandle, &ctx);

        FreezeAllThreads(procHandle, true);

        CloseHandle(threadHandle);
    }
    else
    {
        HANDLE threadHandle = CreateRemoteThread(procHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)internalCodeLocation, internalCodeParamLocation, 0, nullptr);
        if (!threadHandle)
        {
            VirtualFreeEx(procHandle, dllBaseAddress, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeLocation, 0, MEM_RELEASE);
            VirtualFreeEx(procHandle, internalCodeParamLocation, 0, MEM_RELEASE);
            return FailedCreateRemoteThread;
        }

        CloseHandle(threadHandle);
    }

    bool injected = false;
    while (!injected)
    {
        InternalManualMapParameter readParam = {};
        ReadProcessMemory(procHandle, internalCodeParamLocation, &readParam, sizeof(InternalManualMapParameter), nullptr);
        injected = readParam.succeeded;
        Sleep(100);
    }

    if (hijackThread)
    {
        Sleep(250);
        VirtualFreeEx(procHandle, shellCodeLocation, 0, MEM_RELEASE);
        VirtualFreeEx(procHandle, savedCtxLocation, 0, MEM_RELEASE);
    }

    VirtualFreeEx(procHandle, internalCodeLocation, 0, MEM_RELEASE);
    VirtualFreeEx(procHandle, internalCodeParamLocation, 0, MEM_RELEASE);

    return Success;
}

// compiler inserts code that will result in a crash if compiled in debug mode
void __stdcall InternalManualMapCode(InternalManualMapParameter* param)
{
    if (!param) { return; }

    char* dllBaseAddress = param->dllBaseAddress;

    IMAGE_DOS_HEADER* imageDosHeader = (IMAGE_DOS_HEADER*)dllBaseAddress;
    IMAGE_NT_HEADERS* imageNtHeaders = (IMAGE_NT_HEADERS*)(dllBaseAddress + imageDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER* imageOptHeader = &imageNtHeaders->OptionalHeader;

    uintptr_t locationOffset = (uintptr_t)dllBaseAddress - imageOptHeader->ImageBase;
    if (locationOffset != 0) // The dll is not loaded where the dll assumed it would be, so relocation data needs to be used to adjust
    {
        if (imageOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0) { return; }

        IMAGE_BASE_RELOCATION* relocation = (IMAGE_BASE_RELOCATION*)(dllBaseAddress + imageOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (relocation->VirtualAddress != 0)
        {
            WORD* relativeInfo = (WORD*)(relocation + 1);

            int numberOfEntries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (int i = 0; i < numberOfEntries; i++)
            {
                if (((*relativeInfo) >> 0x0C) == IMAGE_REL_BASED_HIGHLOW || ((*relativeInfo) >> 0x0C) == IMAGE_REL_BASED_DIR64) // checking flags to see if this relocation is relevant (32 or 64 bit)
                {
                    uintptr_t* patch = (uintptr_t*)(dllBaseAddress + relocation->VirtualAddress + ((*relativeInfo) & 0xFFF));
                    *patch += locationOffset;
                }

                relativeInfo++;
            }

            relocation = (IMAGE_BASE_RELOCATION*)((char*)relocation + relocation->SizeOfBlock);
        }
    }

    //Load imports

    if (imageOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
    {
        IMAGE_IMPORT_DESCRIPTOR* imageImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)(dllBaseAddress + imageOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (imageImportDesc->Name != 0)
        {
            char* moduleName = (char*)(dllBaseAddress + imageImportDesc->Name);
            HINSTANCE dllHandle = param->loadLibA(moduleName);

            // Load functions

            UINT_PTR* thunk = (UINT_PTR*)(dllBaseAddress + imageImportDesc->OriginalFirstThunk);
            UINT_PTR* func = (UINT_PTR*)(dllBaseAddress + imageImportDesc->FirstThunk);

            if (!thunk) { thunk = func; }

            while (*thunk)
            {
                if (IMAGE_SNAP_BY_ORDINAL(*thunk))
                {
                    *func = (UINT_PTR)param->getProcAddr(dllHandle, (char*)(*thunk & 0xFFFF));
                }
                else
                {
                    IMAGE_IMPORT_BY_NAME* imageImport = (IMAGE_IMPORT_BY_NAME*)(dllBaseAddress + (*thunk));
                    *func = (UINT_PTR)param->getProcAddr(dllHandle, imageImport->Name);
                }

                thunk++;
                func++;
            }

            imageImportDesc++;
        }
    }

    // TLS (Thread local storage) callbacks, these are functions that are set to call when a thread is created

    if (imageOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size != 0)
    {
        IMAGE_TLS_DIRECTORY* imageTlsDir = (IMAGE_TLS_DIRECTORY*)(dllBaseAddress + imageOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        PIMAGE_TLS_CALLBACK* tlsCallback = (PIMAGE_TLS_CALLBACK*)(imageTlsDir->AddressOfCallBacks);

        while (tlsCallback && *tlsCallback)
        {
            (*tlsCallback)(dllBaseAddress, DLL_PROCESS_ATTACH, nullptr);
            tlsCallback++;
        }
    }

    // call dll main

    _DLL_ENTRY_POINT dllMain = (_DLL_ENTRY_POINT)(dllBaseAddress + imageOptHeader->AddressOfEntryPoint);
    dllMain(dllBaseAddress, DLL_PROCESS_ATTACH, nullptr);

    param->succeeded = true;
}