#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <fstream>

using _LoadLibraryA = HINSTANCE(WINAPI*)(const char* dllPath);
using _GetProcAddress = FARPROC(WINAPI*)(HINSTANCE moduleHandle, const char* procName);

using _DLL_ENTRY_POINT = BOOL(WINAPI*)(void* dllHandle, DWORD reason, void* reserved);

bool FreezeAllThreads(HANDLE procHandle, bool resume);

HANDLE GetFirstThread(HANDLE procHandle);

bool InjectByLoadLibraryA(HANDLE procHandle, const char* dllPath);

bool InjectByThreadHijack(HANDLE procHandle, const char* dllPath, int threadId);

bool InjectByManuallyMapping(HANDLE procHandle, const char* dllPath, bool hijackThread, int threadId);

struct InternalManualMapParameter
{
	char* dllBaseAddress;
	_LoadLibraryA loadLibA; 
	_GetProcAddress getProcAddr;
	bool succeeded;
};

void __stdcall InternalManualMapCode(InternalManualMapParameter* param);