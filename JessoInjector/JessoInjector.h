#pragma once

#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>

using _LoadLibraryA = HINSTANCE(WINAPI*)(const char* dllPath);
using _GetProcAddress = FARPROC(WINAPI*)(HINSTANCE moduleHandle, const char* procName);
using _DLL_ENTRY_POINT = BOOL(WINAPI*)(void* dllHandle, DWORD reason, void* reserved);

bool InjectByLoadLibraryA(HANDLE procHandle, const char* dllPath);

bool InjectByManuallyMapping(HANDLE procHandle, const char* dllPath);

struct InternalManualMapParameter
{
	char* dllBaseAddress;
	_LoadLibraryA loadLibA; 
	_GetProcAddress getProcAddr;
	bool succeeded;
};

void __stdcall InternalManualMapCode(InternalManualMapParameter* param);