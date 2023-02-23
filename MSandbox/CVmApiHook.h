#pragma once
#include "WinComm.h"

#define EMU_HOOK_FUCNTION_NAME(__NAME) Emu##__NAME
#define EMU_HOOK_FUCNTION_DEF(__NAME) static int WINAPI EMU_HOOK_FUCNTION_NAME(__NAME)(ULONGLONG address, DWORD size, const PVOID pContext)

struct EmulationItem;
class CVmApiHook
{
public:
	EMU_HOOK_FUCNTION_DEF(GetSystemTimeAsFileTime);
	EMU_HOOK_FUCNTION_DEF(QueryPerformanceCounter);
	EMU_HOOK_FUCNTION_DEF(_initterm_e);
	EMU_HOOK_FUCNTION_DEF(_initterm);
	EMU_HOOK_FUCNTION_DEF(_get_initial_narrow_environment);
	EMU_HOOK_FUCNTION_DEF(__p___argv);
	EMU_HOOK_FUCNTION_DEF(__p___argc);
	EMU_HOOK_FUCNTION_DEF(exit);
	EMU_HOOK_FUCNTION_DEF(printf);
	EMU_HOOK_FUCNTION_DEF(OutputDebugStringW);
	EMU_HOOK_FUCNTION_DEF(__stdio_common_vfprintf);
	EMU_HOOK_FUCNTION_DEF(IsProcessorFeaturePresent);


	EMU_HOOK_FUCNTION_DEF(LoadLibraryA);
	EMU_HOOK_FUCNTION_DEF(LoadLibraryW);
	EMU_HOOK_FUCNTION_DEF(LoadLibraryExA);
	EMU_HOOK_FUCNTION_DEF(LoadLibraryExW);
	EMU_HOOK_FUCNTION_DEF(GetProcAddress);


	
	EMU_HOOK_FUCNTION_DEF(TlsAlloc);
	EMU_HOOK_FUCNTION_DEF(TlsSetValue);
	EMU_HOOK_FUCNTION_DEF(TlsGetValue);
	EMU_HOOK_FUCNTION_DEF(TlsFree);


	static int ReadStringByAddress(const PVOID pContext, ULONGLONG ulAddress, std::string &RetString);
	static int ReadWStringByAddress(const PVOID pContext, ULONGLONG ulAddress, std::wstring &RetString);

};

