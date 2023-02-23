#include "CVmApiHook.h"
#include <unicorn/unicorn.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <functional>
#include <vector>
#include <set>
#include <intrin.h>
#include <atlstr.h>
#include "CVmCpuEmulation.h"
#include "CVmcpu.h"
#include "CPeLoader.h"

//std::ostream *Hook_Outs;
#define LOG_HOOK_INFO(__FUNCNAME, __HCONTEXT, __RIP_ADDRESS) \
						std::cout << ""#__FUNCNAME"->" << CW2A(((const HookContext*)__HCONTEXT)->HookModuleName.c_str()) << "!" << \
						CW2A(((const HookContext*)__HCONTEXT)->HookFunctionName.c_str()) << "\tRIP: 0x" << std::hex << __RIP_ADDRESS << "\n";

#define COVER_HOOKCONTEXT(__CONTEXT) ((const HookContext*)__CONTEXT)


#define EMU_HOOK_FUCNTION_BODY_PASS(__NAME) \
						int WINAPI CVmApiHook::Emu##__NAME(ULONGLONG address, DWORD size, const PVOID pContext)\
						{\
							LOG_HOOK_INFO(Emu##__NAME, pContext, address);\
							return 0;\
						}

#define EMU_HOOK_FUCNTION_BODY(__NAME) int WINAPI CVmApiHook::Emu##__NAME(ULONGLONG address, DWORD size, const PVOID pContext)


EMU_HOOK_FUCNTION_BODY_PASS(__stdio_common_vfprintf);
EMU_HOOK_FUCNTION_BODY_PASS(printf)








//kernel api __stdcall
EMU_HOOK_FUCNTION_BODY(OutputDebugStringW)
{
	LOG_HOOK_INFO(EMU_HOOK_FUCNTION_NAME(OutputDebugStringW), pContext, address);
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		ULONGLONG rcx = 0;
		std::wstring wsString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&rcx);
		if (rcx != 0)
		{
			ReadWStringByAddress(pContext, rcx, wsString);
		}
		std::cout << "string:" << CW2A(wsString.c_str()) << "\n";
	}
	else
	{
		ULONG ulEsp = 0;
		std::wstring wsString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		if (ulEsp)
		{
			ULONGLONG ulParam = 0;  //只有一个参数
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 4), &ulParam, 4);
			ReadWStringByAddress(pContext, ulParam, wsString);
			std::cout << "string:" << CW2A(wsString.c_str()) << "\n";
		}
	}
	return 0;
}

//kernel api __stdcall 1个参数
/*
BOOL IsProcessorFeaturePresent(
   DWORD ProcessorFeature
);
*/
EMU_HOOK_FUCNTION_BODY(IsProcessorFeaturePresent)
{
	LOG_HOOK_INFO(EMU_HOOK_FUCNTION_NAME(IsProcessorFeaturePresent), pContext, address);
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		ULONGLONG rcx = 0;
		std::wstring wsString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&rcx);
		ULONGLONG rax = rcx == PF_XSAVE_ENABLED ? 0 : 1;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		ULONG ulEsp = 0;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		if (ulEsp)
		{
			ULONGLONG ulParam1 = 0;
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 4), &ulParam1, 4);
			ULONG eax = ulParam1 == PF_XSAVE_ENABLED ? 0 : 1;
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&eax);
		}
	}
	return 0;
}


//kernel api __stdcall
EMU_HOOK_FUCNTION_BODY(GetSystemTimeAsFileTime)
{
	FILETIME ft = { 0 };
	GetSystemTimeAsFileTime(&ft);
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		uint64_t rcx = 0;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&rcx);
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmWriteMemory(rcx, &ft, sizeof(FILETIME));
	}
	else
	{
		ULONG ulEsp = 0;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		if (ulEsp)
		{
			ULONGLONG ulParam = 0;  //只有一个参数
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 4), &ulParam, 4);
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmWriteMemory(ulParam, &ft, sizeof(FILETIME));
		}
	}

	LOG_HOOK_INFO(EmuGetSystemTimeAsFileTime, pContext, address);
	return 0;
}

//kernel api __stdcall
EMU_HOOK_FUCNTION_BODY(QueryPerformanceCounter)
{
	LARGE_INTEGER li = { 0 };
	BOOL ret = QueryPerformanceCounter(&li);
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		uint64_t rcx = 0;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&rcx);
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmWriteMemory(rcx, &li, sizeof(LARGE_INTEGER));
	}
	else
	{
		ULONG ulEsp = 0;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		int o = 0;
		if (ulEsp)
		{
			ULONGLONG ulParam = 0;  //只有一个参数
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 4), &ulParam, 4);
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmWriteMemory(ulParam, &li, sizeof(LARGE_INTEGER));
		}

	}
	LOG_HOOK_INFO(EmuQueryPerformanceCounter, pContext, address);
	return 0;
}


/*
HMODULE LoadLibraryA(
  [in] LPCSTR lpLibFileName
);
*/
EMU_HOOK_FUCNTION_BODY(LoadLibraryA)
{
	LOG_HOOK_INFO(EMU_HOOK_FUCNTION_NAME(LoadLibraryA), pContext, address);
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		ULONGLONG rax = 0;
		ULONGLONG rcx = 0;
		std::string szString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&rcx);
		if (rcx != 0)
		{
			ReadStringByAddress(pContext, rcx, szString);
		}
		printf("LoadLibraryA::Path:%s\n", szString.c_str());

		if (szString.size() > 0)
		{
			std::shared_ptr<sLoadModule> LoadModule = COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->LoaderLoadFileEx(CA2W(szString.c_str()), 
														COVER_HOOKCONTEXT(pContext)->pEItem, COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo);
			if (LoadModule != nullptr)
			{
				rax = LoadModule->ullLoadbase;

				printf("LoadLibraryA load sucess 0x%016I64x\n", rax);
			}
		}

		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		ULONG ulEax = 0;
		ULONG ulEsp = 0;
		std::string szString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		if (ulEsp)
		{
			ULONGLONG ulParam = 0;  //只有一个参数
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 4), &ulParam, 4);
			ReadStringByAddress(pContext, ulParam, szString);
			printf("LoadLibraryA::Path:%s\n", szString.c_str());

			if (szString.size() > 0)
			{
				std::shared_ptr<sLoadModule> LoadModule = COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->LoaderLoadFileEx(CA2W(szString.c_str()),
					COVER_HOOKCONTEXT(pContext)->pEItem, COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo);
				if (LoadModule != nullptr)
				{
					ulEax = (ULONG)LoadModule->ullLoadbase;

					printf("LoadLibraryA load sucess 0x%08x\n", ulEax);
				}
			}
		}
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&ulEax);
	}
	return 0;
}

/*
HMODULE LoadLibraryW(
  [in] LPCWSTR lpLibFileName
);
*/
EMU_HOOK_FUCNTION_BODY(LoadLibraryW)
{
	LOG_HOOK_INFO(EMU_HOOK_FUCNTION_NAME(LoadLibraryW), pContext, address);
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		ULONGLONG rax = 0;
		ULONGLONG rcx = 0;
		std::wstring wsString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&rcx);
		if (rcx != 0)
		{
			ReadWStringByAddress(pContext, rcx, wsString);
		}
		wprintf(L"LoadLibraryW::Path:%s\n", wsString.c_str());

		if (wsString.size() > 0)
		{
			std::shared_ptr<sLoadModule> LoadModule = COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->LoaderLoadFileEx(wsString.c_str(),
				COVER_HOOKCONTEXT(pContext)->pEItem, COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo);
			if (LoadModule != nullptr)
			{
				rax = LoadModule->ullLoadbase;

				printf("LoadLibraryW load sucess 0x%016I64x\n", rax);
			}
		}

		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		ULONG ulEax = 0;
		ULONG ulEsp = 0;
		std::wstring wsString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		if (ulEsp)
		{
			ULONGLONG ulParam = 0;  //只有一个参数
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 4), &ulParam, 4);
			ReadWStringByAddress(pContext, ulParam, wsString);
			wprintf(L"LoadLibraryW::Path:%s\n", wsString.c_str());

			if (wsString.size() > 0)
			{
				std::shared_ptr<sLoadModule> LoadModule = COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->LoaderLoadFileEx(wsString.c_str(),
					COVER_HOOKCONTEXT(pContext)->pEItem, COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo);
				if (LoadModule != nullptr)
				{
					ulEax = (ULONG)LoadModule->ullLoadbase;

					printf("LoadLibraryW load sucess 0x%08x\n", ulEax);
				}
			}
		}
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&ulEax);
	}
	return 0;
}


/*
HMODULE LoadLibraryExA(
  [in] LPCSTR lpLibFileName,
	   HANDLE hFile,
  [in] DWORD  dwFlags
);
*/
EMU_HOOK_FUCNTION_BODY(LoadLibraryExA)
{
	LOG_HOOK_INFO(EMU_HOOK_FUCNTION_NAME(LoadLibraryW), pContext, address);
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		ULONGLONG rax = 0;
		ULONGLONG rcx = 0;
		ULONGLONG rdx = 0;
		ULONGLONG r8 = 0;
		std::string szString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&rcx);
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RDX, (PVOID)&rdx);
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_R8, (PVOID)&r8);
		if (rcx != 0)
		{
			ReadStringByAddress(pContext, rcx, szString);
		}
		printf("LoadLibraryExA::hFile:0x%016I64x, dwFlags:0x%08x, lpLibFileName:%s\n", rdx, (ULONG)r8, szString.c_str());

		if (szString.size() > 0)
		{
			std::shared_ptr<sLoadModule> LoadModule = COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->LoaderLoadFileEx(CA2W(szString.c_str()),
				COVER_HOOKCONTEXT(pContext)->pEItem, COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo);
			if (LoadModule != nullptr)
			{
				rax = LoadModule->ullLoadbase;

				printf("LoadLibraryExA load sucess 0x%016I64x\n", rax);
			}
		}

		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		ULONG ulEax = 0;
		ULONG ulEsp = 0;
		std::string szString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		if (ulEsp)
		{
			ULONGLONG ulParam1 = 0;  //3个参数
			ULONGLONG ulParam2 = 0;  //3个参数
			ULONGLONG ulParam3 = 0;  //3个参数
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 0x4), &ulParam3, 4);
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 0x8), &ulParam2, 4);
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 0xC), &ulParam1, 4);
			ReadStringByAddress(pContext, ulParam1, szString);
			printf("LoadLibraryExA::hFile:0x%08x, dwFlags:0x%08x, lpLibFileName:%s\n", (ULONG)ulParam2, (ULONG)ulParam3, szString.c_str());

			if (szString.size() > 0)
			{
				std::shared_ptr<sLoadModule> LoadModule = COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->LoaderLoadFileEx(CA2W(szString.c_str()),
					COVER_HOOKCONTEXT(pContext)->pEItem, COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo);
				if (LoadModule != nullptr)
				{
					ulEax = (ULONG)LoadModule->ullLoadbase;

					printf("LoadLibraryExA load sucess 0x%08x\n", ulEax);
				}
			}
		}
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&ulEax);
	}
	return 0;
}

/*
HMODULE LoadLibraryExW(
  [in] LPCWSTR lpLibFileName,
	   HANDLE  hFile,
  [in] DWORD   dwFlags
);
*/
EMU_HOOK_FUCNTION_BODY(LoadLibraryExW)
{
	LOG_HOOK_INFO(EMU_HOOK_FUCNTION_NAME(LoadLibraryW), pContext, address);
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		ULONGLONG rax = 0;
		ULONGLONG rcx = 0;
		ULONGLONG rdx = 0;
		ULONGLONG r8 = 0;
		std::wstring wsString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&rcx);
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RDX, (PVOID)&rdx);
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_R8, (PVOID)&r8);
		if (rcx != 0)
		{
			ReadWStringByAddress(pContext, rcx, wsString);
			if (r8 & LOAD_LIBRARY_SEARCH_SYSTEM32)
			{
				if (_wcsnicmp(L"api-", wsString.c_str(), 4) == 0)
				{
					std::wstring tmp = COVER_HOOKCONTEXT(pContext)->pEItem->LoadPath[0];
					WCHAR wsMapToDll[MAX_PATH + 1] = { 0 };	
					COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->ApiSetpResolve(wsString.c_str(), NULL, wsMapToDll, MAX_PATH * sizeof(WCHAR));
					if (wcslen(wsMapToDll) > 0)
					{
						wsString = wsMapToDll;
					}
					tmp += wsString;
					wsString = tmp;
				}
			}
		}
		wprintf(L"LoadLibraryExW::hFile:0x%016I64x, dwFlags:0x%08x, lpLibFileName:%s\n", rdx, (ULONG)r8, wsString.c_str());

		if (wsString.size() > 0)
		{
			std::shared_ptr<sLoadModule> LoadModule = COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->LoaderLoadFileEx(wsString.c_str(),
				COVER_HOOKCONTEXT(pContext)->pEItem, COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo);
			if (LoadModule != nullptr)
			{
				rax = LoadModule->ullLoadbase;

				printf("LoadLibraryExW load sucess 0x%016I64x\n", rax);
			}
		}

		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		ULONG ulEax = 0;
		ULONG ulEsp = 0;
		std::wstring wsString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		if (ulEsp)
		{
			ULONGLONG ulParam1 = 0;  //3个参数
			ULONGLONG ulParam2 = 0;  //3个参数
			ULONGLONG ulParam3 = 0;  //3个参数
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 0x4), &ulParam3, 4);
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 0x8), &ulParam2, 4);
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 0xC), &ulParam1, 4);
			ReadWStringByAddress(pContext, ulParam1, wsString);
			wprintf(L"LoadLibraryExW::hFile:0x%08x, dwFlags:0x%08x, lpLibFileName:%s\n", (ULONG)ulParam2, (ULONG)ulParam3, wsString.c_str());

			if (wsString.size() > 0)
			{
				std::shared_ptr<sLoadModule> LoadModule = COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->LoaderLoadFileEx(wsString.c_str(),
					COVER_HOOKCONTEXT(pContext)->pEItem, COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo);
				if (LoadModule != nullptr)
				{
					ulEax = (ULONG)LoadModule->ullLoadbase;

					printf("LoadLibraryExW load sucess 0x%08x\n", ulEax);
				}
			}
		}
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&ulEax);
	}
	return 0;
}

/*
	FARPROC GetProcAddress(
		[in] HMODULE hModule,
		[in] LPCSTR  lpProcName
	);
*/
EMU_HOOK_FUCNTION_BODY(GetProcAddress)
{
	LOG_HOOK_INFO(EMU_HOOK_FUCNTION_NAME(GetProcAddress), pContext, address);
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		ULONGLONG rax = 0;
		ULONGLONG rcx = 0;
		ULONGLONG rdx = 0;
		std::string szString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&rcx);
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RDX, (PVOID)&rdx);
		if (rcx != 0)
		{
			ReadStringByAddress(pContext, rdx, szString);
		}
		printf("GetProcAddress::hModule:0x%016I64x, lpProcName:%s\n", rcx, szString.c_str());

		if (szString.size() > 0)
		{
			std::wstring wsFunctionName = CA2W(szString.c_str());
			rax = COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->GetMoudleExportFunctionAddrEx(COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo, rcx, wsFunctionName);
			printf("GetProcAddress 0x%016I64x\n", rax);
		}

		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		ULONG ulEax = 0;
		ULONG ulEsp = 0;
		std::string szString;
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		if (ulEsp)
		{
			ULONGLONG ulParam1 = 0;
			ULONGLONG ulParam2 = 0;
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 8), &ulParam1, 4);
			COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 4), &ulParam2, 4);
			ReadStringByAddress(pContext, ulParam2, szString);
			printf("GetProcAddress::hModule:0x%08x, lpProcName:%s\n", (ULONG)ulParam1, szString.c_str());

			if (szString.size() > 0)
			{
				std::wstring wsFunctionName = CA2W(szString.c_str());
				ulEax = (ULONG)COVER_HOOKCONTEXT(pContext)->pEItem->pLoader->GetMoudleExportFunctionAddrEx(COVER_HOOKCONTEXT(pContext)->pEItem->pModulesInfo, ulParam1, wsFunctionName);
				printf("GetProcAddress 0x%08x\n", (ULONG)ulParam1);
			}
		}
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&ulEax);
	}
	return 0;
}


EMU_HOOK_FUCNTION_BODY(_initterm_e)
{
	DWORD64 rax = 0;
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&rax);
	}
	LOG_HOOK_INFO(Emu_initterm_e, pContext, address);
	return 0;
}

//_cdecl
EMU_HOOK_FUCNTION_BODY(_initterm)
{
	LOG_HOOK_INFO(Emu_initterm, pContext, address);
	return 0;
}

//_cdecl
EMU_HOOK_FUCNTION_BODY(_get_initial_narrow_environment)
{
	assert(COVER_HOOKCONTEXT(pContext)->pEItem->vmParamEvnInfo.ullEnvAddr != 0);
	DWORD64 rax = COVER_HOOKCONTEXT(pContext)->pEItem->vmParamEvnInfo.ullEnvAddr;
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&rax);
	}
	LOG_HOOK_INFO(Emu_get_initial_narrow_environment, pContext, address);
	return 0;
}

//_cdecl
EMU_HOOK_FUCNTION_BODY(__p___argc)
{
	assert(COVER_HOOKCONTEXT(pContext)->pEItem->vmParamEvnInfo.ullArgcAddr != 0);
	DWORD64 rax = COVER_HOOKCONTEXT(pContext)->pEItem->vmParamEvnInfo.ullArgcAddr;
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&rax);
	}
	LOG_HOOK_INFO(Emu__p___argc, pContext, address);
	return 0;
}

//_cdecl
EMU_HOOK_FUCNTION_BODY(__p___argv)
{
	assert(COVER_HOOKCONTEXT(pContext)->pEItem->vmParamEvnInfo.ullArgvAddr != 0);
	DWORD64 rax = COVER_HOOKCONTEXT(pContext)->pEItem->vmParamEvnInfo.ullArgvAddr;
	if (COVER_HOOKCONTEXT(pContext)->pEItem->pFileinfo->BitType == BIT_TYPE_64)
	{
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RAX, (PVOID)&rax);
	}
	else
	{
		COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EAX, (PVOID)&rax);
	}
	LOG_HOOK_INFO(Emu__p___argv, pContext, address);
	return 0;
}

//_cdecl
EMU_HOOK_FUCNTION_BODY(exit)
{
	LOG_HOOK_INFO(Emuexit, pContext, address);
	COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmEmulationStop();
	return 0;
}



EMU_HOOK_FUCNTION_BODY(TlsAlloc)
{
	return 0;
}

EMU_HOOK_FUCNTION_BODY(TlsSetValue)
{
	return 0;
}

EMU_HOOK_FUCNTION_BODY(TlsGetValue)
{
	return 0;
}

EMU_HOOK_FUCNTION_BODY(TlsFree)
{
	return 0;
}


int CVmApiHook::ReadStringByAddress(const PVOID pContext, ULONGLONG ulAddress, std::string &RetString)
{
	char buf[2] = { 0 };
	ULONGLONG ulStrAddr = ulAddress;
	RetString = "";
	while (COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory(ulStrAddr, &buf[0], 1))
	{
		if (buf[0] == 0)
		{
			break;
		}
		RetString += buf;
		buf[0] = 0;
		ulStrAddr += 1;
	}
	return (int)RetString.length();
}

int CVmApiHook::ReadWStringByAddress(const PVOID pContext, ULONGLONG ulAddress, std::wstring &RetString)
{
	WCHAR buf[2] = { 0 };
	ULONGLONG ulStrAddr = ulAddress;
	RetString = L"";
	while (COVER_HOOKCONTEXT(pContext)->pEItem->pvmCpu->VmReadMemory(ulStrAddr, &buf[0], sizeof(WCHAR)))
	{
		if (buf[0] == 0)
		{
			break;
		}
		RetString += buf;
		buf[0] = 0;
		ulStrAddr += sizeof(WCHAR);
	}
	return (int)RetString.length();
}