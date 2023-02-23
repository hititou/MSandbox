#include <unicorn/unicorn.h>
#include "CMemManager.h"
#include "CPeLoader.h"
#include "CVmCpuEmulation.h"
#include "CVmcpu.h"

static int VMCodeExecFilter(uint64_t address, uint32_t size, const HookContext* pContext)
{
	static ULONGLONG g_ulRsp = 0;
	bool bBegin = false;
	if (g_ulRsp == 0)
	{
		bBegin = true;
		pContext->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RSP, (PVOID)&g_ulRsp);
	}

	ULONGLONG ulRsp = 0;
	pContext->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RSP, (PVOID)&ulRsp);
	std::cout << "VMCodeExecFilter->" << CW2A(pContext->HookModuleName.c_str()) << "\tBeginRSP: 0x" << std::hex << g_ulRsp <<
									"\tNowRsp: 0x" << std::hex << ulRsp << "\tRIP: 0x" << std::hex << address << "\n";

	if (!bBegin && g_ulRsp == ulRsp)
	{
		//std::cout << "g_ulRsp == ulRsp" << "\n";
		//pContext->pEItem->pvmCpu->VmEmulationStop();
	}
	return 0;
}

static int VMCodeAddrCoutPrintFilter(uint64_t address, uint32_t size, const HookContext* pContext)
{
	ULONGLONG ulParam1 = 0;
	if (pContext->pEItem->pFileinfo->BitType == BIT_TYPE_32)
	{
		ULONG ulEsp = 0;
		pContext->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		pContext->pEItem->pvmCpu->VmReadMemory((ULONGLONG)(ulEsp + 4), &ulParam1, 4);
	}
	else
	{
		pContext->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RDX, (PVOID)&ulParam1);
	}

	std::string printfStr;
	auto readVMString = [pContext, ulParam1](std::string &RetStr) -> void {
		char buf[2] = { 0 };
		ULONGLONG ulStrAddr = ulParam1;
		while (pContext->pEItem->pvmCpu->VmReadMemory(ulStrAddr, &buf[0], 1))
		{
			if (buf[0] == 0)
			{
				break;
			}
			RetStr += buf;
			buf[0] = 0;
			ulStrAddr += 1;
		}
	};
	readVMString(printfStr);

	std::cout << "VMCodeAddrCoutPrintFilter->" << CW2A(pContext->HookModuleName.c_str()) << "\tRIP: 0x" << std::hex << address << "\tprintfStr:" << printfStr.c_str()  << "\n";

	ULONGLONG NextRip = address + 5;
	if (pContext->pEItem->pFileinfo->BitType == BIT_TYPE_32)
	{
		pContext->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EIP, &NextRip);
	}
	else
	{
		pContext->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RIP, &NextRip);
	}
	return 0;
}


static int VMCodeAddrPrintfFilter(uint64_t address, uint32_t size, const HookContext* pContext)
{
	ULONGLONG ulParam1 = 0;
	if (pContext->pEItem->pFileinfo->BitType == BIT_TYPE_32)
	{
		ULONG ulEsp = 0;
		pContext->pEItem->pvmCpu->VmRegRead(UC_X86_REG_ESP, (PVOID)&ulEsp);
		pContext->pEItem->pvmCpu->VmReadMemory((ULONGLONG)ulEsp, &ulParam1, 4);
	}
	else
	{
		pContext->pEItem->pvmCpu->VmRegRead(UC_X86_REG_RCX, (PVOID)&ulParam1);
	}

	std::string printfStr;
	auto readVMString = [pContext, ulParam1](std::string &RetStr) -> void {
		char buf[2] = { 0 };
		ULONGLONG ulStrAddr = ulParam1;
		while (pContext->pEItem->pvmCpu->VmReadMemory(ulStrAddr, &buf[0], 1))
		{
			if (buf[0] == 0)
			{
				break;
			}
			RetStr += buf;
			buf[0] = 0;
			ulStrAddr += 1;
		}
	};
	readVMString(printfStr);

	std::cout << "VMCodeAddrPrintfFilter->" << CW2A(pContext->HookModuleName.c_str()) << "\tRIP: 0x" << std::hex << address << "\tprintfStr:" << printfStr.c_str() << "\n";

	ULONGLONG NextRip = address + 5;
	if (pContext->pEItem->pFileinfo->BitType == BIT_TYPE_32)
	{
		pContext->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_EIP, &NextRip);
	}
	else
	{
		pContext->pEItem->pvmCpu->VmRegWrite(UC_X86_REG_RIP, &NextRip);
	}
	return 0;
}

int main(int argc, char **argv, char **argevn)
{
	for (int i = 0; ; i++)
	{
		if (argevn[i] == NULL)
		{
			break;
		}
		printf("%s\n", argevn[i]);
	}

	if (argc < 2)
	{
		printf("usage: unicorn_pe (filename) [-p \"param1 param2\"]\n");
		return 0;
	}

	std::wstring wfilename = CA2W(argv[1]);
	std::wstring wparam;
	if (argc >= 4 && strcmp(argv[2], "-p") == 0)
	{
		wparam = CA2W(argv[3]);
	}
	else
	{
		wparam = L"";
	}

	CPELoader pefile;
	std::shared_ptr<sFileInfo> fileinfo = std::make_shared<sFileInfo>();
	if (!pefile.LoaderGetFileInfo(wfilename.c_str(), fileinfo))
	{
		printf("LoaderGetFileInfo false\n");
		return 0;
	}

	CVmCpuEmulation VmEngine;
	EmulationItem *pProcess = VmEngine.EmulationInit(wfilename, fileinfo->BitType == BIT_TYPE_32 ? L"C:/Windows/SysWOW64/" : L"c:/windows/system32/", wparam);
	if (pProcess)
	{
		HookHadle *pHooker86d0 = NULL;
		HookHadle *pHooker86d1 = NULL;

		HookHadle *pHooker64d0 = NULL;
		HookHadle *pHooker64d1 = NULL;

		
		//RunTest_x86D.exe
		VmEngine.EmulationAddAddressHook(pProcess, (ULONGLONG)0x41012683ul, (pCodeTraceCallback)VMCodeAddrCoutPrintFilter, NULL, &pHooker86d0);
		VmEngine.EmulationAddAddressHook(pProcess, (ULONGLONG)0x41012690ul, (pCodeTraceCallback)VMCodeAddrPrintfFilter, NULL, &pHooker86d1);
		
		//RunTest_x64D.exe
		VmEngine.EmulationAddAddressHook(pProcess, (ULONGLONG)0x1400125A8ull, (pCodeTraceCallback)VMCodeAddrCoutPrintFilter, NULL, &pHooker64d0);
		VmEngine.EmulationAddAddressHook(pProcess, (ULONGLONG)0x1400125B4ull, (pCodeTraceCallback)VMCodeAddrPrintfFilter, NULL, &pHooker64d1);


		VmEngine.EmulationStart(pProcess);

		VmEngine.EmulationDelHook(pHooker86d0);
		VmEngine.EmulationDelHook(pHooker86d1);
		VmEngine.EmulationDelHook(pHooker64d0);
		VmEngine.EmulationDelHook(pHooker64d1);


		VmEngine.EmulationStop(pProcess);

		//pProcess->pmemMgr->LOG(BIT_TYPE_32 == pProcess->pFileinfo->BitType);
		pProcess->PrintfFucntionCallLog();

		VmEngine.EmulationFree(pProcess);
		delete pProcess;
	}
	return 0;
}