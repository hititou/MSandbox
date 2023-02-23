#pragma once
#include "WinComm.h"
#include <unicorn/unicorn.h>


struct sHeapStackSpace
{
	ULONGLONG ullBase;
	DWORD dwSize;
};


class CVmcpu;
class CWinMemManager;
class CPELoader;
struct sLoadModule;
struct sFileInfo;
struct sVmCpuRegContext;


struct ThreadInfoItem
{
	ThreadInfoItem()
	{
		ThreadID = 0;
		ullTebAddress = 0;
		dwTlsIndex = 0;
		dwFlsIndex = 0;
		ulTlsVmAddr = 0;
		ulFlsVmAddr = 0;
		bMainThread = 0;
		ullStackBase = 0;
		dwStackSize = 0;
		ullRunEntry = 0;
	}
	DWORD ThreadID;
	ULONGLONG ullTebAddress;

	//tls fls
#define TLS_FLS_COUNT 4096
	DWORD dwTlsIndex;
	DWORD dwFlsIndex;
	ULONGLONG ulTlsVmAddr;
	ULONGLONG ulFlsVmAddr;

	byte bMainThread;
	ULONGLONG ullStackBase;
	DWORD dwStackSize;

	ULONGLONG ullRunEntry;


};

struct ParamEvnInfo
{
	ParamEvnInfo()
	{
		ullArgcAddr = 0;
		ullArgvAddr = 0;
		ullEnvAddr = 0;
	};
	ULONGLONG ullArgcAddr;
	ULONGLONG ullArgvAddr;
	ULONGLONG ullEnvAddr;
};

struct vFucntionCallItem
{
	std::wstring wsModuleName;
	std::wstring wsFunction;
	ULONGLONG ullAddress;
};


#define PROCESS_ID 64
struct EmulationItem
{
	EmulationItem() 
	{
		pvmCpu = NULL;
		pmemMgr = NULL;
		pLoader = NULL;
		pFileinfo = NULL;
		pModulesInfo = NULL;
		pRegInfo = NULL;
		ullMainStackBase = 0;
		dwStackSize = 0;
		ullReserveHeapBase = 0;
		dwReserveHeapSize = 0;
		uMemUnMapedTrace = 0;
		uMemUnReadWriteTrace = 0;
		uCodeTrace = 0;
		uIntTrace = 0;
		ullCapstone = 0;
		ulStartAddress = 0;
		LastException = 0;
		ullPebAddress = 0;
		dwProcessID = PROCESS_ID;
		dwThreadIDIndex = PROCESS_ID;
		dwMainThreadID = 0;
		ullGdtAddress = 0;

	};
	std::shared_ptr<CVmcpu> pvmCpu;
	std::shared_ptr<CWinMemManager> pmemMgr;
	std::shared_ptr<CPELoader> pLoader;
	//默认路径
	std::vector<std::wstring> LoadPath;
	//环境变量
	std::vector<std::wstring> Environments;
	//参数
	std::vector<std::wstring> Param;
	ParamEvnInfo vmParamEvnInfo;
	
	std::shared_ptr<sFileInfo> pFileinfo;
	//模块信息
	std::shared_ptr<sLoadModule> pModulesInfo;
	//寄存器信息
	std::shared_ptr<sVmCpuRegContext> pRegInfo;

	//根据模块选择的GDT地址
	ULONGLONG ullGdtAddress;

	//heap stack info
	std::list<sHeapStackSpace> heaps;  //堆范围
	std::list<sHeapStackSpace> stacks; //stack范围
	ULONGLONG ullMainStackBase;
	DWORD dwStackSize;
	ULONGLONG ullReserveHeapBase;
	DWORD dwReserveHeapSize;
	ULONGLONG ulStartAddress;
	ULONGLONG ulEndAddress;

	DWORD dwProcessID;
	DWORD dwMainThreadID;
	ULONGLONG ullPebAddress;

	LONG LastException;

	uc_hook uMemUnMapedTrace;
	uc_hook uMemUnReadWriteTrace;
	uc_hook uCodeTrace;
	uc_hook uIntTrace;

	ULONGLONG ullCapstone;

#define THREADID_STEP 8
	DWORD dwThreadIDIndex;
	DWORD AllocThreadID()
	{
		dwThreadIDIndex += THREADID_STEP;
		return dwThreadIDIndex;
	};
#define MAP_THREAS std::map<DWORD, std::shared_ptr<ThreadInfoItem>>
	MAP_THREAS mThreads;


	//Fucntion Call Log
	std::vector<vFucntionCallItem> FucntionCallLog;
	void PrintfFucntionCallLog()
	{
		std::cout << "\n============Function Call Log==============\n";
		for (std::vector<vFucntionCallItem>::const_iterator iter = FucntionCallLog.begin(); iter != FucntionCallLog.end(); ++iter)
		{
			//std::cout << "module: " << CW2A(iter->wsModuleName.c_str()) << ",\t\tFunction: " << CW2A(iter->wsFunction.c_str()) << ",\t\tAddress: 0x" << std::hex << iter->ullAddress << "\n";

			wprintf(L"module:%-16s  Function:%-40s  Address:0x%016I64x\n", iter->wsModuleName.c_str(), iter->wsFunction.c_str(), iter->ullAddress);
		}
		std::cout << "============Function Call Log==============\n";
	};
};


struct HookContext
{
	HookContext()
	{
		pContext = NULL;
		pEItem = NULL;
		HookModuleName = L"";
		HookFunctionName = L"";
	};
	PVOID pContext;
	EmulationItem *pEItem;
	std::wstring HookModuleName;
	std::wstring HookFunctionName;
	ULONGLONG ulFunctionAddr;
};

struct HookHadle
{
#define FIX_ORG_CODE_COUNT 16
	HookHadle()
	{
		uc_Hooker = 0;
		pCallback = NULL;
		dwFlag = 0;
		FixByteCount = 0;
		CallType = 0;
		ArgCount = 0;
		memset(FixOrgCode, 0, FIX_ORG_CODE_COUNT);
	};
	DWORD dwFlag;
	byte CallType;
	byte ArgCount;
	byte FixByteCount;
	byte FixOrgCode[FIX_ORG_CODE_COUNT];
	ULONGLONG uc_Hooker;
	PVOID pCallback;
	HookContext Context;
};

typedef int (WINAPI *pCodeTraceCallback)(ULONGLONG address, DWORD size, const HookContext* pContext);


class CVmCpuEmulation
{
public:
	CVmCpuEmulation();
	~CVmCpuEmulation();


	EmulationItem *EmulationInit(std::wstring wsFilePath, std::wstring wsRootPath, std::wstring wsParam);
	bool EmulationStart(EmulationItem *pEItem);
	bool EmulationStop(EmulationItem *pEItem);
	bool EmulationFree(EmulationItem *pEItem);

	/*
	dwHookFlag : 1 Filter模式
	dwHookFlag : 2 Hook模式
	*/
#define FUNCTION_NAME_HOOK_FLAG_FILTER       0x1
#define FUNCTION_NAME_HOOK_FLAG_HOOK_RETURN  0x2
	/*
	FuncCallType
	//CALL TYPE
	*/
#define FUNC_CALL_TYPE_STDCALL  1
#define FUNC_CALL_TYPE_CDECL    2
#define FUNC_CALL_TYPE_FASTCALL 3
	//函数hook
	bool EmulationAddFunctionHook(EmulationItem *pEItem, const WCHAR *wsModuleName, const WCHAR *wsFunctionName, byte FuncCallType, byte bArgCount,
									pCodeTraceCallback pCallBack, PVOID pContext, OUT HookHadle **pRetHooker, DWORD dwHookFlag);
	//地址hook
	bool EmulationAddAddressHook(EmulationItem *pEItem, ULONGLONG ullHookAddress, pCodeTraceCallback pCallBack, PVOID pContext, OUT HookHadle **pRetHooker);
	//代码执行回调
	bool EmulationAddExecCodeHook(EmulationItem *pEItem, pCodeTraceCallback pCallBack, PVOID pContext, OUT HookHadle **pRetHooker);


	bool EmulationDelHook(HookHadle *pRetHooker);


	

	std::shared_ptr<ThreadInfoItem> EmulationCreateThreadTeb(EmulationItem *pEItem, ULONGLONG ulRunEntry, bool bMainThread);

	DWORD GetCurrentThreadID(EmulationItem *pEItem);

	std::shared_ptr<ThreadInfoItem> GetThreadInfo(EmulationItem *pEItem, DWORD dwThreadID);

private:

	bool InitlizeProcess(EmulationItem *pEmulContext);
	bool InitlizePebTeb(EmulationItem *pEmulContext);
	bool InitKernelSharedUserData(EmulationItem *pEmulContext);
	bool InitlizeVCpuRegister(EmulationItem *pEmulContext);
	bool InitlizeHook(EmulationItem *pEmulContext);

	bool InitlizePramEvnInfo(EmulationItem *pEmulContext, std::wstring &peFilePath, std::wstring &param);

	bool InitlizeFunctionHook(EmulationItem * pEmulContext);
	bool UnInitlizeFunctionHook();

	std::vector<HookHadle *> m_FuncHookHadle;
};

