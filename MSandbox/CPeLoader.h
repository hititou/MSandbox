#pragma once
#include "WinComm.h"
#include <unicorn/unicorn.h>



struct sSectionInfo
{
	sSectionInfo()
	{
		ullSectionBase = 0;
		dwSizeOfRawData = 0;
		dwVirtualSize = 0;
		dwAlignSectionSize = 0;
		dwCharacteristics = 0;
		memset(SectionName, 0, 9);
	}
	ULONGLONG ullSectionBase;
	DWORD dwSizeOfRawData;
	DWORD dwVirtualSize;
	DWORD dwAlignSectionSize;  // align VirtualSize
	DWORD dwCharacteristics;
	CHAR SectionName[9];
};


struct sFunctionInfo
{
	sFunctionInfo() {
		ullFunctionAddr = 0;
	};
	std::wstring name;
	ULONGLONG ullFunctionAddr;
};

struct sExportFunction : public sFunctionInfo
{
	sExportFunction()
	{
		IsMap = false;
		MapToModule = L"";
		MapToFunction = L"";
	}
	byte IsMap;
	std::wstring MapToModule;
	std::wstring MapToFunction;

	sExportFunction& operator=(sExportFunction& other)
	{
		name = other.name;
		ullFunctionAddr = other.ullFunctionAddr;
		IsMap = other.IsMap;
		MapToModule = other.MapToModule;
		MapToFunction = other.MapToFunction;
		return *this;
	};

};

//导出表
struct sExportTableInfo
{
	sExportTableInfo() {};
	std::map<ULONGLONG, std::wstring> FunaddrToName;
	std::vector<sExportFunction> FNameToAddr;
	std::map<ULONG, ULONGLONG> FuncExportNum;//通过序号导出的函授
};

//导入表
struct sImportTableInfo
{
	sImportTableInfo() 
	{
		ImportName = L"";
		MapToDllName = L"";
	};
	std::wstring ImportName;
	std::wstring MapToDllName;    //api-ms-类的dll map真是的物理dll
	std::map<ULONGLONG, std::wstring> FunaddrToName;
	std::vector<sFunctionInfo> FNameToAddr;
};


//一个pe模块
struct sLoadModule
{
	sLoadModule() {
		ullLoadbase   = 0;
		dwImageSize   = 0;
		ullImageEntry = 0;
		dwPriority    = 0;
		ullExceptionTable = 0;
		dwExceptionTableSize = 0;
		filePath = L"";
		name = L"";
		wsParam = L"";
		IsLoading = false;
		pMemoryAddress = NULL;
	};
	std::wstring name;            //模块名
	std::wstring filePath;        //路径
	std::wstring wsParam;         //参数
	bool IsLoading;
	ULONGLONG ullLoadbase;        //VCPU加载基地址
	DWORD dwImageSize;            //镜像大小
	ULONGLONG ullImageEntry;      //入口地址
	DWORD dwPriority;             //加载层次
	ULONGLONG ullExceptionTable;  
	DWORD dwExceptionTableSize;
	std::vector<sSectionInfo> vSections;   //session表
	std::vector<sImportTableInfo> vImportModules;  //导入模块函数
	std::vector<std::wstring> vExportApiDependModule; //有些到处函数转发到其他模块， 需要加载
	sExportTableInfo ExportApis;

	std::list<std::shared_ptr<sLoadModule>> vDependModules; //依赖模块 

	PVOID pMemoryAddress;

	void LoadModuleLog()
	{
		wprintf(L"\n=================Load Module Info====================\n");
		wprintf(L"Priority:%d, Name:%-20s Param:\"%10s\"    Filepath:%-50s\n", dwPriority, name.c_str(), wsParam.c_str(), filePath.c_str());
		wprintf(L"ullLoadbase:0x%016I64x,\tdwImageSize:0x%08x\n", ullLoadbase, dwImageSize);
		for (std::vector<sSectionInfo>::const_iterator iter = vSections.begin(); iter != vSections.end(); ++iter)
		{
			printf("Section:%-10s  Base:0x%016I64x, \tSizeOfRawData:0x%08x \tAlignSectionSize:0x%08x, \tCharacteristics:0x%08x\n", 
				iter->SectionName, iter->ullSectionBase, iter->dwSizeOfRawData, iter->dwAlignSectionSize, iter->dwCharacteristics);
		}
		wprintf(L"\n");
		for (std::vector<sImportTableInfo>::const_iterator iter = vImportModules.begin(); iter != vImportModules.end(); ++iter)
		{
			for (std::vector<sFunctionInfo>::const_iterator iter2 = iter->FNameToAddr.begin(); iter2 != iter->FNameToAddr.end(); ++iter2)
			{
				wprintf(L"ImportModule:%-20s  Function:%-40s  Address: 0x%016I64x\n", iter->ImportName.c_str(), iter2->name.c_str(), iter2->ullFunctionAddr);
			}
		}
		wprintf(L"\n");
		for (std::vector<sExportFunction>::const_iterator iter = ExportApis.FNameToAddr.begin(); iter != ExportApis.FNameToAddr.end(); ++iter)
		{
			wprintf(L"ExportModule:%-20s  Function:%-40s  Address: 0x%016I64x\n", name.c_str(), iter->name.c_str(), iter->ullFunctionAddr);
		}
		if (dwPriority == 0)
		{
			wprintf(L"MainModule:%-20s  DependModuleCount:%d,\tBase:0x%016I64x,\tEntryPoint: 0x%016I64x,\tSize:0x%08x,\tPriority:%d\n", 
														name.c_str(), (DWORD)vDependModules.size(), ullLoadbase, ullImageEntry, dwImageSize, dwPriority);
			for (std::list<std::shared_ptr<sLoadModule>>::const_iterator iter = vDependModules.begin(); iter != vDependModules.end(); ++iter)
			{
				wprintf(L"Module:%-20s  DependModule:%-20s  Base:0x%016I64x,\tEntryPoint:0x%016I64x,\tSize:0x%08x,\tPriority:%d\n", 
					name.c_str(), (*iter)->name.c_str(), (*iter)->ullLoadbase, (*iter)->ullImageEntry, (*iter)->dwImageSize, (*iter)->dwPriority);
			}
		}
		wprintf(L"=================Load Module Info====================\n");
	}

	struct sModuleInfo
	{
		sModuleInfo()
		{
			name = L"";
			ullLoadbase = 0;
			dwImageSize = 0;
			ExportFunctionName = L"";
			memset(SectionName, 0, 9);
		}
		std::wstring name;
		ULONGLONG ullLoadbase;
		DWORD dwImageSize;
		std::wstring ExportFunctionName;
		char SectionName[9];
	};
	bool GetModuleNameByAddress(ULONGLONG ulAddress, sModuleInfo &info)
	{

		auto FindSection = [this](ULONGLONG ulAddress) -> const CHAR * {
			for (std::vector<sSectionInfo>::const_iterator iter = vSections.begin(); iter != vSections.end(); ++iter)
			{
				if (ulAddress >= iter->ullSectionBase && ulAddress <= iter->ullSectionBase + iter->dwAlignSectionSize)
				{
					return iter->SectionName;
				}
			}

			return ""; 
		};
		
		info.ExportFunctionName = L"";
		info.SectionName[0] = 0;
		if (ulAddress > ullLoadbase && ulAddress < ullLoadbase + dwImageSize)
		{
			info.name = name;
			info.ullLoadbase = ullLoadbase;
			info.dwImageSize = dwImageSize;
			std::map<ULONGLONG, std::wstring>::const_iterator iter = ExportApis.FunaddrToName.find(ulAddress);
			if (iter != ExportApis.FunaddrToName.end())
			{
				info.ExportFunctionName = iter->second;
			}

			strncpy(info.SectionName, FindSection(ulAddress), 8);
			return true;
		}

		for (std::list<std::shared_ptr<sLoadModule>>::const_iterator iter = vDependModules.begin(); iter != vDependModules.end(); ++iter)
		{
			if (ulAddress >= (*iter)->ullLoadbase && ulAddress <= (*iter)->ullLoadbase + (*iter)->dwImageSize)
			{
				std::map<ULONGLONG, std::wstring>::const_iterator iter2 = (*iter)->ExportApis.FunaddrToName.find(ulAddress);
				if (iter2 != (*iter)->ExportApis.FunaddrToName.end())
				{
					info.ExportFunctionName = iter2->second;
				}
				info.name = (*iter)->name;
				info.ullLoadbase = (*iter)->ullLoadbase;
				info.dwImageSize = (*iter)->dwImageSize;
				strncpy(info.SectionName, FindSection(ulAddress), 8);
				return true;
			}
		}

		info.name = L"UnKnowModule";
		info.ullLoadbase = 0;
		info.dwImageSize = 0;
		return false;
	}
};



enum OsSystemType
{
	em_windows_pe = 1,
	em_linux_elf,
	em_android_elf,
	em_no_sport,
};
#define BIT_TYPE_16 1
#define BIT_TYPE_32 2
#define BIT_TYPE_64 3

#define FILE_TYPE_EXEC        1  //pe，elf可执行文件
#define FILE_TYPE_DYNAMIC     2  //so, dll文件
#define FILE_TYPE_KERNEL_SYS  3  //sys文件

struct sFileInfo
{
	sFileInfo()
	{
		arch = uc_arch::UC_ARCH_MAX;
		osType = OsSystemType::em_no_sport;
		BitType = 0;
		FileType = 0;
	}
	uc_arch arch;
	OsSystemType osType;
	BYTE BitType;
	BYTE FileType;
};


struct sVMMemWriteInfo
{
	sVMMemWriteInfo()
	{
		uladdr = 0;
		a.ul64bitValue = 0;
		dwSize = 0;

	}
	ULONGLONG uladdr;
	union
	{
		ULONG ul32bitValue;
		ULONGLONG ul64bitValue;
	}a;
	DWORD dwSize;
};


struct EmulationItem;
class CVmcpu;
class CPELoader
{
public:
	CPELoader();
	~CPELoader();

	bool LoaderGetFileInfo(const WCHAR *filename, std::shared_ptr<sFileInfo> fInfo);
	
	ULONGLONG GetMoudleExportFunctionAddr(std::shared_ptr<sLoadModule> &MainModule, std::wstring &wsModuleName, std::wstring &wsFunctionName);

	ULONGLONG GetMoudleExportFunctionAddrEx(std::shared_ptr<sLoadModule> &MainModule, ULONGLONG ulModuleBase, std::wstring &wsFunctionName);

	PVOID GetApiSetData(DWORD *dwRetSize);

	std::shared_ptr<sLoadModule> CPELoader::LoaderLoadFileEx(const WCHAR *filename, EmulationItem *pEItem, std::shared_ptr<sLoadModule> &MainModule);
	
	bool ApiSetpResolve(const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen);
private:
	std::shared_ptr<sLoadModule> LoaderLoadSingleModuleNaked(const WCHAR *filename, DWORD dwPriority, EmulationItem *pEItem);
	std::shared_ptr<sLoadModule> CPELoader::LoaderLoadAllModuleNaked(const WCHAR *filename, DWORD dwPriority, EmulationItem *pEItem, std::shared_ptr<sLoadModule> &MainModule);
	bool LoaderLoadDependModules(std::shared_ptr<sLoadModule> &pMainModule, EmulationItem *pEItem, DWORD dwPriority, std::shared_ptr<sLoadModule> &pModule);
	bool LoaderLoadFixEatIatSectionPost(std::shared_ptr<sLoadModule> &MainModule, std::shared_ptr<sLoadModule> &LoadingModule, EmulationItem *pEItem);

	PVOID LoadImageFile(const WCHAR *filename, ULONGLONG *pulFileSize);
	int PeloaderCheckNtHeader(IMAGE_NT_HEADERS *pNtheader);
	bool GetPeHeadInfo(PVOID pBase, PIMAGE_NT_HEADERS *ppNtHead, PIMAGE_SECTION_HEADER *ppSectionHead);
	ULONGLONG GetTotalImageSize(PVOID pFileBase, ULONGLONG ulFilesize);

	ULONGLONG GetExportFuncAddressNoMap(std::wstring &wsModuleName, std::wstring &wsFunctionName, std::shared_ptr<sLoadModule> &MainModule, OUT std::wstring &RetMapModule);
	ULONGLONG GetExportFuncAddressByNumberNoMap(std::wstring &wsModuleName, DWORD dwIndex, std::shared_ptr<sLoadModule> &MainModule, OUT std::wstring &RetMapModule);
	DWORD GetPeExportsPre(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, std::shared_ptr<sLoadModule> &pLoadModule, OUT std::vector<std::wstring> &vDependModule);
	bool GetPeExportsPost(std::shared_ptr<sLoadModule> &pLoadModule, std::shared_ptr<sLoadModule> &MainModule);
	DWORD GetPeImportsModules(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, BYTE bitType, std::vector<sImportTableInfo> &IatTables);
	DWORD GetImportsApi(PVOID pImageBase, DWORD dwsize, BYTE bitType, PIMAGE_IMPORT_DESCRIPTOR pDirent, std::vector<sFunctionInfo> &vNameFunctions);

	bool CheckModuleLoaded(const WCHAR *wsModuleName, std::shared_ptr<sLoadModule> &MainModule);

	bool GetFixUpImageReloc(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, OUT std::vector<sVMMemWriteInfo> &vRelocInfo);
	
	std::shared_ptr<sLoadModule> GetDependModule(const std::list<std::shared_ptr<sLoadModule>> &vDepend, std::wstring &wsName);
	bool GetFunctionInfoByName(const sExportTableInfo &ExportApis, const std::wstring &wsFunctionName, OUT sExportFunction &RetResult);
	ULONGLONG GetFunctionByName(const sExportTableInfo &ExportApis, const std::wstring &wsFunctionName);
	ULONGLONG GetFunctionByNumber(const sExportTableInfo &ExportApis, ULONG dwIndex);
	bool GetModuleIATAddr(const std::list<std::shared_ptr<sLoadModule>> &vDepends, std::shared_ptr<sLoadModule> &pLoadingModule);
	bool GetFixUpImageIAT(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, const std::vector<sImportTableInfo>& vImportModules, OUT std::vector<sVMMemWriteInfo> &vIATFuncInfo);

	inline BYTE GetPeImagesBits(PIMAGE_NT_HEADERS pNtHead);
	inline bool WriteVmMemory(const std::shared_ptr<CVmcpu> &pVmCpu, const std::vector<sVMMemWriteInfo> &vWriteInfo);

	//kernel driver need
	bool InitModuleSecurityCookie(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, const std::shared_ptr<CVmcpu> &pVmCpu);

	//api Set
	PVOID m_ApiSetData;
	DWORD m_dwApiSetDataSize;
	
	bool ApiSetResolveToHostV6(PVOID ApiSetMap, const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen);
	PVOID ApiSetpSearchForApiSetV6(PVOID ApiSetMap, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength);
	PVOID ApiSetpSearchForApiSetHostV6(PVOID ApiSetEntry, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength, PVOID ApiSetNamespace);
	bool ApiSetResolveToHostV4(PVOID ApiSetMap, const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen);
	PVOID ApiSetpSearchForApiSetV4(PVOID ApiSetNamespace, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength);
	PVOID ApiSetpSearchForApiSetHostV4(PVOID ApiSetVEntry, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength, PVOID ApiSetNamespace);
	bool ApiSetResolveToHostV3(PVOID ApiSetMap, const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen);
	PVOID ApiSetpSearchForApiSetHostV3(PVOID ApiSetValueArray, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength, PVOID ApiSetNamespace);
	bool ApiSetResolveToHostV2(PVOID ApiSetMap, const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen);
	PVOID ApiSetpSearchForApiSetHostV2(PVOID ApiSetValueArray, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength, PVOID ApiSetNamespace);
	bool CheckApiSetMap(const WCHAR *wsMsDll);
};