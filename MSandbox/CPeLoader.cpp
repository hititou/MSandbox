#include "CPeLoader.h"
#include <stdlib.h>
#include <atlstr.h>
#include <algorithm>
#include <string>
#include "CVmCpuEmulation.h"
#include "CMemManager.h"
#include "CVmcpu.h"

#define IMPORT_NUM_DEFAULT_NAME L"NumImport..!!"
#define IMPORT_FUNCTION_NUM_FLAGS 0xEFFFFFFFFFFFFFFF
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)

#define BITS_NT_HEADER_OPTION(BITS, NTHEADER, OPTION_FIELD_NAME) (BITS == BIT_TYPE_32 ? ((PIMAGE_NT_HEADERS32)NTHEADER)->OptionalHeader.OPTION_FIELD_NAME : ((PIMAGE_NT_HEADERS64)NTHEADER)->OptionalHeader.OPTION_FIELD_NAME)

#define LOAD_SYSTEM_DLL_COUNT 4
static const WCHAR *g_wsLoaddll[LOAD_SYSTEM_DLL_COUNT] = { L"ntdll.dll", L"kernel32.dll" , L"kernelbase.dll", L"user32.dll"};

CPELoader::CPELoader() : m_ApiSetData(NULL), m_dwApiSetDataSize(0)
{
	m_ApiSetData = GetApiSetData(&m_dwApiSetDataSize);
}

CPELoader::~CPELoader()
{
	if (m_ApiSetData)
	{
		free(m_ApiSetData);
		m_ApiSetData = NULL;
		m_dwApiSetDataSize = 0;
	}
}




int CPELoader::PeloaderCheckNtHeader(IMAGE_NT_HEADERS *pNtheader)
{
	WORD attr = 0;
	
	/* Validate the "PE\0\0" signature */
	if (pNtheader->Signature != IMAGE_NT_SIGNATURE) 
	{
		return -EINVAL;
	}
	BYTE bits = GetPeImagesBits(pNtheader);
	if (bits == 0)
	{
		return -EINVAL;
	}

	WORD Magic = BITS_NT_HEADER_OPTION(bits, pNtheader, Magic);
	DWORD dwSectionAlignment = BITS_NT_HEADER_OPTION(bits, pNtheader, SectionAlignment);
	DWORD dwFileAlignment = BITS_NT_HEADER_OPTION(bits, pNtheader, FileAlignment);

	if (Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
		Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return -EINVAL;
	}

	/* Validate the image for the current architecture. */
	if (pNtheader->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 &&
		pNtheader->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
	{
		return -EINVAL;
	}

	/* Must have attributes */
	attr = IMAGE_FILE_EXECUTABLE_IMAGE;
	if ((pNtheader->FileHeader.Characteristics & attr) != attr)
	{
		return -EINVAL;
	}
		
	/* Make sure we have at least one section */
	if (pNtheader->FileHeader.NumberOfSections == 0)
	{
		return -EINVAL;
	}

	if (dwSectionAlignment < dwFileAlignment)
	{
		return -EINVAL;
	}

	if ((pNtheader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
	{
		return IMAGE_FILE_EXECUTABLE_IMAGE;
	}
		
	if ((pNtheader->FileHeader.Characteristics & IMAGE_FILE_DLL))
	{
		/*DLL Must be relocatable */
		attr = IMAGE_FILE_RELOCS_STRIPPED;
		if ((pNtheader->FileHeader.Characteristics & attr))
		{
			return -EINVAL;
		}
		return IMAGE_FILE_DLL;
	}
		
	return -EINVAL;
}

bool CPELoader::GetPeHeadInfo(PVOID pBase, PIMAGE_NT_HEADERS *ppNtHead, PIMAGE_SECTION_HEADER *ppSectionHead)
{
	__try
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
		PIMAGE_NT_HEADERS pNtHead = NULL;
		BYTE bits = 0;
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return false;
		}
		pNtHead = (PIMAGE_NT_HEADERS)((char *)pDosHeader + pDosHeader->e_lfanew);
		if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
		{
			return false;
		}
		*ppNtHead = pNtHead;

		bits = GetPeImagesBits(pNtHead);
		assert(bits != 0);
		if (bits == 0)
		{
			return false;
		}

		if (bits == BIT_TYPE_32)
		{
			*ppSectionHead = (PIMAGE_SECTION_HEADER)((char *)pNtHead + sizeof(IMAGE_NT_HEADERS32));
		}
		else
		{
			*ppSectionHead = (PIMAGE_SECTION_HEADER)((char *)pNtHead + sizeof(IMAGE_NT_HEADERS64));
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}

ULONGLONG CPELoader::GetTotalImageSize(PVOID pFileBase, ULONGLONG ulFilesize)
{
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	ULONGLONG dwRetSize = 0;
	
	if (!GetPeHeadInfo(pFileBase, &pNTHeader, &pSectionHeader))
	{
		return 0;
	}

	BYTE bits = GetPeImagesBits(pNTHeader);

	DWORD dwSizeOfImage = BITS_NT_HEADER_OPTION(bits, pNTHeader, SizeOfImage);
	DWORD dwSectionAlignment = BITS_NT_HEADER_OPTION(bits, pNTHeader, SectionAlignment);
	DWORD dwSizeOfHeaders = BITS_NT_HEADER_OPTION(bits, pNTHeader, SizeOfHeaders);

	if (ulFilesize > dwSizeOfImage)
	{
		auto AlignSize = [](DWORD dwOrigin, DWORD dwAlignment) -> DWORD { return (dwOrigin + dwAlignment - 1) / dwAlignment * dwAlignment; };
		dwRetSize = AlignSize(dwSizeOfHeaders, dwSectionAlignment);

		for (WORD i = 0; i < pNTHeader->FileHeader.NumberOfSections; ++i)
		{
			DWORD dwCodeSize = pSectionHeader[i].Misc.VirtualSize;
			DWORD dwLoadSize = pSectionHeader[i].SizeOfRawData;
			DWORD dwMaxSize = dwLoadSize > dwCodeSize ? dwLoadSize : dwCodeSize;
			DWORD dwSectionSize = AlignSize(pSectionHeader[i].VirtualAddress + dwMaxSize, dwSectionAlignment);
			if (dwRetSize < dwSectionSize)
			{
				dwRetSize = dwSectionSize;
			}
		}

		assert(ALIGN_SIZE_UP(dwSizeOfImage, PAGE_SIZE) == dwRetSize);
		return dwRetSize;
	}
	return ALIGN_SIZE_UP(dwSizeOfImage, PAGE_SIZE) + PAGE_SIZE;
}

bool CPELoader::CheckModuleLoaded(const WCHAR *wsModuleName, std::shared_ptr<sLoadModule> &MainModule)
{
	for (std::list<std::shared_ptr<sLoadModule>>::iterator iter = MainModule->vDependModules.begin();
		 iter != MainModule->vDependModules.end(); ++iter)
	{
		if (_wcsicmp(wsModuleName, (*iter)->name.c_str()) == 0)
		{
			return true;
		}
	}
	return false;
}

bool CPELoader::LoaderLoadFixEatIatSectionPost(std::shared_ptr<sLoadModule> &MainModule, std::shared_ptr<sLoadModule> &LoadingModule, EmulationItem *pEItem)
{
	//后处理输入表API地址
	GetPeExportsPost(LoadingModule, MainModule);

	//获取iat函数
	GetModuleIATAddr(MainModule->vDependModules, LoadingModule);

	//fix iat表
	std::vector<sVMMemWriteInfo> vIATFixInfo;
	GetFixUpImageIAT(LoadingModule->pMemoryAddress, LoadingModule->ullLoadbase, LoadingModule->dwImageSize, LoadingModule->vImportModules, vIATFixInfo);
	if (!WriteVmMemory(pEItem->pvmCpu, vIATFixInfo))
	{
		assert(0);
	}

	//设置vimage的session属性
	for (std::vector<sSectionInfo>::const_iterator cSeciter = LoadingModule->vSections.begin(); cSeciter != LoadingModule->vSections.end(); ++cSeciter)
	{
		if (cSeciter->dwAlignSectionSize == 0 || cSeciter->ullSectionBase == 0 ||
			!(cSeciter->ullSectionBase >= LoadingModule->ullLoadbase && cSeciter->ullSectionBase < (LoadingModule->ullLoadbase + LoadingModule->dwImageSize)))
		{
			assert(0);
			continue;
		}
		DWORD dwProtect = VM_MEM_PROTECT_READ;
		if (cSeciter->dwCharacteristics & IMAGE_SCN_MEM_EXECUTE)
			dwProtect |= VM_MEM_PROTECT_EXEC;
		if (cSeciter->dwCharacteristics & IMAGE_SCN_MEM_WRITE)
			dwProtect |= VM_MEM_PROTECT_WRITE;

		if (!pEItem->pvmCpu->VmProtectMemory(cSeciter->ullSectionBase, cSeciter->dwAlignSectionSize, dwProtect))
		{
			assert(0);
		}
	}

	return true;
}


std::shared_ptr<sLoadModule> CPELoader::LoaderLoadFileEx(const WCHAR *filename, EmulationItem *pEItem, std::shared_ptr<sLoadModule> &MainModule)
{
	std::shared_ptr<sLoadModule> LoadModule = nullptr;
	DWORD dwPriority = MainModule == nullptr ? 0 : MainModule->dwPriority + 1;

	if (MainModule != nullptr)
	{
		std::shared_ptr<sFileInfo> Fileinfo = std::make_shared<sFileInfo>();
		if (!LoaderGetFileInfo(filename, Fileinfo))
		{
			return nullptr;
		}
		if (Fileinfo->arch != pEItem->pFileinfo->arch || 
			Fileinfo->BitType != pEItem->pFileinfo->BitType)
		{
			return nullptr;
		}

		std::wstring ModuleName = PathFindFileNameW(filename);
		std::shared_ptr<sLoadModule> module = GetDependModule(MainModule->vDependModules, ModuleName);
		if (module)
		{
			return module;
		}
	}

	LoadModule = LoaderLoadAllModuleNaked(filename, dwPriority, pEItem, MainModule);
	if (LoadModule)
	{
		std::shared_ptr<sLoadModule> pMainModuleTmp = MainModule == nullptr ? LoadModule : MainModule;
		for (std::list<std::shared_ptr<sLoadModule>>::iterator iter = pMainModuleTmp->vDependModules.begin(); iter != pMainModuleTmp->vDependModules.end(); ++iter)
		{
			bool bRet = LoaderLoadFixEatIatSectionPost(pMainModuleTmp, *iter, pEItem);
			assert(bRet);

			(*iter)->IsLoading = false;
		}

		//主模块
		if (dwPriority == 0)
		{
			bool bRet = LoaderLoadFixEatIatSectionPost(LoadModule, LoadModule, pEItem);
			assert(bRet);
			LoadModule->IsLoading = false;
		}

		if (LoadModule->pMemoryAddress)
		{
			free(LoadModule->pMemoryAddress);
			LoadModule->pMemoryAddress = NULL;
		}
		for (std::list<std::shared_ptr<sLoadModule>>::iterator iter = LoadModule->vDependModules.begin(); iter != LoadModule->vDependModules.end(); ++iter)
		{
			if ((*iter)->pMemoryAddress)
			{
				free((*iter)->pMemoryAddress);
				(*iter)->pMemoryAddress = NULL;
			}
		}
	}

	return LoadModule;
}

bool CPELoader::LoaderLoadDependModules(std::shared_ptr<sLoadModule> &pMainModule, EmulationItem *pEItem, DWORD dwPriority, std::shared_ptr<sLoadModule> &pModule)
{
	//apiset 映射所依赖的模块
	for (std::vector<std::wstring>::iterator iter = pModule->vExportApiDependModule.begin(); iter != pModule->vExportApiDependModule.end(); ++iter)
	{
		if (!CheckModuleLoaded(iter->c_str(), pMainModule))
		{
			std::wstring sdllPath = pEItem->LoadPath[0] + *iter;
			std::shared_ptr<sLoadModule> sDependDllModule = LoaderLoadSingleModuleNaked(sdllPath.c_str(), dwPriority + 1, pEItem);
			if (sDependDllModule != NULL)
			{
				pMainModule->vDependModules.push_back(sDependDllModule);
				//wprintf(L"Log: %s load success, \tbase: 0x%016I64x, \tsize: 0x%08x\n",
				//	iter->c_str(), sDependDllModule->ullLoadbase, sDependDllModule->dwImageSize);

				LoaderLoadDependModules(pMainModule, pEItem, sDependDllModule->dwPriority + 1, sDependDllModule);
			}
			else
			{
				wprintf(L"Warning: %s load false\n", iter->c_str());
				//assert(0);
			}
		}
	}

	//加载该模块所有依赖的模块
	for (std::vector<sImportTableInfo>::iterator iter = pModule->vImportModules.begin(); iter != pModule->vImportModules.end(); ++iter)
	{
		WCHAR wsMapToDll[MAX_PATH + 1] = { 0 };
		do
		{
			wsMapToDll[0] = 0;
			ApiSetpResolve(iter->ImportName.c_str(), NULL, wsMapToDll, MAX_PATH * sizeof(WCHAR));
			iter->MapToDllName = wsMapToDll;
		} while (wcslen(wsMapToDll) > 0 && CheckApiSetMap(wsMapToDll));

		std::wstring wsNeedLoadModule = iter->MapToDllName.size() > 0 ? iter->MapToDllName : iter->ImportName;
		//wprintf(L"%s Ready to be loaded..., ImportName:%s, MapToDllName:%s\n", wsNeedLoadModule.c_str(), iter->ImportName.c_str(), iter->MapToDllName.c_str());
		if (!CheckModuleLoaded(wsNeedLoadModule.c_str(), pMainModule))
		{
			std::wstring sdllPath = pEItem->LoadPath[0] + wsNeedLoadModule;
			std::shared_ptr<sLoadModule> sDependDllModule = LoaderLoadSingleModuleNaked(sdllPath.c_str(), dwPriority + 1, pEItem);
			if (sDependDllModule != NULL)
			{
				pMainModule->vDependModules.push_back(sDependDllModule);
				//wprintf(L"Log: %s load success, \tbase: 0x%016I64x, \tsize: 0x%08x\n",
				//	wsNeedLoadModule.c_str(), sDependDllModule->ullLoadbase, sDependDllModule->dwImageSize);

				LoaderLoadDependModules(pMainModule, pEItem, sDependDllModule->dwPriority + 1, sDependDllModule);
			}
			else
			{
				wprintf(L"Warning: %s load false\n", wsNeedLoadModule.c_str());
				assert(0);
			}
		}
	}

	return true;
}


std::shared_ptr<sLoadModule> CPELoader::LoaderLoadAllModuleNaked(const WCHAR *filename, DWORD dwPriority, EmulationItem *pEItem, std::shared_ptr<sLoadModule> &MainModule)
{
	std::shared_ptr<sLoadModule> pModule = LoaderLoadSingleModuleNaked(filename, dwPriority, pEItem);
	if (pModule == nullptr)
	{
		assert(0);
		return nullptr;
	}
	if (MainModule != nullptr && dwPriority > 0)
	{
		//主模块的依赖模块
		MainModule->vDependModules.push_back(pModule);
	}

	std::shared_ptr<sLoadModule> pMainModuleTmp = MainModule == nullptr ? pModule : MainModule;
	if (dwPriority == 0)
	{
		for (WORD j = 0; j < LOAD_SYSTEM_DLL_COUNT; j++)
		{
			std::wstring sdllPath = pEItem->LoadPath[0] + g_wsLoaddll[j];
			std::shared_ptr<sLoadModule> sSysDllModule = LoaderLoadSingleModuleNaked(sdllPath.c_str(), dwPriority + 1, pEItem);
			if (sSysDllModule == NULL)
			{
				assert(0);
				return nullptr;
			}
			pModule->vDependModules.push_back(sSysDllModule);
			LoaderLoadDependModules(pMainModuleTmp, pEItem, sSysDllModule->dwPriority + 1, sSysDllModule);
		}
	}

	LoaderLoadDependModules(pMainModuleTmp, pEItem, pModule->dwPriority + 1, pModule);
	return pModule;
}



std::shared_ptr<sLoadModule> CPELoader::LoaderLoadSingleModuleNaked(const WCHAR *filename, DWORD dwPriority, EmulationItem *pEItem)
{
	bool bRet = false;

	PVOID pFileBase = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	WORD dwSections = 0;
	std::shared_ptr<sLoadModule> pLoadModule = NULL;
	std::shared_ptr<sLoadModule> pMainModule = NULL;
	ULONGLONG ulFileSize = 0;
	PVOID pMemoryAddress = NULL;
	DWORD dwThisPriority = dwPriority;
	ULONGLONG ullImageBase = 0;

	do
	{
		pFileBase = LoadImageFile(filename, &ulFileSize);
		if (pFileBase == NULL)
		{
			break;
		}

		if (!GetPeHeadInfo(pFileBase, &pNTHeader, &pSectionHeader))
		{
			break;
		}
		int nPeType = PeloaderCheckNtHeader(pNTHeader);
		if (nPeType <= 0) //pe or dll
		{
			break;
		}
		BYTE bits = GetPeImagesBits(pNTHeader);
		if (bits == 0)
		{
			assert(0);
			break;
		}

		if (dwPriority > 0)
		{
			if (pEItem->pFileinfo->BitType == BIT_TYPE_32 && bits != BIT_TYPE_32)
			{
				break;
			}
			else if (pEItem->pFileinfo->BitType == BIT_TYPE_64 && bits != BIT_TYPE_64)
			{
				break;
			}
		}

		ULONGLONG dwImageSize = GetTotalImageSize(pFileBase, ulFileSize);
		if (dwImageSize == 0)
		{
			break;
		}
		dwSections = pNTHeader->FileHeader.NumberOfSections;

		pMemoryAddress = (PVOID)malloc(dwImageSize);
		if (pMemoryAddress == NULL)
		{
			break;
		}
		memset(pMemoryAddress, 0, dwImageSize);
		DWORD dwSizeOfHeaders = BITS_NT_HEADER_OPTION(bits, pNTHeader, SizeOfHeaders);
		memcpy(pMemoryAddress, pFileBase, dwSizeOfHeaders);

		pLoadModule = std::make_shared<sLoadModule>();
		pLoadModule->name = PathFindFileNameW(filename);
		pLoadModule->filePath = filename;
		pLoadModule->dwPriority = dwPriority;
		pLoadModule->ullLoadbase = 0;
		pLoadModule->IsLoading = true;

		ullImageBase = (ULONGLONG)BITS_NT_HEADER_OPTION(bits, pNTHeader, ImageBase);
		if (dwPriority == 0 && ullImageBase != 0 && (ALIGN_SIZE_UP(ullImageBase, PAGE_SIZE) == ullImageBase))
		{
			if (pEItem->pmemMgr->WinAddReserveBlockSpace(pEItem->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, ullImageBase, (DWORD)dwImageSize))
			{
				pLoadModule->ullLoadbase = ullImageBase;
			}
		}
		if (pLoadModule->ullLoadbase == 0)
		{
			assert(!(pNTHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED));
			pLoadModule->ullLoadbase = pEItem->pmemMgr->WinMemSpaceAlloc(pEItem->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, (DWORD)dwImageSize);
			if (pLoadModule->ullLoadbase == 0)
			{
				break;
			}
		}

		pLoadModule->dwImageSize = (DWORD)dwImageSize;
		DWORD dwAddressOfEntryPoint = BITS_NT_HEADER_OPTION(bits, pNTHeader, AddressOfEntryPoint);
		if (dwAddressOfEntryPoint != 0)
		{
			pLoadModule->ullImageEntry = pLoadModule->ullLoadbase + dwAddressOfEntryPoint;
		}

		bool bCopySucc = false;
		DWORD dwSectionAlignment = BITS_NT_HEADER_OPTION(bits, pNTHeader, SectionAlignment);
		for (WORD i = 0; i < dwSections; i++)
		{
			if (pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)
			{
				continue;
			}

			if (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData > dwImageSize)
			{
				bCopySucc = false;
				break;
			}

			auto AlignSizeFunc = [](DWORD dwOrigin, DWORD dwAlignment) -> DWORD { return (dwOrigin + dwAlignment - 1) / dwAlignment * dwAlignment; };
			sSectionInfo section;
			section.ullSectionBase = pLoadModule->ullLoadbase + pSectionHeader[i].VirtualAddress;
			section.dwSizeOfRawData = pSectionHeader[i].SizeOfRawData;
			section.dwVirtualSize = pSectionHeader[i].Misc.VirtualSize;
			section.dwAlignSectionSize = AlignSizeFunc(section.dwVirtualSize, dwSectionAlignment);
			section.dwCharacteristics = pSectionHeader[i].Characteristics;
			memcpy(section.SectionName, pSectionHeader[i].Name, 8);
			pLoadModule->vSections.push_back(section);

			memcpy((char *)pMemoryAddress + pSectionHeader[i].VirtualAddress, (char *)pFileBase + pSectionHeader[i].PointerToRawData, pSectionHeader[i].SizeOfRawData);
			bCopySucc = true;
		}
		if (!bCopySucc)
		{
			break;
		}

		//map to vcpu 内存
		if (!pEItem->pvmCpu->VmMapMemory(pLoadModule->ullLoadbase, (DWORD)dwImageSize, VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true))
		{
			pEItem->pmemMgr->WinMemSpaceFree(pEItem->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, pLoadModule->ullLoadbase);
			assert(0);
			break;
		}
		//copy image to vcpu
		if (!pEItem->pvmCpu->VmWriteMemory(pLoadModule->ullLoadbase, (const void *)pMemoryAddress, (DWORD)dwImageSize))
		{
			pEItem->pvmCpu->VmUnMapMemory(pLoadModule->ullLoadbase, (DWORD)dwImageSize);
			pEItem->pmemMgr->WinMemSpaceFree(pEItem->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, pLoadModule->ullLoadbase);
			assert(0);
			break;
		}

		//获取初步的导出函数
		GetPeExportsPre(pMemoryAddress, pLoadModule->ullLoadbase, (DWORD)dwImageSize, pLoadModule, pLoadModule->vExportApiDependModule);

		//添加导入模块
		GetPeImportsModules(pMemoryAddress, pLoadModule->ullLoadbase, pLoadModule->dwImageSize, pEItem->pFileinfo->BitType, pLoadModule->vImportModules);

		//重定位
		std::vector<sVMMemWriteInfo> vRelocInfo;
		if (!GetFixUpImageReloc(pMemoryAddress, pLoadModule->ullLoadbase, pLoadModule->dwImageSize, vRelocInfo))
		{
			break;
		}
		if (!WriteVmMemory(pEItem->pvmCpu, vRelocInfo))
		{
			break;
		}

		//kernel driver need
		//InitModuleSecurityCookie(pMemoryAddress, pLoadModule->ullLoadbase, (DWORD)dwImageSize, pEItem->pvmCpu);
		pLoadModule->pMemoryAddress = pMemoryAddress;
		bRet = true;

	} while (false);


	if (!bRet && pMemoryAddress)
	{
		free(pMemoryAddress);
		pMemoryAddress = NULL;
	}

	if (!bRet && pLoadModule)
	{
		pLoadModule = NULL;
	}

	if (pFileBase)
	{
		UnmapViewOfFile(pFileBase);
	}
	return pLoadModule;
}





DWORD CPELoader::GetImportsApi(PVOID pImageBase, DWORD dwsize, BYTE bitType, PIMAGE_IMPORT_DESCRIPTOR pDirent, std::vector<sFunctionInfo> &vNameFunctions)
{
	PIMAGE_THUNK_DATA32 ulpLookupTbl32Bit = NULL;
	PIMAGE_THUNK_DATA64 ulpLookupTbl64Bit = NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName = NULL;

	if (bitType != BIT_TYPE_32 && bitType != BIT_TYPE_64)
	{
		return 0;
	}

	DWORD i = 0;
	if (bitType == BIT_TYPE_32)
	{
		ulpLookupTbl32Bit = (PIMAGE_THUNK_DATA32)((BYTE *)pImageBase + pDirent->OriginalFirstThunk);
		for (i = 0; ulpLookupTbl32Bit->u1.Ordinal; i++)
		{
			sFunctionInfo sFuncItem;
			if (IMAGE_SNAP_BY_ORDINAL32(ulpLookupTbl32Bit->u1.Ordinal)) {

				//num 引入的函数
				sFuncItem.name = L"#";
				sFuncItem.name += std::to_wstring((ULONG)(ulpLookupTbl32Bit->u1.Ordinal & 0x0FFFFFFFul));
				//sFuncItem.ullFunctionAddr = IMPORT_FUNCTION_NUM_FLAGS;
			}
			else 
			{
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)pImageBase + ulpLookupTbl32Bit->u1.Ordinal);
				sFuncItem.name = CA2W(&pImportByName->Name[0]);
			}

			vNameFunctions.push_back(sFuncItem);
			ulpLookupTbl32Bit++;
		}
	}
	else
	{
		ulpLookupTbl64Bit = (PIMAGE_THUNK_DATA64)((BYTE *)pImageBase + pDirent->OriginalFirstThunk);
		for (i = 0; ulpLookupTbl64Bit->u1.Ordinal; i++)
		{
			sFunctionInfo sFuncItem;
			if (IMAGE_SNAP_BY_ORDINAL64(ulpLookupTbl64Bit->u1.Ordinal)) {

				//num 引入的函数
				sFuncItem.name = L"#";
				sFuncItem.name += std::to_wstring((ULONG)(ulpLookupTbl64Bit->u1.Ordinal & 0x0FFFFFFFull));
				//sFuncItem.ullFunctionAddr = IMPORT_FUNCTION_NUM_FLAGS;
			}
			else
			{
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)pImageBase + ulpLookupTbl64Bit->u1.Ordinal);
				sFuncItem.name = CA2W(&pImportByName->Name[0]);
			}
			vNameFunctions.push_back(sFuncItem);
			ulpLookupTbl64Bit++;
		}
	}

	return i;
}




//重定位
bool CPELoader::GetFixUpImageReloc(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, std::vector<sVMMemWriteInfo> &vRelocInfo)
{

	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	PIMAGE_DATA_DIRECTORY pBaseReloc = NULL;
	PIMAGE_BASE_RELOCATION pFixupBlock = NULL;
	ULONGLONG ulBaseImage = 0;

	if (!GetPeHeadInfo(pImageBase, &pNTHeader, &pSectionHeader))
	{
		return false;
	}
	BYTE bits = GetPeImagesBits(pNTHeader);
	if (bits == 0)
	{
		return false;
	}
	
	//不需要重定位
	ulBaseImage = BITS_NT_HEADER_OPTION(bits, pNTHeader, ImageBase);
	if ((ULONGLONG)ulBaseImage == ullVmImageBase)
	{
		return true;
	}

	pBaseReloc = bits == BIT_TYPE_64 ? &((PIMAGE_NT_HEADERS64)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] :
									   &((PIMAGE_NT_HEADERS32)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (pBaseReloc->VirtualAddress == 0 || pBaseReloc->Size == 0)
	{
		return true;
	}

	pFixupBlock = (PIMAGE_BASE_RELOCATION)((BYTE *)pImageBase + pBaseReloc->VirtualAddress);
	DWORD dwBlockCount = 0;
	while (pFixupBlock->SizeOfBlock) 
	{
		WORD fixup = 0, offset = 0;
		WORD *pLocData = (WORD *)((PBYTE)pFixupBlock + sizeof(IMAGE_BASE_RELOCATION));
		dwBlockCount = (pFixupBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (DWORD i = 0; i < dwBlockCount; i++) 
		{
			fixup = pLocData[i];
			offset = fixup & 0xfff;
			switch ((fixup >> 12) & 0x0f) 
			{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;

			case IMAGE_REL_BASED_HIGHLOW:
			{
				uint32_t addr = 0;
				uint32_t *loc = (uint32_t *)((PBYTE)pImageBase + pFixupBlock->VirtualAddress + offset);
				addr = (uint32_t)(ULONG_PTR)((PBYTE)ullVmImageBase + (*loc - (uint32_t)ulBaseImage));
				//*loc = addr;
				sVMMemWriteInfo item;
				item.uladdr = (ULONGLONG)((PBYTE)ullVmImageBase + pFixupBlock->VirtualAddress + offset);
				item.a.ul32bitValue = addr;
				item.dwSize = sizeof(uint32_t);
				vRelocInfo.push_back(item);
			}
			break;

			case IMAGE_REL_BASED_DIR64: 
			{
				//必须64位编译
				assert(sizeof(ULONGLONG) == sizeof(PBYTE));
				ULONGLONG addr = 0;
				ULONGLONG *loc = (ULONGLONG *)((ULONGLONG)pImageBase + pFixupBlock->VirtualAddress + offset);
				addr = (ULONGLONG)((PBYTE)ullVmImageBase + (*loc - (ULONGLONG)ulBaseImage));
				//*loc = addr;
				sVMMemWriteInfo item;
				item.uladdr = (ULONGLONG)((ULONGLONG)ullVmImageBase + pFixupBlock->VirtualAddress + offset);
				item.a.ul64bitValue = addr;
				item.dwSize = sizeof(ULONGLONG);
				vRelocInfo.push_back(item);
			}
			break;

			default:
				assert(0);
				return false;
				break;
			}
		}

		pFixupBlock = (PIMAGE_BASE_RELOCATION)((PBYTE)pFixupBlock + pFixupBlock->SizeOfBlock);
	};

	return true;
}

std::shared_ptr<sLoadModule> CPELoader::GetDependModule(const std::list<std::shared_ptr<sLoadModule>>& vDepend, std::wstring &wsName)
{
	for (std::list<std::shared_ptr<sLoadModule>>::const_iterator iter = vDepend.begin(); iter != vDepend.end(); ++iter)
	{
		if (_wcsicmp(wsName.c_str(), (*iter)->name.c_str()) == 0)
		{
			return *iter;
		}
	}
	return NULL;
}


bool CPELoader::GetFunctionInfoByName(const sExportTableInfo &ExportApis, const std::wstring &wsFunctionName, OUT sExportFunction &RetResult)
{
	if (ExportApis.FNameToAddr.size() == 0)
	{
		return false;
	}

	LONG lHigh = 0;
	LONG lLow = 0;
	LONG lMiddle = 0;
	int nResult = 0;
	lHigh = (LONG)ExportApis.FNameToAddr.size() - 1;

	while (lHigh >= lLow)
	{
		lMiddle = (lLow + lHigh) >> 1;
		nResult = wcscmp(wsFunctionName.c_str(), ExportApis.FNameToAddr[lMiddle].name.c_str());
		if (nResult < 0)
		{
			lHigh = lMiddle - 1;
		}
		else if (nResult > 0)
		{
			lLow = lMiddle + 1;
		}
		else
		{
			break;
		}
	}

	if (lHigh < lLow)
	{
		return false;
	}

	RetResult.name = ExportApis.FNameToAddr[lMiddle].name;
	RetResult.ullFunctionAddr = ExportApis.FNameToAddr[lMiddle].ullFunctionAddr;
	RetResult.IsMap = ExportApis.FNameToAddr[lMiddle].IsMap;
	RetResult.MapToModule = ExportApis.FNameToAddr[lMiddle].MapToModule;
	RetResult.MapToFunction = ExportApis.FNameToAddr[lMiddle].MapToFunction;
	return true;
}

ULONGLONG CPELoader::GetFunctionByNumber(const sExportTableInfo &ExportApis, ULONG dwIndex)
{
	std::map<ULONG, ULONGLONG>::const_iterator iter = ExportApis.FuncExportNum.find(dwIndex);
	if (iter != ExportApis.FuncExportNum.end())
	{
		return iter->second;
	}
	return 0;
}

ULONGLONG CPELoader::GetFunctionByName(const sExportTableInfo &ExportApis, const std::wstring &wsFunctionName)
{
	if (ExportApis.FNameToAddr.size() == 0)
	{
		return 0;
	}

	LONG lHigh = 0;
	LONG lLow = 0;
	LONG lMiddle = 0;
	int nResult = 0;
	lHigh = (LONG)ExportApis.FNameToAddr.size() - 1;

	while (lHigh >= lLow)
	{
		lMiddle = (lLow + lHigh) >> 1;
		nResult = wcscmp(wsFunctionName.c_str(), ExportApis.FNameToAddr[lMiddle].name.c_str());
		if (nResult < 0)
		{
			lHigh = lMiddle - 1;
		}
		else if (nResult > 0)
		{
			lLow = lMiddle + 1;
		}
		else
		{
			break;
		}
	}

	if (lHigh < lLow)
	{
		return 0;
	}

	return ExportApis.FNameToAddr[lMiddle].ullFunctionAddr;
}

bool CPELoader::GetModuleIATAddr(const std::list<std::shared_ptr<sLoadModule>>& vDepends, std::shared_ptr<sLoadModule> &pLoadingModule)
{
	for (std::vector<sImportTableInfo>::iterator iter = pLoadingModule->vImportModules.begin(); iter != pLoadingModule->vImportModules.end(); ++iter)
	{
		std::wstring RealDependDll = iter->MapToDllName.size() > 0 ? iter->MapToDllName : iter->ImportName;

		std::shared_ptr<sLoadModule> module = NULL;
		if (_wcsicmp(RealDependDll.c_str(), pLoadingModule->name.c_str()) == 0)
		{
			//当前正在加载的模块
			module = pLoadingModule;
			assert(pLoadingModule->IsLoading == true);
		}
		else
		{
			module = GetDependModule(vDepends, RealDependDll);
		}
		for (std::vector<sFunctionInfo>::iterator iter2 = iter->FNameToAddr.begin(); iter2 != iter->FNameToAddr.end(); ++iter2)
		{
			if (module == NULL)
			{
				//不能找到加载的模块
				iter2->ullFunctionAddr = IMPORT_FUNCTION_NUM_FLAGS;
				assert(0);
			}
			else
			{
				if (iter2->ullFunctionAddr == IMPORT_FUNCTION_NUM_FLAGS)
				{
					continue;
				}

				if (iter2->name.size() == 0)
				{
					assert(0);
				}

				if (iter2->name[0] == L'#')
				{
					std::wstring Num = iter2->name;
					Num.erase(Num.begin());
					DWORD dwindex = _wtol(Num.c_str());
					iter2->ullFunctionAddr = GetFunctionByNumber(module->ExportApis, dwindex);
				}
				else
				{
					//从加载的模块导出api里面找回函数地址
					iter2->ullFunctionAddr = GetFunctionByName(module->ExportApis, iter2->name);
				}

				if (iter2->ullFunctionAddr != 0)
				{
					iter->FunaddrToName.insert(std::pair<ULONGLONG, std::wstring>(iter2->ullFunctionAddr, iter2->name));
				}
				else
				{
					iter2->ullFunctionAddr = IMPORT_FUNCTION_NUM_FLAGS;
				}
			}
		}
	}
	return true;

}

bool CPELoader::GetFixUpImageIAT(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, const std::vector<sImportTableInfo>& vImportModules, OUT std::vector<sVMMemWriteInfo>& vIATFuncInfo)
{
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	PIMAGE_IMPORT_DESCRIPTOR pDirent = NULL;
	PIMAGE_DATA_DIRECTORY pImportDataDir = NULL;

	if (!GetPeHeadInfo(pImageBase, &pNTHeader, &pSectionHeader))
	{
		return false;
	}
	BYTE bits = GetPeImagesBits(pNTHeader);
	if (bits == 0)
	{
		return false;
	}

	pImportDataDir = bits == BIT_TYPE_32 ? &((PIMAGE_NT_HEADERS32)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] :
										   &((PIMAGE_NT_HEADERS64)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (pImportDataDir->VirtualAddress == 0 || pImportDataDir->Size == 0)
	{
		return false;
	}
	pDirent = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)pImageBase + pImportDataDir->VirtualAddress);
	if ((ULONGLONG)pDirent >= (ULONGLONG)pImageBase + dwsize)
	{
		return false;
	}

	for (DWORD i = 0; pDirent[i].Name; i++)
	{
		std::wstring tmp = CA2W((char *)((BYTE *)pImageBase + pDirent[i].Name));
		if (_wcsicmp(vImportModules[i].ImportName.c_str(), tmp.c_str()) != 0)
		{
			assert(0);
			return false;
		}
		
		if (bits == BIT_TYPE_32)
		{
			PIMAGE_THUNK_DATA32 pNameThunk32Bit = (PIMAGE_THUNK_DATA32)((BYTE *)pImageBase + (&pDirent[i])->OriginalFirstThunk);
			PIMAGE_THUNK_DATA32 pVmLookupTbl32Bit = (PIMAGE_THUNK_DATA32)((BYTE *)ullVmImageBase + (&pDirent[i])->FirstThunk);
			for (DWORD j = 0; pNameThunk32Bit->u1.Ordinal; j++)
			{
				std::wstring wsFunctionName;
				if (IMAGE_SNAP_BY_ORDINAL32(pNameThunk32Bit->u1.Ordinal)) {

					wsFunctionName = L"#";
					wsFunctionName += std::to_wstring((ULONG)(pNameThunk32Bit->u1.Ordinal & 0x0FFFFFFFul));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)pImageBase + pNameThunk32Bit->u1.Ordinal);
					wsFunctionName = CA2W(&pImportByName->Name[0]);
				}
				if (_wcsicmp(vImportModules[i].FNameToAddr[j].name.c_str(), wsFunctionName.c_str()) != 0)
				{
					assert(0);
					return false;
				}
				sVMMemWriteInfo writeItem;
				writeItem.uladdr = (ULONGLONG)&pVmLookupTbl32Bit->u1.Function;
				writeItem.a.ul32bitValue = (ULONG)vImportModules[i].FNameToAddr[j].ullFunctionAddr;
				writeItem.dwSize = sizeof(ULONG);
				vIATFuncInfo.push_back(writeItem);
				pNameThunk32Bit++;
				pVmLookupTbl32Bit++;
			}
		}
		else
		{
			PIMAGE_THUNK_DATA64 pNameThunk64Bit = (PIMAGE_THUNK_DATA64)((BYTE *)pImageBase + (&pDirent[i])->OriginalFirstThunk);
			PIMAGE_THUNK_DATA64 pVmLookupTbl64Bit = (PIMAGE_THUNK_DATA64)((ULONG_PTR)ullVmImageBase + (&pDirent[i])->FirstThunk);
			for (DWORD x = 0; pNameThunk64Bit->u1.Ordinal; x++)
			{
				std::wstring wsFunctionName;
				if (IMAGE_SNAP_BY_ORDINAL64(pNameThunk64Bit->u1.Ordinal)) {

					wsFunctionName = L"#";
					wsFunctionName += std::to_wstring((ULONG)(pNameThunk64Bit->u1.Ordinal & 0x0FFFFFFFull));
				}
				else
				{
					PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE *)pImageBase + pNameThunk64Bit->u1.Ordinal);
					wsFunctionName = CA2W(&pImportByName->Name[0]);
				}
				if (_wcsicmp(vImportModules[i].FNameToAddr[x].name.c_str(), wsFunctionName.c_str()) != 0)
				{
					assert(0);
					return false;
				}

				sVMMemWriteInfo writeItem;
				writeItem.uladdr = (ULONGLONG)&pVmLookupTbl64Bit->u1.Function;
				writeItem.a.ul64bitValue = (ULONGLONG)vImportModules[i].FNameToAddr[x].ullFunctionAddr;
				writeItem.dwSize = sizeof(ULONGLONG);
				vIATFuncInfo.push_back(writeItem);
				pNameThunk64Bit++;
				pVmLookupTbl64Bit++;
			}
		}
	}
	return true;
}

BYTE CPELoader::GetPeImagesBits(PIMAGE_NT_HEADERS pNtHead)
{
	PIMAGE_NT_HEADERS32 p32Header = (PIMAGE_NT_HEADERS32)pNtHead;
	PIMAGE_NT_HEADERS64 p64Header = (PIMAGE_NT_HEADERS64)pNtHead;


	if (pNtHead->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
		p32Header->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		return BIT_TYPE_32;
	}
	else if (pNtHead->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
		p64Header->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		return BIT_TYPE_64;
	}

	return 0;
}



DWORD CPELoader::GetPeImportsModules(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, BYTE bitType, std::vector<sImportTableInfo> &IatTables)
{
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	PIMAGE_IMPORT_DESCRIPTOR pDirent = NULL;
	PIMAGE_DATA_DIRECTORY pImportDataDir = NULL;

	if (!GetPeHeadInfo(pImageBase, &pNTHeader, &pSectionHeader))
	{
		return 0;
	}
	BYTE bits = GetPeImagesBits(pNTHeader);
	if (bits == 0 || bits != bitType)
	{
		return 0;
	}
	

	pImportDataDir = bits == BIT_TYPE_32 ? &((PIMAGE_NT_HEADERS32)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] :
										   &((PIMAGE_NT_HEADERS64)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (pImportDataDir->VirtualAddress == 0 || pImportDataDir->Size == 0)
	{
		return 0;
	}
	pDirent = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)pImageBase + pImportDataDir->VirtualAddress);
	if ((ULONGLONG)pDirent >= (ULONGLONG)pImageBase + dwsize)
	{
		return 0;
	}

	DWORD i = 0;
	for (i = 0; pDirent[i].Name; i++) 
	{
		sImportTableInfo sImportModule;
		sImportModule.ImportName = CA2W((char *)((BYTE *)pImageBase + pDirent[i].Name));

		if (GetImportsApi(pImageBase, dwsize, bitType, &pDirent[i], sImportModule.FNameToAddr) == 0)
		{
			return 0;
		}
		IatTables.push_back(sImportModule);
	}

	return i;
}


bool CPELoader::GetPeExportsPost(std::shared_ptr<sLoadModule> &pLoadModule, std::shared_ptr<sLoadModule> &MainModule)
{
	for (std::vector<sExportFunction>::iterator iter = pLoadModule->ExportApis.FNameToAddr.begin(); iter != pLoadModule->ExportApis.FNameToAddr.end(); ++iter)
	{
		if (iter->IsMap)
		{
			std::wstring MapToModule;
			if (iter->MapToFunction.size() > 0 && iter->MapToFunction[0] == L'#')
			{
				std::wstring Num = iter->MapToFunction;
				Num.erase(Num.begin());
				DWORD dwindex = _wtol(Num.c_str());
				if (dwindex > 0)
				{
					iter->ullFunctionAddr = GetExportFuncAddressByNumberNoMap(iter->MapToModule, dwindex, MainModule, MapToModule);
					if (iter->ullFunctionAddr)
					{
						iter->MapToModule = MapToModule;
						pLoadModule->ExportApis.FunaddrToName.insert(std::pair<ULONGLONG, std::wstring>(iter->ullFunctionAddr, iter->name));
					}
				}
			}

			if (iter->ullFunctionAddr == 0 || iter->ullFunctionAddr == IMPORT_FUNCTION_NUM_FLAGS)
			{
				iter->ullFunctionAddr = GetExportFuncAddressNoMap(iter->MapToModule, iter->MapToFunction, MainModule, MapToModule);
				if (iter->ullFunctionAddr && MapToModule.size() > 0)
				{
					iter->MapToModule = MapToModule;
					pLoadModule->ExportApis.FunaddrToName.insert(std::pair<ULONGLONG, std::wstring>(iter->ullFunctionAddr, iter->name));
				}
				else
				{
					iter->ullFunctionAddr = IMPORT_FUNCTION_NUM_FLAGS;
					wprintf(L"Warning: %s->ExportFunction: %s is MapTo %s!%s, but can not Found Address\n",
						pLoadModule->name.c_str(), iter->name.c_str(), iter->MapToModule.c_str(), iter->MapToFunction.c_str());

					//assert(iter->ullFunctionAddr && MapToModule.size() > 0);
				}
			}
		}
	}
	return true;
}


ULONGLONG CPELoader::GetExportFuncAddressByNumberNoMap(std::wstring &wsModuleName, DWORD dwIndex, std::shared_ptr<sLoadModule> &MainModule, OUT std::wstring &RetMapModule)
{
	std::shared_ptr<sLoadModule> module = GetDependModule(MainModule->vDependModules, wsModuleName);
	if (module == NULL)
	{
		return 0;
	}

	ULONGLONG ullFunctionAddr = GetFunctionByNumber(module->ExportApis, dwIndex);
	if (ullFunctionAddr != 0)
	{
		RetMapModule = wsModuleName;
	}
	return ullFunctionAddr;
}

ULONGLONG CPELoader::GetExportFuncAddressNoMap(std::wstring &wsModuleName, std::wstring &wsFunctionName, std::shared_ptr<sLoadModule> &MainModule, OUT std::wstring &RetMapModule)
{
	std::shared_ptr<sLoadModule> module = GetDependModule(MainModule->vDependModules, wsModuleName);
	if (module == NULL)
	{
		return 0;
	}

	sExportFunction FunctionInfo;
	bool bRet = GetFunctionInfoByName(module->ExportApis, wsFunctionName, FunctionInfo);
	if (!bRet)
	{
		return 0;
	}
	if (FunctionInfo.IsMap)
	{
		return GetExportFuncAddressNoMap(FunctionInfo.MapToModule, FunctionInfo.MapToFunction, MainModule, RetMapModule);
	}

	RetMapModule = wsModuleName;
	return FunctionInfo.ullFunctionAddr;
}


DWORD CPELoader::GetPeExportsPre(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, std::shared_ptr<sLoadModule> &pLoadModule, OUT std::vector<std::wstring> &vDependModule)
{
	DWORD dwRetCount = 0;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_DATA_DIRECTORY pExportDir = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportTable = NULL;

	ULONG *pNameTable = NULL;
	WORD *pOrdinalTable = NULL;

	if (!GetPeHeadInfo(pImageBase, &pNTHeader, &pSectionHeader))
	{
		return 0;
	}
	BYTE bits = GetPeImagesBits(pNTHeader);

	pExportDir = bits == BIT_TYPE_32 ? &((PIMAGE_NT_HEADERS32)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] :
									   &((PIMAGE_NT_HEADERS64)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (pExportDir->Size == 0)
	{
		return 0;
	}

	pExportTable = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pImageBase + pExportDir->VirtualAddress);

	pNameTable = (ULONG *)((char *)pImageBase + pExportTable->AddressOfNames);
	pOrdinalTable = (WORD *)((char *)pImageBase + pExportTable->AddressOfNameOrdinals);

	if (pExportTable->NumberOfFunctions == 0)
	{
		return 0;
	}
	PVOID pFuncsAddress = malloc(pExportTable->NumberOfFunctions * sizeof(ULONG));
	if (pFuncsAddress == NULL)
	{
		return 0;
	}
	memcpy(pFuncsAddress, (char *)pImageBase + pExportTable->AddressOfFunctions, pExportTable->NumberOfFunctions * sizeof(ULONG));

	for (DWORD i = 0; i < pExportTable->NumberOfNames; i++)
	{
		assert(*pOrdinalTable < pExportTable->NumberOfFunctions);

		ULONG address = ((ULONG *)((char *)pImageBase + pExportTable->AddressOfFunctions))[*pOrdinalTable];
		((ULONG *)pFuncsAddress)[*pOrdinalTable] = 0;

		if (address >= dwsize  || *pNameTable >= dwsize)
		{
			assert(0);
			continue;
		}

		sExportFunction item;
		item.name = CA2W((const char *)((char *)pImageBase + *pNameTable));
		item.ullFunctionAddr = (ULONGLONG)(ullVmImageBase + address);

		//检查是否map api
		item.IsMap = false;
		ULONGLONG ulImageFunctionAddr = (ULONGLONG)((PBYTE)pImageBase + address);
		if ((PBYTE)ulImageFunctionAddr > (PBYTE)pExportTable && (PBYTE)ulImageFunctionAddr < (PBYTE)pExportTable + pExportDir->Size)
		{
			item.IsMap = true;
			std::wstring ApiMapPath = CA2W((char *)((char *)pImageBase + address));
			assert(ApiMapPath.size() > 0);
			std::string::size_type a = ApiMapPath.find(L'.');
			assert(a != std::string::npos);
			item.MapToModule = ApiMapPath.substr(0, a) + L".dll";
			assert(a + 1 < ApiMapPath.size());
			item.MapToFunction = ApiMapPath.substr(a + 1, ApiMapPath.size() - 1);

			WCHAR wsMapToDll[MAX_PATH + 1] = { 0 };
			do 
			{
				wsMapToDll[0] = 0x0;
				ApiSetpResolve(item.MapToModule.c_str(), NULL, wsMapToDll, MAX_PATH * sizeof(WCHAR));
				if (wcslen(wsMapToDll) > 0)
				{
					item.MapToModule = wsMapToDll;
				}
			} while (wcslen(wsMapToDll) > 0 && CheckApiSetMap(wsMapToDll));

			auto CheckNeedAdd = [&vDependModule](std::wstring &MapToModule) -> bool {
				for (std::vector<std::wstring>::const_iterator iter = vDependModule.begin(); iter != vDependModule.end(); ++iter)
				{
					if (_wcsicmp(iter->c_str(), MapToModule.c_str()) == 0)
					{
						return false;
					}
				}
				return true;
			};
			if (CheckNeedAdd(item.MapToModule))
			{
				vDependModule.push_back(item.MapToModule);
			}
		}

		//function name to addr
		pLoadModule->ExportApis.FNameToAddr.push_back(item);

		if (!item.IsMap)
		{
			//addr map to function name
			pLoadModule->ExportApis.FunaddrToName.insert(std::pair<ULONGLONG, std::wstring>(item.ullFunctionAddr, item.name));
		}

		pNameTable++;
		pOrdinalTable++;
		dwRetCount++;
	}


	for (DWORD i = 0; i < pExportTable->NumberOfFunctions; i++)
	{
		//num 导出的函数
		if (((ULONG *)pFuncsAddress)[i] != 0)
		{
			pLoadModule->ExportApis.FuncExportNum[i + pExportTable->Base] = ullVmImageBase + ((ULONG *)pFuncsAddress)[i];
		}
	}

	if (pFuncsAddress)
	{
		free(pFuncsAddress);
	}
	return dwRetCount;
}


PVOID CPELoader::LoadImageFile(const WCHAR *filename, ULONGLONG *pulFileSize)
{
	bool bRet = false;
	HANDLE hfile = NULL;
	HANDLE hMapFile = NULL;
	PVOID pFileBase = NULL;

	do
	{
		hfile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hfile == INVALID_HANDLE_VALUE)
		{
			DWORD dwLass = GetLastError();
			break;
		}

		DWORD dwSizeHigh = 0;
		DWORD dwSizeLow = GetFileSize(hfile, &dwSizeHigh);
		if (dwSizeHigh == 0 && (dwSizeLow == 0 || dwSizeLow < 1024))
		{
			break;
		}

		if (pulFileSize)
		{
			*pulFileSize = ((ULONGLONG)dwSizeHigh << 32) + dwSizeLow;
		}

		hMapFile = CreateFileMappingW(hfile, NULL, PAGE_READONLY, dwSizeHigh, dwSizeLow, NULL);
		if (hMapFile == NULL)
		{
			break;
		}

		pFileBase = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, 0);
		if (pFileBase == NULL)
		{
			break;
		}

	} while (false);

	if (hMapFile)
	{
		CloseHandle(hMapFile);
	}
	if (hfile)
	{
		CloseHandle(hfile);
	}

	return pFileBase;

}

bool CPELoader::LoaderGetFileInfo(const WCHAR *filename, std::shared_ptr<sFileInfo> fInfo)
{
	bool bRet = false;
	PVOID pFileBase = NULL;

	do
	{
		pFileBase = LoadImageFile(filename, NULL);
		if (pFileBase == NULL)
		{
			break;
		}

		PIMAGE_NT_HEADERS pNTHeader = NULL;
		PIMAGE_SECTION_HEADER pSectionHeader = NULL;
		if (GetPeHeadInfo(pFileBase, &pNTHeader, &pSectionHeader))
		{
			int nPeType = PeloaderCheckNtHeader(pNTHeader);
			if (nPeType <= 0) //pe or dll
			{
				break;
			}
			fInfo->arch = uc_arch::UC_ARCH_X86;
			fInfo->osType = em_windows_pe;

			if (nPeType == IMAGE_FILE_EXECUTABLE_IMAGE)
			{
				fInfo->FileType = FILE_TYPE_EXEC;
			}
			else if (nPeType == IMAGE_FILE_DLL)
			{
				fInfo->FileType = FILE_TYPE_DYNAMIC;
			}
			else
			{
				break;
			}

			fInfo->BitType = GetPeImagesBits(pNTHeader);

			bRet = true;
		}
		else if (0)
		{
			//其他检测逻辑
		}
		else
		{
			break;
		}

	} while (false);

	if (pFileBase)
	{
		UnmapViewOfFile(pFileBase);
	}
	return bRet;
}

inline bool CPELoader::WriteVmMemory(const std::shared_ptr<CVmcpu> &pVmCpu, const std::vector<sVMMemWriteInfo>& vWriteInfo)
{
	if (vWriteInfo.size() > 0)
	{
		//fix up reloc
		for (std::vector<sVMMemWriteInfo>::const_iterator iter = vWriteInfo.begin(); iter != vWriteInfo.end(); ++iter)
		{
			assert(iter->dwSize == sizeof(ULONGLONG) || iter->dwSize == sizeof(ULONG));
			if (!pVmCpu->VmWriteMemory(iter->uladdr, iter->dwSize == sizeof(ULONGLONG) ? (const void *)&iter->a.ul64bitValue : (const void *)&iter->a.ul32bitValue, iter->dwSize))
			{
				assert(0);
				return false;
			}
		}
	}
	return true;
}

bool CPELoader::InitModuleSecurityCookie(PVOID pImageBase, ULONGLONG ullVmImageBase, DWORD dwsize, const std::shared_ptr<CVmcpu> &pVmCpu)
{
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_LOAD_CONFIG_DIRECTORY32 pConfigDir32 = NULL;
	PIMAGE_LOAD_CONFIG_DIRECTORY64 pConfigDir64 = NULL;
	ULONGLONG SecurityCookieRva = 0;
	ULONGLONG SecurityCookieValue = 0;
	ULONGLONG SecurityCookieValueOld = 0;

	if (!GetPeHeadInfo(pImageBase, &pNTHeader, &pSectionHeader))
	{
		return false;
	}
	BYTE bits = GetPeImagesBits(pNTHeader);
	if (bits == 0)
	{
		return false;
	}

	ULONGLONG FileImageBase = (ULONGLONG)BITS_NT_HEADER_OPTION(bits, pNTHeader, ImageBase);
	PIMAGE_DATA_DIRECTORY pDirTmp = bits == BIT_TYPE_32 ? &((PIMAGE_NT_HEADERS32)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] :
									   &((PIMAGE_NT_HEADERS64)pNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	if (pDirTmp->VirtualAddress == 0 || pDirTmp->Size == 0)
	{
		return true;
	}
	PVOID pTmp = (PVOID)((BYTE *)pImageBase + pDirTmp->VirtualAddress);
	if ((ULONGLONG)pTmp >= (ULONGLONG)pImageBase + dwsize)
	{
		return false;
	}

	if (bits == BIT_TYPE_32)
	{
		pConfigDir32 = (PIMAGE_LOAD_CONFIG_DIRECTORY32)pTmp;
		SecurityCookieRva = pConfigDir32->SecurityCookie - (ULONGLONG)FileImageBase;
		SecurityCookieValue = (ULONGLONG)*(ULONG *)((PBYTE)pImageBase + (ULONG)SecurityCookieRva);
	}
	else
	{
		pConfigDir64 = (PIMAGE_LOAD_CONFIG_DIRECTORY64)pTmp;
		SecurityCookieRva = pConfigDir64->SecurityCookie - (ULONGLONG)FileImageBase;
		SecurityCookieValue = *(ULONGLONG *)((PBYTE)pImageBase + (ULONG)SecurityCookieRva);
	}
	SecurityCookieValueOld = SecurityCookieValue;

	do 
	{
		SecurityCookieValue = GetRandomUlonglong();
		SecurityCookieValue &= ~0x0FFFFull;
		if (bits == BIT_TYPE_32)
		{
			SecurityCookieValue &= 0x0FFFFFFFFull;
		}
	} while (SecurityCookieValue == SecurityCookieValueOld);

	pVmCpu->VmWriteMemory(ullVmImageBase + SecurityCookieRva, &SecurityCookieValue, bits == BIT_TYPE_32 ? sizeof(DWORD) : sizeof(ULONGLONG));

	return true;
}

PVOID CPELoader::GetApiSetData(DWORD *dwRetSize)
{
	if (m_ApiSetData && m_dwApiSetDataSize > 0)
	{
		PVOID pRet = malloc(m_dwApiSetDataSize + 2);
		if (!pRet)
		{
			return NULL;
		}
		memcpy(pRet, m_ApiSetData, m_dwApiSetDataSize);
		if (dwRetSize)
		{
			*dwRetSize = m_dwApiSetDataSize;
		}
		return pRet;
	}
	ULONGLONG ulFizeSize = 0;
	PVOID pBase = LoadImageFile(L"c:/windows/system32/apisetschema.dll", &ulFizeSize);
	if (pBase == NULL)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!GetPeHeadInfo(pBase, &pNTHeader, &pSectionHeader))
	{
		UnmapViewOfFile(pBase);
		return NULL;
	}

	DWORD dwSections = pNTHeader->FileHeader.NumberOfSections;
	for (WORD i = 0; i < dwSections; i++)
	{
		if (pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)
		{
			continue;
		}
		if (strcmp((const char *)pSectionHeader[i].Name, ".apiset") == 0)
		{
			PVOID pRet = malloc(pSectionHeader[i].SizeOfRawData + 2);
			if (!pRet)
			{
				UnmapViewOfFile(pBase);
				return NULL;
			}
			memcpy(pRet, (PVOID)((char *)pBase + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData);
			if (dwRetSize)
			{
				*dwRetSize = pSectionHeader[i].SizeOfRawData;
			}
			UnmapViewOfFile(pBase);
			return pRet;
		}
	}

	UnmapViewOfFile(pBase);
	return NULL;
}







#define APISETAPI NTAPI

#define API_SET_SCHEMA_VERSION_V2       0x00000002
#define API_SET_SCHEMA_VERSION_V3       0x00000003 // No offline support.
#define API_SET_SCHEMA_VERSION_V4       0x00000004
#define API_SET_SCHEMA_VERSION_V6       0x00000006

typedef struct _API_SET_NAMESPACE {
	ULONG Version;
} API_SET_NAMESPACE, *PAPI_SET_NAMESPACE;


// API set schema version 6.
typedef struct _API_SET_NAMESPACE_V6 {
	ULONG Version;
	ULONG Size;
	ULONG Flags;
	ULONG Count;
	ULONG EntryOffset;  // API_SET_NAMESPACE_ENTRY_V6
	ULONG HashOffset;   // API_SET_NAMESPACE_HASH_ENTRY_V6
	ULONG HashFactor;
} API_SET_NAMESPACE_V6, *PAPI_SET_NAMESPACE_V6;

typedef struct _API_SET_NAMESPACE_ENTRY_V6 {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG HashedLength;
	ULONG ValueOffset;
	ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY_V6, *PAPI_SET_NAMESPACE_ENTRY_V6;

typedef struct _API_SET_HASH_ENTRY_V6 {
	ULONG Hash;
	ULONG Index;
} API_SET_HASH_ENTRY_V6, *PAPI_SET_HASH_ENTRY_V6;

typedef struct _API_SET_VALUE_ENTRY_V6 {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY_V6, *PAPI_SET_VALUE_ENTRY_V6;




// API set schema version 4.
typedef struct _API_SET_VALUE_ENTRY_V4 {
	ULONG Flags;        // 0x00
	ULONG NameOffset;   // 0x04
	ULONG NameLength;   // 0x08
	ULONG ValueOffset;  // 0x0C
	ULONG ValueLength;  // 0x10
} API_SET_VALUE_ENTRY_V4, *PAPI_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_VALUE_ARRAY_V4 {
	ULONG Flags;        // 0x00
	ULONG Count;        // 0x04
	API_SET_VALUE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V4, *PAPI_SET_VALUE_ARRAY_V4;

typedef struct _API_SET_NAMESPACE_ENTRY_V4 {
	ULONG Flags;
	ULONG NameOffset;
	ULONG NameLength;
	ULONG AliasOffset;
	ULONG AliasLength;
	ULONG DataOffset;   // API_SET_VALUE_ARRAY_V4
} API_SET_NAMESPACE_ENTRY_V4, *PAPI_SET_NAMESPACE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_ARRAY_V4 {
	ULONG Version;      // 0x00
	ULONG Size;         // 0x04
	ULONG Flags;        // 0x08
	ULONG Count;        // 0x0C
	API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V4, *PAPI_SET_NAMESPACE_ARRAY_V4;

#define API_SET_SCHEMA_FLAGS_SEALED              0x00000001
#define API_SET_SCHEMA_FLAGS_HOST_EXTENSION      0x00000002
#define API_SET_SCHEMA_ENTRY_FLAGS_SEALED        0x00000001
#define API_SET_SCHEMA_ENTRY_FLAGS_EXTENSION     0x00000002



// API set schema version 3.
typedef struct _API_SET_VALUE_ENTRY_V3 {
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY_V3, *PAPI_SET_VALUE_ENTRY_V3;

typedef struct _API_SET_VALUE_ARRAY_V3 {
	ULONG Count;
	API_SET_VALUE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V3, *PAPI_SET_VALUE_ARRAY_V3;

typedef struct _API_SET_NAMESPACE_ENTRY_V3 {
	ULONG NameOffset;
	ULONG NameLength;
	ULONG DataOffset;   // API_SET_VALUE_ARRAY_V3
} API_SET_NAMESPACE_ENTRY_V3, *PAPI_SET_NAMESPACE_ENTRY_V3;

typedef struct _API_SET_NAMESPACE_ARRAY_V3 {
	ULONG Version;
	ULONG Count;
	API_SET_NAMESPACE_ENTRY_V3 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V3, *PAPI_SET_NAMESPACE_ARRAY_V3;


// Support for downlevel API set schema version 2.
typedef struct _API_SET_VALUE_ENTRY_V2 {
	ULONG NameOffset;
	ULONG NameLength;
	ULONG ValueOffset;
	ULONG ValueLength;
} API_SET_VALUE_ENTRY_V2, *PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2 {
	ULONG Count;
	API_SET_VALUE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_VALUE_ARRAY_V2, *PAPI_SET_VALUE_ARRAY_V2;

typedef struct _API_SET_NAMESPACE_ENTRY_V2 {
	ULONG NameOffset;
	ULONG NameLength;
	ULONG DataOffset;   // API_SET_VALUE_ARRAY_V2
} API_SET_NAMESPACE_ENTRY_V2, *PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2 {
	ULONG Version;
	ULONG Count;
	API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
} API_SET_NAMESPACE_ARRAY_V2, *PAPI_SET_NAMESPACE_ARRAY_V2;



#define API_SET_PREFIX_API_     (ULONGLONG)0x002D004900500041 /* L"api-" */
#define API_SET_PREFIX_EXT_     (ULONGLONG)0x002D005400580045 /* L"ext-" */
#define API_SET_DLL_EXTENSTION  (ULONGLONG)0x004C004C0044002E /* L".DLL" */


#define API_SET_CHAR_TO_LOWER(c) \
								(((WCHAR)((c) - L'A') <= (L'a' - L'A' - 1)) ? ((c) + 0x20) : (c))


#define GET_API_SET_NAMESPACE_ENTRY_V6(ApiSetNamespace, Index) \
								((PAPI_SET_NAMESPACE_ENTRY_V6)((ULONG_PTR)(ApiSetNamespace) + \
                                ((PAPI_SET_NAMESPACE_V6)(ApiSetNamespace))->EntryOffset + \
                                ((Index) * sizeof(API_SET_NAMESPACE_ENTRY_V6))))

#define GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetNamespace, Entry, Index) \
								((PAPI_SET_VALUE_ENTRY_V6)((ULONG_PTR)(ApiSetNamespace) + \
                                ((PAPI_SET_NAMESPACE_ENTRY_V6)(Entry))->ValueOffset + \
                                ((Index) * sizeof(API_SET_VALUE_ENTRY_V6))))

#define GET_API_SET_NAMESPACE_ENTRY_NAME_V6(ApiSetNamespace, Entry) \
								((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + ((PAPI_SET_NAMESPACE_ENTRY_V6)(Entry))->NameOffset))

#define GET_API_SET_NAMESPACE_ENTRY_VALUE_V6(ApiSetNamespace, Entry) \
								((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + ((PAPI_SET_NAMESPACE_ENTRY_V6)(Entry))->ValueOffset))

#define GET_API_SET_VALUE_ENTRY_NAME_V6(ApiSetNamespace, Entry) \
								((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + ((PAPI_SET_VALUE_ENTRY_V6)(Entry))->NameOffset))

#define GET_API_SET_VALUE_ENTRY_VALUE_V6(ApiSetNamespace, Entry) \
								((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + ((PAPI_SET_VALUE_ENTRY_V6)(Entry))->ValueOffset))

#define GET_API_SET_HASH_ENTRY_V6(ApiSetNamespace, Middle) \
								((PAPI_SET_HASH_ENTRY_V6)((ULONG_PTR)(ApiSetNamespace) + \
								((PAPI_SET_NAMESPACE_V6)(ApiSetNamespace))->HashOffset + \
                                ((Middle) * sizeof(API_SET_HASH_ENTRY_V6))))



#define GET_API_SET_NAMESPACE_ENTRY_V4(ApiSetNamespace, Index) \
								((PAPI_SET_NAMESPACE_ENTRY_V4)(((PAPI_SET_NAMESPACE_ARRAY_V4)(ApiSetNamespace))->Array + \
                                        Index))

#define GET_API_SET_NAMESPACE_ENTRY_NAME_V4(ApiSetNamespace, NamespaceEntry) \
								((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + \
								((PAPI_SET_NAMESPACE_ENTRY_V4)(NamespaceEntry))->NameOffset))

#define GET_API_SET_NAMESPACE_ENTRY_DATA_V4(ApiSetNamespace, NamespaceEntry) \
								((PAPI_SET_VALUE_ARRAY_V4)((ULONG_PTR)(ApiSetNamespace) + \
                                ((PAPI_SET_NAMESPACE_ENTRY_V4)(NamespaceEntry))->DataOffset))

#define GET_API_SET_VALUE_ENTRY_V4(ApiSetNamespace, ResolvedValueArray, Index) \
								((PAPI_SET_VALUE_ENTRY_V4)(((PAPI_SET_VALUE_ARRAY_V4)(ResolvedValueArray))->Array + \
                                  Index))

#define GET_API_SET_VALUE_ENTRY_NAME_V4(ApiSetNamespace, ApiSetValueEntry) \
								((WCHAR*)((ULONG_PTR)(ApiSetNamespace) + \
								((PAPI_SET_VALUE_ENTRY_V4)(ApiSetValueEntry))->NameOffset))

#define GET_API_SET_VALUE_ENTRY_VALUE_V4(ApiSetNamespace, ApiSetValueEntry) \
								((WCHAR*)((ULONG_PTR)(ApiSetNamespace) + \
								((PAPI_SET_VALUE_ENTRY_V4)(ApiSetValueEntry))->ValueOffset))



#define GET_API_SET_NAMESPACE_ENTRY_V3(ApiSetNamespace, Index) \
								((PAPI_SET_NAMESPACE_ENTRY_V3)(((PAPI_SET_NAMESPACE_ARRAY_V3)(ApiSetNamespace))->Array + \
                                  Index))

#define GET_API_SET_NAMESPACE_ENTRY_NAME_V3(ApiSetNamespace, NamespaceEntry) \
								((PWCHAR)((ULONG_PTR)(ApiSetNamespace) + \
								((PAPI_SET_NAMESPACE_ENTRY_V3)(NamespaceEntry))->NameOffset))

#define GET_API_SET_NAMESPACE_ENTRY_DATA_V3(ApiSetNamespace, NamespaceEntry) \
								((PAPI_SET_VALUE_ARRAY_V3)((ULONG_PTR)(ApiSetNamespace) + \
                                ((PAPI_SET_NAMESPACE_ENTRY_V3)(NamespaceEntry))->DataOffset))

#define GET_API_SET_VALUE_ENTRY_V3(ApiSetNamespace, ResolvedValueArray, Index) \
								((PAPI_SET_VALUE_ENTRY_V3)(((PAPI_SET_VALUE_ARRAY_V3)(ResolvedValueArray))->Array + \
                                  Index))

#define GET_API_SET_VALUE_ENTRY_NAME_V3(ApiSetNamespace, ApiSetValueEntry) \
								((WCHAR*)((ULONG_PTR)(ApiSetNamespace) + \
								((PAPI_SET_VALUE_ENTRY_V3)(ApiSetValueEntry))->NameOffset))

#define GET_API_SET_VALUE_ENTRY_VALUE_V3(ApiSetNamespace, ApiSetValueEntry) \
								((WCHAR*)((ULONG_PTR)(ApiSetNamespace) + \
								((PAPI_SET_VALUE_ENTRY_V3)(ApiSetValueEntry))->ValueOffset))


#define GET_API_SET_NAMESPACE_ENTRY_V2(ApiSetNamespace, Index) \
								((PAPI_SET_NAMESPACE_ENTRY_V2)((ULONG_PTR)(ApiSetNamespace) + \
                                ((PAPI_SET_NAMESPACE_ARRAY_V2)(ApiSetNamespace))->Array + \
                                  Index))

#define GET_API_SET_VALUE_ENTRY_V2(ResolvedValueArray, Index) \
								((PAPI_SET_VALUE_ENTRY_V2)(((PAPI_SET_VALUE_ARRAY_V2)(ResolvedValueArray))->Array + \
                                  Index))




#define RTL_UPCASE(wch) (                                                       \
    ((wch) < 'a' ?                                                              \
        (wch)                                                                   \
    :                                                                           \
        ((wch) <= 'z' ?                                                         \
            (wch) - ('a'-'A')                                                   \
        :                                                                       \
            ((WCHAR)(wch))                                                      \
        )                                                                       \
    )                                                                           \
)

#define RTL_DOWNCASE(wch) (                                                     \
    ((wch) < 'A' ?                                                              \
        (wch)                                                                   \
    :                                                                           \
        ((wch) <= 'Z' ?                                                         \
            (wch) + ('a'-'A')                                                   \
        :                                                                       \
            ((WCHAR)(wch))                                                      \
        )                                                                       \
    )                                                                           \
)
#define STATUS_INVALID_BUFFER_SIZE       ((LONG)0xC0000206L)
static
LONG
NTAPI
RtlCompareUnicodeStrings(
	IN CONST WCHAR* String1,
	IN SIZE_T Length1,
	IN CONST WCHAR* String2,
	IN SIZE_T Length2,
	IN BOOLEAN CaseInSensitive
)
{
	CONST WCHAR* s1, *s2, *Limit;
	LONG n1, n2;
	UINT32 c1, c2;

	if (Length1 > LONG_MAX || Length2 > LONG_MAX) 
	{
		return STATUS_INVALID_BUFFER_SIZE;
	}

	s1 = String1;
	s2 = String2;
	n1 = (LONG)Length1;
	n2 = (LONG)Length2;

	Limit = (WCHAR*)((CHAR*)s1 + (n1 <= n2 ? n1 : n2));
	if (CaseInSensitive) 
	{
		while (s1 < Limit) 
		{
			c1 = *s1;
			c2 = *s2;
			if (c1 != c2)
			{
				//
				// Note that this needs to reference the translation table!
				//
				c1 = RTL_UPCASE(c1);
				c2 = RTL_UPCASE(c2);
				if (c1 != c2)
				{
					return (INT32)(c1)-(INT32)(c2);
				}
			}
			s1 += 1;
			s2 += 1;
		}
	}
	else 
	{
		while (s1 < Limit) 
		{
			c1 = *s1;
			c2 = *s2;
			if (c1 != c2) 
			{
				return (LONG)(c1)-(LONG)(c2);
			}
			s1 += 1;
			s2 += 1;
		}
	}

	return n1 - n2;
}


PVOID CPELoader::ApiSetpSearchForApiSetHostV2(PVOID ApiSetValueArray, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength, PVOID ApiSetNamespace)
{
	LONG Low;
	LONG Middle;
	LONG High;
	LONG Result;
	PAPI_SET_VALUE_ENTRY_V2 ApiSetValueEntry = NULL;
	PAPI_SET_VALUE_ARRAY_V2 ApiSetValueArrayTmp = (PAPI_SET_VALUE_ARRAY_V2)ApiSetValueArray;

	Low = 1; // skip first entry.
	High = ApiSetValueArrayTmp->Count - 1;

	while (High >= Low)
	{
		Middle = (High + Low) >> 1;

		ApiSetValueEntry = &ApiSetValueArrayTmp->Array[Middle];
		const WCHAR *ApiSetHostString = (WCHAR*)((ULONG_PTR)ApiSetNamespace + ApiSetValueEntry->NameOffset);
		Result = RtlCompareUnicodeStrings(ApiSetNameToResolve,
			ApiSetNameToResolveLength,
			ApiSetHostString,
			(USHORT)ApiSetValueEntry->NameLength / sizeof(WCHAR),
			TRUE);
		if (Result == STATUS_INVALID_BUFFER_SIZE)
		{
			return NULL;
		}
		if (Result < 0)
		{
			High = Middle - 1;
		}
		else if (Result > 0) 
		{
			Low = Middle + 1;
		}
		else
		{
			return ApiSetValueEntry;
		}
	}

	return NULL;
}



bool CPELoader::ApiSetResolveToHostV2(PVOID ApiSetMap, const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen)
{
	bool bRet = false;
	WCHAR *ApiSetNameBuffer = NULL;
	ULONGLONG ApiSetNameBufferPrefix = 0;
	LONG Low = 0;
	LONG Middle = 0;
	LONG High = 0;
	LONG Result = 0;
	PAPI_SET_NAMESPACE_ARRAY_V2 ApiSetNamespaceArray = NULL;
	PAPI_SET_NAMESPACE_ENTRY_V2 ApiSetNamespaceEntry = NULL;
	PAPI_SET_VALUE_ARRAY_V2 ApiSetValueArray = NULL;
	PAPI_SET_VALUE_ENTRY_V2 HostLibraryEntry = NULL;
	WCHAR *wsTmp = NULL;

	do
	{
		if (wcslen(wsMsDll) * sizeof(WCHAR) < sizeof(API_SET_PREFIX_API_))
		{
			break;
		}

		ApiSetNameBuffer = (WCHAR *)malloc((wcslen(wsMsDll) + 1) * sizeof(WCHAR));
		if (ApiSetNameBuffer == NULL)
		{
			break;
		}
		memcpy(ApiSetNameBuffer, wsMsDll, wcslen(wsMsDll) * sizeof(WCHAR));
		ApiSetNameBuffer[wcslen(wsMsDll)] = 0;
		ApiSetNameBufferPrefix = *(ULONGLONG*)ApiSetNameBuffer;
		ApiSetNameBufferPrefix &= ~(ULONGLONG)0x0000002000200020;
		if ((ApiSetNameBufferPrefix != API_SET_PREFIX_API_))
		{
			break;
		}

		//
		// Skip the prefix.
		//
		wsTmp = (WCHAR *)((PBYTE)ApiSetNameBuffer + sizeof(API_SET_PREFIX_API_));

		//
		// Cut off the '.DLL' extension.
		//
		if (wcslen(wsTmp) * sizeof(WCHAR) >= sizeof(API_SET_DLL_EXTENSTION) &&
			wsTmp[(wcslen(wsTmp) * sizeof(WCHAR) - sizeof(API_SET_DLL_EXTENSTION)) / sizeof(WCHAR)] == L'.')
		{
			wsTmp[(wcslen(wsTmp) * sizeof(WCHAR) - sizeof(API_SET_DLL_EXTENSTION)) / sizeof(WCHAR)] = 0;
		}

		ApiSetNamespaceArray = (PAPI_SET_NAMESPACE_ARRAY_V2)ApiSetMap;
		ApiSetNamespaceEntry = NULL;

		Low = 0;
		High = (LONG)(ApiSetNamespaceArray->Count - 1);

		while (High >= Low) 
		{
			Middle = (Low + High) >> 1;

			ApiSetNamespaceEntry = GET_API_SET_NAMESPACE_ENTRY_V2(ApiSetMap, Middle);
			const WCHAR *ApiSetNamespaceString = (WCHAR*)((ULONG_PTR)ApiSetMap + ApiSetNamespaceEntry->NameOffset);
			Result = RtlCompareUnicodeStrings(wsTmp,
											 (USHORT)wcslen(wsTmp),
											  ApiSetNamespaceString,
											 (USHORT)ApiSetNamespaceEntry->NameLength / sizeof(WCHAR),
											  TRUE);
			if (Result == STATUS_INVALID_BUFFER_SIZE)
			{
				High = 0;
				Low = 1;
				break;
			}

			if (Result < 0) 
			{
				High = Middle - 1;
			}
			else if (Result > 0) 
			{
				Low = Middle + 1;
			}
			else 
			{
				break;
			}
		}

		if (High < Low) 
		{
			break;
		}

		//
		// Get the namspace value array.
		//
		ApiSetValueArray = (PAPI_SET_VALUE_ARRAY_V2)((ULONG_PTR)ApiSetMap + ApiSetNamespaceEntry->DataOffset);

		//
		// Look for aliases in hosts libraries if necessary.
		//
		if (ApiSetValueArray->Count > 1 && wsParentName) 
		{

			HostLibraryEntry = (PAPI_SET_VALUE_ENTRY_V2)ApiSetpSearchForApiSetHostV2(ApiSetValueArray,
				wsParentName,
				(USHORT)wcslen(wsParentName),
				ApiSetMap);
		}
		else if (ApiSetValueArray->Count > 0)
		{
			HostLibraryEntry = GET_API_SET_VALUE_ENTRY_V2(ApiSetValueArray, ApiSetValueArray->Count - 1);
		}
		else 
		{
			break;
		}

		memcpy(wsRealDll, GET_API_SET_VALUE_ENTRY_VALUE_V4(ApiSetMap, HostLibraryEntry), min(HostLibraryEntry->ValueLength, dwLen));
		bRet = true;

	} while (false);

	if (ApiSetNameBuffer)
	{
		free(ApiSetNameBuffer);
	}

	return bRet;
}

PVOID CPELoader::ApiSetpSearchForApiSetHostV3(PVOID ApiSetValueArray, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength, PVOID ApiSetNamespace)
{
	LONG Low;
	LONG Middle;
	LONG High;
	LONG Result;
	PAPI_SET_VALUE_ENTRY_V3 ApiSetValueEntry;
	PAPI_SET_VALUE_ARRAY_V3 ApiSetValueArrayTmp = (PAPI_SET_VALUE_ARRAY_V3)ApiSetValueArray;
	Low = 1; // skip first entry.
	High = ApiSetValueArrayTmp->Count - 1;

	while (High >= Low) 
	{
		Middle = (High + Low) >> 1;
		ApiSetValueEntry = GET_API_SET_VALUE_ENTRY_V3(ApiSetNamespace, ApiSetValueArray, Middle);
		Result = RtlCompareUnicodeStrings(ApiSetNameToResolve,
										  ApiSetNameToResolveLength,
										  GET_API_SET_VALUE_ENTRY_NAME_V3(ApiSetNamespace, ApiSetValueEntry),
										  (USHORT)ApiSetValueEntry->NameLength / sizeof(WCHAR),
										  TRUE);
		if (Result == STATUS_INVALID_BUFFER_SIZE)
		{
			return NULL;
		}

		if (Result < 0) 
		{
			High = Middle - 1;
		}
		else if (Result > 0) 
		{
			Low = Middle + 1;
		}
		else 
		{
			return ApiSetValueEntry;
		}
	}

	return NULL;
}



bool CPELoader::ApiSetResolveToHostV3(PVOID ApiSetMap, const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen)
{
	bool bRet = false;
	WCHAR *ApiSetNameBuffer = NULL;
	ULONGLONG ApiSetNameBufferPrefix = 0;
	LONG Low = 0;
	LONG Middle = 0;
	LONG High = 0;
	LONG Result = 0;
	PAPI_SET_NAMESPACE_ARRAY_V3 ApiSetNamespaceArray = NULL;
	PAPI_SET_NAMESPACE_ENTRY_V3 ResolvedNamespaceEntry = NULL;
	PAPI_SET_VALUE_ARRAY_V3 ResolvedValueArray = NULL;
	PAPI_SET_VALUE_ENTRY_V3 HostLibraryEntry = NULL;
	WCHAR *wsTmp = NULL;


	do
	{
		if (wcslen(wsMsDll) * sizeof(WCHAR) < sizeof(API_SET_PREFIX_API_))
		{
			break;
		}

		ApiSetNameBuffer = (WCHAR *)malloc((wcslen(wsMsDll) + 1) * sizeof(WCHAR));
		if (ApiSetNameBuffer == NULL)
		{
			break;
		}
		memcpy(ApiSetNameBuffer, wsMsDll, wcslen(wsMsDll) * sizeof(WCHAR));
		ApiSetNameBuffer[wcslen(wsMsDll)] = 0;
		ApiSetNameBufferPrefix = *(ULONGLONG*)ApiSetNameBuffer;
		ApiSetNameBufferPrefix &= ~(ULONGLONG)0x0000002000200020;
		if ((ApiSetNameBufferPrefix != API_SET_PREFIX_API_) &&
			(ApiSetNameBufferPrefix != API_SET_PREFIX_EXT_))
		{
			break;
		}

		//
		// Skip the prefix.
		//
		wsTmp = (WCHAR *)((PBYTE)ApiSetNameBuffer + sizeof(API_SET_PREFIX_API_));

		//
		// Cut off the '.DLL' extension.
		//
		if (wcslen(wsTmp) * sizeof(WCHAR) >= sizeof(API_SET_DLL_EXTENSTION) &&
			wsTmp[(wcslen(wsTmp) * sizeof(WCHAR) - sizeof(API_SET_DLL_EXTENSTION)) / sizeof(WCHAR)] == L'.')
		{
			wsTmp[(wcslen(wsTmp) * sizeof(WCHAR) - sizeof(API_SET_DLL_EXTENSTION)) / sizeof(WCHAR)] = 0;
		}

		ApiSetNamespaceArray = (PAPI_SET_NAMESPACE_ARRAY_V3)ApiSetMap;
		ResolvedNamespaceEntry = NULL;

		Low = 0;
		High = (LONG)(ApiSetNamespaceArray->Count - 1);

		while (High >= Low) 
		{
			Middle = (Low + High) >> 1;

			ResolvedNamespaceEntry = GET_API_SET_NAMESPACE_ENTRY_V3(ApiSetMap, Middle);

			Result = RtlCompareUnicodeStrings(wsTmp,
				(USHORT)wcslen(wsTmp),
				GET_API_SET_NAMESPACE_ENTRY_NAME_V3(ApiSetMap, ResolvedNamespaceEntry),
				(USHORT)ResolvedNamespaceEntry->NameLength / sizeof(WCHAR),
				TRUE);

			if (STATUS_INVALID_BUFFER_SIZE == Result)
			{
				Low = 1;
				High = 0;
				break;
			}

			if (Result < 0)
			{
				High = Middle - 1;
			}
			else if (Result > 0) 
			{
				Low = Middle + 1;
			}
			else 
			{
				break;
			}
		}

		if (High < Low) 
		{
			break;
		}

		//
		// Get the namspace value array.
		//
		ResolvedValueArray = GET_API_SET_NAMESPACE_ENTRY_DATA_V3(ApiSetMap, ResolvedNamespaceEntry);

		//
		// Look for aliases in hosts libraries if necessary.
		//
		if (ResolvedValueArray->Count > 1 && wsParentName) 
		{

			HostLibraryEntry = (PAPI_SET_VALUE_ENTRY_V3)ApiSetpSearchForApiSetHostV3(ResolvedValueArray,
				wsParentName,
				(USHORT)wcslen(wsParentName),
				(PAPI_SET_NAMESPACE_ARRAY_V3)ApiSetMap);
		}
		else if (ResolvedValueArray->Count > 0)
		{
			HostLibraryEntry = GET_API_SET_VALUE_ENTRY_V3(ApiSetMap, ResolvedValueArray, ResolvedValueArray->Count - 1);
		}
		else
		{
			break;
		}

		memcpy(wsRealDll, GET_API_SET_VALUE_ENTRY_VALUE_V4(ApiSetMap, HostLibraryEntry), min(HostLibraryEntry->ValueLength, dwLen));
		bRet = true;

	} while (false);

	if (ApiSetNameBuffer)
	{
		free(ApiSetNameBuffer);
	}

	return bRet;
}


PVOID
CPELoader::ApiSetpSearchForApiSetV4(
	PVOID ApiSetNamespace,
	const WCHAR * ApiSetNameToResolve,
	USHORT ApiSetNameToResolveLength)
{
	LONG Low;
	LONG Middle;
	LONG High;
	LONG Result;
	PAPI_SET_NAMESPACE_ARRAY_V4 ApiSetNamespaceArray;
	PAPI_SET_NAMESPACE_ENTRY_V4 ApiSetNamespaceEntry;
	PAPI_SET_NAMESPACE ApiSetNamespaceTmp = (PAPI_SET_NAMESPACE)ApiSetNamespace;

	ApiSetNamespaceArray = (PAPI_SET_NAMESPACE_ARRAY_V4)ApiSetNamespace;

	Low = 0;
	High = (LONG)(ApiSetNamespaceArray->Count - 1);

	while (High >= Low) 
	{
		Middle = (High + Low) >> 1;

		ApiSetNamespaceEntry = GET_API_SET_NAMESPACE_ENTRY_V4(ApiSetNamespaceTmp, Middle);

		Result = RtlCompareUnicodeStrings(ApiSetNameToResolve,
			ApiSetNameToResolveLength,
			GET_API_SET_NAMESPACE_ENTRY_NAME_V4(ApiSetNamespaceTmp, ApiSetNamespaceEntry),
			(USHORT)ApiSetNamespaceEntry->NameLength / sizeof(WCHAR),
			TRUE);

		if (STATUS_INVALID_BUFFER_SIZE == Result)
		{
			return NULL;
		}

		if (Result < 0) 
		{
			High = Middle - 1;
		}
		else if (Result > 0) 
		{
			Low = Middle + 1;
		}
		else 
		{
			return ApiSetNamespaceEntry;
		}
	}

	return NULL;
}



PVOID CPELoader::ApiSetpSearchForApiSetHostV4(PVOID ApiSetVEntry, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength, PVOID ApiSetNamespace)
{
	LONG Low;
	LONG Middle;
	LONG High;
	LONG Result;
	PAPI_SET_VALUE_ENTRY_V4 ApiSetHostEntry;
	PAPI_SET_VALUE_ARRAY_V4 ApiSetValueArray = (PAPI_SET_VALUE_ARRAY_V4)ApiSetVEntry;

	Low = 1; // skip first entry.
	High = (LONG)(ApiSetValueArray->Count - 1);

	while (High >= Low) 
	{
		Middle = (High + Low) >> 1;

		ApiSetHostEntry = GET_API_SET_VALUE_ENTRY_V4(ApiSetNamespace, ApiSetValueArray, Middle);

		Result = RtlCompareUnicodeStrings(ApiSetNameToResolve,
			ApiSetNameToResolveLength,
			GET_API_SET_VALUE_ENTRY_NAME_V4(ApiSetNamespace, ApiSetHostEntry),
			(USHORT)ApiSetHostEntry->NameLength / sizeof(WCHAR),
			TRUE);
		if (STATUS_INVALID_BUFFER_SIZE == Result)
		{
			return NULL;
		}

		if (Result < 0) 
		{
			High = Middle - 1;
		}
		else if (Result > 0) 
		{
			Low = Middle + 1;
		}
		else 
		{
			return ApiSetHostEntry;
		}
	}

	return NULL;
}



bool CPELoader::ApiSetResolveToHostV4(PVOID ApiSetMap, const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen)
{
	bool bRet = false;
	WCHAR *ApiSetNameBuffer = NULL;
	ULONGLONG ApiSetNameBufferPrefix;
	PAPI_SET_NAMESPACE_ENTRY_V4 ResolvedNamespaceEntry;
	PAPI_SET_VALUE_ARRAY_V4 ResolvedValueArray;
	PAPI_SET_VALUE_ENTRY_V4 HostLibraryEntry;
	WCHAR *wsTmp = NULL;


	do
	{
		if (wcslen(wsMsDll) * sizeof(WCHAR) < sizeof(API_SET_PREFIX_API_))
		{
			break;
		}

		ApiSetNameBuffer = (WCHAR *)malloc((wcslen(wsMsDll) + 1) * sizeof(WCHAR));
		if (ApiSetNameBuffer == NULL)
		{
			break;
		}
		memcpy(ApiSetNameBuffer, wsMsDll, wcslen(wsMsDll) * sizeof(WCHAR));
		ApiSetNameBuffer[wcslen(wsMsDll)] = 0;
		ApiSetNameBufferPrefix = *(ULONGLONG*)ApiSetNameBuffer;
		ApiSetNameBufferPrefix &= ~(ULONGLONG)0x0000002000200020;
		if ((ApiSetNameBufferPrefix != API_SET_PREFIX_API_) &&
			(ApiSetNameBufferPrefix != API_SET_PREFIX_EXT_))
		{
			break;
		}

		//
		// Skip the prefix.
		//
		wsTmp = (WCHAR *)((PBYTE)ApiSetNameBuffer + sizeof(API_SET_PREFIX_API_));

		//
		// Cut off the '.DLL' extension.
		//
		if (wcslen(wsTmp) * sizeof(WCHAR) >= sizeof(API_SET_DLL_EXTENSTION) &&
			wsTmp[(wcslen(wsTmp) * sizeof(WCHAR) - sizeof(API_SET_DLL_EXTENSTION)) / sizeof(WCHAR)] == L'.')
		{
			wsTmp[(wcslen(wsTmp) * sizeof(WCHAR) - sizeof(API_SET_DLL_EXTENSTION)) / sizeof(WCHAR)] = 0;
		}


		ResolvedNamespaceEntry = (PAPI_SET_NAMESPACE_ENTRY_V4)ApiSetpSearchForApiSetV4(ApiSetMap, wsTmp, (USHORT)wcslen(wsTmp));
		if (!ResolvedNamespaceEntry)
		{
			break;
		}

		//
		// Get the namspace value array.
		//
		ResolvedValueArray = GET_API_SET_NAMESPACE_ENTRY_DATA_V4(ApiSetMap, ResolvedNamespaceEntry);

		//
		// Look for aliases in hosts libraries if necessary.
		//
		if (ResolvedValueArray->Count > 1 && wsParentName)
		{
			HostLibraryEntry = (PAPI_SET_VALUE_ENTRY_V4)ApiSetpSearchForApiSetHostV4(ResolvedValueArray, wsParentName, (USHORT)wcslen(wsParentName), (PAPI_SET_NAMESPACE_ARRAY_V4)ApiSetMap);
		}
		else if (ResolvedValueArray->Count > 0)
		{
			HostLibraryEntry = GET_API_SET_VALUE_ENTRY_V4(ApiSetMap, ResolvedValueArray, ResolvedValueArray->Count - 1);
		}
		else
		{
			break;
		}

		memcpy(wsRealDll, GET_API_SET_VALUE_ENTRY_VALUE_V4(ApiSetMap, HostLibraryEntry), min(HostLibraryEntry->ValueLength, dwLen));
		bRet = true;

	} while (false);

	if (ApiSetNameBuffer)
	{
		free(ApiSetNameBuffer);
	}

	return bRet;
}



PVOID CPELoader::ApiSetpSearchForApiSetV6(PVOID ApiSetMap, const WCHAR *ApiSetNameToResolve, USHORT ApiSetNameToResolveLength)
{
	const WCHAR *pwc = NULL;
	USHORT Count = 0;
	ULONG HashKey = 0;
	LONG Low = 0;
	LONG Middle = 0;
	LONG High = 0;
	PAPI_SET_HASH_ENTRY_V6 HashEntry = NULL;
	PAPI_SET_NAMESPACE_ENTRY_V6 FoundEntry = NULL;
	PAPI_SET_NAMESPACE_V6 ApiSetNamespace = (PAPI_SET_NAMESPACE_V6)ApiSetMap;

	if (!ApiSetNameToResolveLength)
	{
		return NULL;
	}

	HashKey = 0;
	pwc = ApiSetNameToResolve;
	Count = ApiSetNameToResolveLength;
	do {
		HashKey = HashKey * ApiSetNamespace->HashFactor + (USHORT)API_SET_CHAR_TO_LOWER(*pwc);
		++pwc;
		--Count;
	} while (Count);

	FoundEntry = NULL;
	Low = 0;
	Middle = 0;
	High = (LONG)ApiSetNamespace->Count - 1;

	while (High >= Low)
	{
		Middle = (Low + High) >> 1;
		HashEntry = GET_API_SET_HASH_ENTRY_V6(ApiSetNamespace, Middle);
		if (HashKey < HashEntry->Hash)
		{
			High = Middle - 1;
		}
		else if (HashKey > HashEntry->Hash)
		{
			Low = Middle + 1;
		}
		else
		{
			FoundEntry = GET_API_SET_NAMESPACE_ENTRY_V6(ApiSetNamespace, HashEntry->Index);
			break;
		}
	}

	if (High < Low)
	{
		return NULL;
	}

	if (RtlCompareUnicodeStrings(ApiSetNameToResolve,
		ApiSetNameToResolveLength,
		GET_API_SET_NAMESPACE_ENTRY_NAME_V6(ApiSetNamespace, FoundEntry),
		(USHORT)FoundEntry->HashedLength / sizeof(WCHAR),
		TRUE) == 0) 
	{
		return FoundEntry;
	}
	return NULL;
}




PVOID CPELoader::ApiSetpSearchForApiSetHostV6(
	 PVOID ApiSetEntry,
	 const WCHAR *ApiSetNameToResolve,
	 USHORT ApiSetNameToResolveLength,
	 PVOID ApiSetNamespace)
{
	LONG Low;
	LONG Middle;
	LONG High;
	LONG Result;
	PAPI_SET_VALUE_ENTRY_V6 FoundEntry;
	PAPI_SET_VALUE_ENTRY_V6 ApiSetHostEntry;
	PAPI_SET_NAMESPACE_ENTRY_V6 Entry = (PAPI_SET_NAMESPACE_ENTRY_V6)ApiSetEntry;
	PAPI_SET_NAMESPACE_V6 ApiSetNamespaceTmp = (PAPI_SET_NAMESPACE_V6)ApiSetNamespace;


	FoundEntry = GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetNamespaceTmp, Entry, 0);
	High = (LONG)(Entry->ValueCount - 1);
	if (!High) 
	{
		return FoundEntry;
	}

	// skip the first entry.
	Low = 1;

	while (Low <= High) 
	{
		Middle = (Low + High) >> 1;
		ApiSetHostEntry = GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetNamespaceTmp, Entry, Middle);
		Result = RtlCompareUnicodeStrings(ApiSetNameToResolve,
										  ApiSetNameToResolveLength,
										  GET_API_SET_VALUE_ENTRY_NAME_V6(ApiSetNamespaceTmp, ApiSetHostEntry),
										  (USHORT)ApiSetHostEntry->NameLength / sizeof(WCHAR),
										  TRUE);
		if (STATUS_INVALID_BUFFER_SIZE == Result)
		{
			return NULL;
		}
		if (Result < 0)
		{
			High = Middle - 1;
		}
		else if (Result > 0) 
		{
			Low = Middle + 1;
		}
		else
		{
			FoundEntry = GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetNamespaceTmp, Entry, Middle);
			break;
		}
	}

	return FoundEntry;
}

bool CPELoader::ApiSetResolveToHostV6(PVOID ApiSetMap, const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen)
{
	const WCHAR *ApiSetNameBuffer = NULL;
	const WCHAR *pwc = NULL;
	ULONG ApiSetNameBufferLength = 0;
	USHORT ApiSetNameNoExtLength = 0;
	PAPI_SET_NAMESPACE_ENTRY_V6 ResolvedNamespaceEntry = NULL;
	PAPI_SET_VALUE_ENTRY_V6 HostLibraryEntry = NULL;
	ULONGLONG ApiSetNameBufferPrefix = 0;
	bool bRet = false;

	do 
	{
		if (wcslen(wsMsDll) * sizeof(WCHAR) < sizeof(API_SET_PREFIX_API_))
		{
			break;
		}
		ApiSetNameBuffer = wsMsDll;
		ApiSetNameBufferPrefix = *(ULONGLONG*)ApiSetNameBuffer;
		ApiSetNameBufferPrefix &= ~(ULONGLONG)0x0000002000200020;
		if ((ApiSetNameBufferPrefix != API_SET_PREFIX_API_) &&
			(ApiSetNameBufferPrefix != API_SET_PREFIX_EXT_)) 
		{
			break;
		}

		ApiSetNameBufferLength = (ULONG)(wcslen(wsMsDll) * sizeof(WCHAR));
		pwc = (WCHAR*)((ULONG_PTR)ApiSetNameBuffer + ApiSetNameBufferLength);
		do {
			if (ApiSetNameBufferLength <= 1)
			{
				break;
			}
			ApiSetNameBufferLength -= sizeof(WCHAR);
			--pwc;
		} while (*pwc != L'-');

		ApiSetNameNoExtLength = (USHORT)(ApiSetNameBufferLength / sizeof(WCHAR));
		if (!ApiSetNameNoExtLength) 
		{
			break;
		}

		ResolvedNamespaceEntry = (PAPI_SET_NAMESPACE_ENTRY_V6)ApiSetpSearchForApiSetV6(ApiSetMap, ApiSetNameBuffer, ApiSetNameNoExtLength);
		if (!ResolvedNamespaceEntry) 
		{
			break;
		}


		if (ResolvedNamespaceEntry->ValueCount > 1 && wsParentName) {

			HostLibraryEntry = (PAPI_SET_VALUE_ENTRY_V6)ApiSetpSearchForApiSetHostV6(ResolvedNamespaceEntry,
				wsParentName,
				(USHORT)wcslen(wsParentName),
				(PAPI_SET_NAMESPACE_V6)ApiSetMap);
		}
		else if (ResolvedNamespaceEntry->ValueCount > 0) 
		{

			HostLibraryEntry = GET_API_SET_NAMESPACE_VALUE_ENTRY_V6(ApiSetMap, ResolvedNamespaceEntry, ResolvedNamespaceEntry->ValueCount - 1);
		}
		else 
		{
			break;
		}

		memcpy(wsRealDll, GET_API_SET_VALUE_ENTRY_VALUE_V6(ApiSetMap, HostLibraryEntry), min(HostLibraryEntry->ValueLength, dwLen));
		bRet = true;
	} while (false);

	return bRet;
}

bool CPELoader::CheckApiSetMap(const WCHAR * wsMsDll)
{
	ULONGLONG ApiSetNameBufferPrefix = 0;
	ApiSetNameBufferPrefix = *(ULONGLONG*)wsMsDll;
	ApiSetNameBufferPrefix &= ~(ULONGLONG)0x0000002000200020;
	if ((ApiSetNameBufferPrefix != API_SET_PREFIX_API_) &&
		(ApiSetNameBufferPrefix != API_SET_PREFIX_EXT_))
	{
		return false;
	}
	return true;
}


bool CPELoader::ApiSetpResolve(const WCHAR *wsMsDll, const WCHAR *wsParentName, OUT WCHAR *wsRealDll, DWORD dwLen)
{
	PAPI_SET_NAMESPACE ApiSetMap = (PAPI_SET_NAMESPACE)m_ApiSetData;
	bool bRet = false;
	if (ApiSetMap == NULL)
	{
		DWORD dwDataSize = 0;
		ApiSetMap = (PAPI_SET_NAMESPACE)GetApiSetData(&dwDataSize);
		if (ApiSetMap == NULL)
		{
			return false;
		}
		m_ApiSetData = ApiSetMap;
		m_dwApiSetDataSize = dwDataSize;
	}

	switch (ApiSetMap->Version)
	{
		//
		// API set schema version 2
		//
	case API_SET_SCHEMA_VERSION_V2:
		bRet = ApiSetResolveToHostV2(ApiSetMap, wsMsDll, wsParentName, wsRealDll, dwLen);
		break;

		//
		// API set schema version 3
		//
	case API_SET_SCHEMA_VERSION_V3:
		bRet = ApiSetResolveToHostV3(ApiSetMap, wsMsDll, wsParentName, wsRealDll, dwLen);
		break;

		//
		// API set schema version 4
		//
	case API_SET_SCHEMA_VERSION_V4:
		bRet = ApiSetResolveToHostV4(ApiSetMap, wsMsDll, wsParentName, wsRealDll, dwLen);
		break;

		//
		// API set schema version 6
		//
	case API_SET_SCHEMA_VERSION_V6:
		bRet = ApiSetResolveToHostV6(ApiSetMap, wsMsDll, wsParentName, wsRealDll, dwLen);
		break;

	default:
		break;
	}
	return bRet;
}


ULONGLONG CPELoader::GetMoudleExportFunctionAddrEx(std::shared_ptr<sLoadModule> &MainModule, ULONGLONG ulModuleBase, std::wstring &wsFunctionName)
{
	for (std::list<std::shared_ptr<sLoadModule>>::const_iterator iter = MainModule->vDependModules.begin(); iter != MainModule->vDependModules.end(); ++iter)
	{
		if (ulModuleBase == (*iter)->ullLoadbase)
		{
			return GetMoudleExportFunctionAddr(MainModule, (*iter)->name, wsFunctionName);
		}
	}

	return 0;
}

ULONGLONG CPELoader::GetMoudleExportFunctionAddr(std::shared_ptr<sLoadModule> &MainModule, std::wstring &wsModuleName, std::wstring &wsFunctionName)
{
	std::wstring RetMapModule;
	if (_wcsicmp(MainModule->name.c_str(), wsModuleName.c_str()) == 0)
	{
		sExportFunction FunctionInfo;
		bool bRet = GetFunctionInfoByName(MainModule->ExportApis, wsFunctionName, FunctionInfo);
		if (!bRet)
		{
			return 0;
		}
		if (FunctionInfo.IsMap)
		{
			return GetExportFuncAddressNoMap(FunctionInfo.MapToModule, FunctionInfo.MapToFunction, MainModule, RetMapModule);
		}
		else
		{
			return FunctionInfo.ullFunctionAddr;
		}
	}
	else
	{
		return GetExportFuncAddressNoMap(wsModuleName, wsFunctionName, MainModule, RetMapModule);
	}
	return 0;
}