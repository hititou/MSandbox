#pragma once
#include <windows.h>
#include <wtypes.h>
#include <errno.h>
#include "WinComm.h"
#include <map>
#include <vector>

/*
x64内存地址分布
teb/peb/tls/环境变量/参数/thread info
0x10000 - 0x1410000(20M)
Stack:
0x2000000 - 0x3000000 (main thread 16M)
0x3001000 - 0x3E8FA000(其他thread)   1M * 1000  最大支持1000条线程
...
...

heaps: (包括模块也从heaps中申请地址空间)
0x40000000
x86 end   0x7ffd0000
x64 end   0x000007FF`FFFFFFF


#define MM_SHARED_USER_DATA_VA 0x7ffe0000  sizeof(KUSER_SHARED_DATA)
*/

enum MemType
{
	em_MTProcessInfoType = 1,
	em_StackType,
	em_HeapsType32Bit,
	em_HeapsType64Bit,
	em_ReserveType,  //保留地址空间
	em_max,
};


/// See: MODEL-SPECIFIC REGISTERS (MSRS)
enum class MSRS : unsigned int {
	kIa32ApicBase = 0x01B,

	kIa32FeatureControl = 0x03A,

	kIa32SysenterCs = 0x174,
	kIa32SysenterEsp = 0x175,
	kIa32SysenterEip = 0x176,

	kIa32Debugctl = 0x1D9,

	kIa32MtrrCap = 0xFE,
	kIa32MtrrDefType = 0x2FF,
	kIa32MtrrPhysBaseN = 0x200,
	kIa32MtrrPhysMaskN = 0x201,
	kIa32MtrrFix64k00000 = 0x250,
	kIa32MtrrFix16k80000 = 0x258,
	kIa32MtrrFix16kA0000 = 0x259,
	kIa32MtrrFix4kC0000 = 0x268,
	kIa32MtrrFix4kC8000 = 0x269,
	kIa32MtrrFix4kD0000 = 0x26A,
	kIa32MtrrFix4kD8000 = 0x26B,
	kIa32MtrrFix4kE0000 = 0x26C,
	kIa32MtrrFix4kE8000 = 0x26D,
	kIa32MtrrFix4kF0000 = 0x26E,
	kIa32MtrrFix4kF8000 = 0x26F,

	kIa32VmxBasic = 0x480,
	kIa32VmxPinbasedCtls = 0x481,
	kIa32VmxProcBasedCtls = 0x482,
	kIa32VmxExitCtls = 0x483,
	kIa32VmxEntryCtls = 0x484,
	kIa32VmxMisc = 0x485,
	kIa32VmxCr0Fixed0 = 0x486,
	kIa32VmxCr0Fixed1 = 0x487,
	kIa32VmxCr4Fixed0 = 0x488,
	kIa32VmxCr4Fixed1 = 0x489,
	kIa32VmxVmcsEnum = 0x48A,
	kIa32VmxProcBasedCtls2 = 0x48B,
	kIa32VmxEptVpidCap = 0x48C,
	kIa32VmxTruePinbasedCtls = 0x48D,
	kIa32VmxTrueProcBasedCtls = 0x48E,
	kIa32VmxTrueExitCtls = 0x48F,
	kIa32VmxTrueEntryCtls = 0x490,
	kIa32VmxVmfunc = 0x491,
	kIa32Efer = 0xC0000080,
	kIa32Star = 0xC0000081,
	kIa32Lstar = 0xC0000082,
	kIa32Fmask = 0xC0000084,
	kIa32FsBase = 0xC0000100,
	kIa32GsBase = 0xC0000101,
	kIa32KernelGsBase = 0xC0000102,
	kIa32TscAux = 0xC0000103,
};

#define MAX_ALLOC_SIZE 0x40000000

#define WIN_USERMODE_PROCESS_THREAD_INFO_BEGIN 0x10000ull
#define WIN_USERMODE_STACK_ADDRESS_BEGIN       0x2000000ull
#define WIN_USERMODE_HEAPS_ADDRESS_BEGIN       0x40000000ull

#define WIN_USERMODE_PROCESS_THREAD_INFO_LIMIT (WIN_USERMODE_STACK_ADDRESS_BEGIN - PAGE_SIZE)
#define WIN_USERMODE_STACK_ADDRESS_LIMIT       (WIN_USERMODE_HEAPS_ADDRESS_BEGIN - PAGE_SIZE)

#define WIN_USERMODE_HEAPS_ADDRESS_32BIT_LIMIT 0x7FFFFFFFull
#define WIN_USERMODE_HEAPS_ADDRESS_64BIT_LIMIT 0x000007FFFFFFFFFFull

#define KERNEL_SHARE_DATA_USER_BASE_X86 0x7FFE0000ull
#define KERNEL_SHARE_DATA_USER_BASE_X64 0x0000078000000000ull
#define KERNEL_SHARE_DATA_USER_SIZE     0x10000

#define USERMODE_THREAD_STACK_SIZE       0x100000ull  //1M
#define USERMODE_MAIN_THREAD_STACK_SIZE  0x200000ull  //2M
#define USERMODE_HEAPS_SIZE              0x1000000ull  //保留

//GDT地址
#define GDT_ADDRESS_X64 0xfffff00000000000ull
#define GDT_ADDRESS_X86 0xFFFF0000ul
#define GDT_SEGMENTSELECTOR_INDEX_CS 1
#define GDT_SEGMENTSELECTOR_INDEX_DS 2
#define GDT_SEGMENTSELECTOR_INDEX_FS 3
#define GDT_SEGMENTSELECTOR_INDEX_GS 4


enum { POOL_COUNT = 48 };


struct MemAddrPoolInfo
{
	MemAddrPoolInfo()
	{
		list.Flink = 0;
		list.Blink = 0;
		index = 0;
		dwCount = 0;
		ullTotleSize = 0;
		ullAllocSize = 0;
	}
	LIST_ENTRY list;
	BYTE index;
	DWORD dwCount;
	ULONGLONG ullTotleSize; //总大小
	ULONGLONG ullAllocSize; //总申请大小

};

struct MemBlockInfo
{
	MemBlockInfo()
	{
		list.Flink = 0;
		list.Blink = 0;
		mType = em_max;
		ullAddressBase = 0;
		bBlockSizeIndex = 0;
		bBlockStatus = 0;
		ulBlockSize = 0;
		ulAllocSize = 0;
	}
	LIST_ENTRY list;
	MemType mType;
	ULONGLONG ullAddressBase;  //块基地址
	BYTE bBlockSizeIndex;      //块大小索引
	BYTE bBlockStatus;         //块状态      1:use, 0:free
	ULONG ulBlockSize;         //块大小
	ULONG ulAllocSize;         //申请大小

};


struct SpaceRange
{
	SpaceRange()
	{
		begin = 0;
		end = 0;
	}
	ULONGLONG begin;
	ULONGLONG end;
};
struct MemManager
{  
	MemManager()
	{
		mType = em_max;
		ullAddressBase = 0;
		ullAddressLimit = 0;
		SpaceInfo = NULL;
		allocMap = NULL;
		Reservelist.Flink = 0;
		Reservelist.Blink = 0;
	}
	MemType mType;
	ULONGLONG ullAddressBase;            //空间基地址
	ULONGLONG ullAddressLimit;           //限制长度
	std::vector<SpaceRange> *SpaceInfo;  //可用范围
	CRITICAL_SECTION csUseLock;          //使用块锁
	MemAddrPoolInfo ProcessInfoAddrSpaceUse[POOL_COUNT];  //使用块池子
	CRITICAL_SECTION csFreeLock;         //空闲块锁
	MemAddrPoolInfo ProcessInfoAddrSpaceFree[POOL_COUNT]; //空闲块池子
	std::map<ULONGLONG, ULONGLONG> *allocMap; //map to use block
	LIST_ENTRY Reservelist;		         //保留的地址空间

	const WCHAR *GetMemTypeString(MemType mType)
	{
		switch (mType)
		{
		case em_MTProcessInfoType:
			return L"ProcessInfoType";
			break;
		case em_StackType:
			return L"StackType";
			break;
		case em_HeapsType32Bit:
			return L"HeapsType32Bit";
			break;
		case em_HeapsType64Bit:
			return L"HeapsType64Bit";
			break;
		case em_ReserveType:
			return L"ReserveType";
			break;
		case em_max:
			return L"NoSportType";
			break;
		default:
			return L"UnKnowType";
			break;
		}
		return NULL;
	}

	void MemManagerLog()
	{
		ULONGLONG ulTotleUse = 0;
		ULONGLONG ulTotleFree = 0;
		ULONGLONG ulTotleReserve = 0;
		wprintf(L"\n=======================%s Log Start==========================\n", GetMemTypeString(mType));
		wprintf(L"MemType: %s, \tAddressBase: 0x%016I64x, \tullAddressLimit: 0x%016I64x\n", GetMemTypeString(mType), ullAddressBase, ullAddressLimit);
		if (SpaceInfo)
		{
			for (std::vector<SpaceRange>::const_iterator iter = SpaceInfo->begin(); iter != SpaceInfo->end(); ++iter)
			{
				wprintf(L"SpaceInfo->Base: 0x%016I64x, \tEnd: 0x%016I64x\n", iter->begin, iter->end);
			}
		}
		
		for (int i = 0; i < POOL_COUNT; i++)
		{
			if (ProcessInfoAddrSpaceUse[i].dwCount == 0)
			{
				continue;
			}
			ulTotleUse += ProcessInfoAddrSpaceUse[i].ullTotleSize;
			wprintf(L"UseSpace[%d]->Index: %d, \tCount: %d, \tAllocSize: 0x%016I64x, \tTotleSize: 0x%016I64x\n",i, ProcessInfoAddrSpaceUse[i].index, 
				ProcessInfoAddrSpaceUse[i].dwCount, ProcessInfoAddrSpaceUse[i].ullAllocSize, ProcessInfoAddrSpaceUse[i].ullTotleSize);
		}
		
		for (int i = 0; i < POOL_COUNT; i++)
		{
			if (ProcessInfoAddrSpaceFree[i].dwCount == 0)
			{
				continue;
			}
			ulTotleFree += ProcessInfoAddrSpaceFree[i].ullTotleSize;
			wprintf(L"FreeSpace[%d]->Index: %d, \tCount: %d, \tAllocSize: 0x%016I64x, \tTotleSize: 0x%016I64x\n", i, ProcessInfoAddrSpaceFree[i].index,
				ProcessInfoAddrSpaceFree[i].dwCount, ProcessInfoAddrSpaceFree[i].ullAllocSize, ProcessInfoAddrSpaceFree[i].ullTotleSize);
		}
	
		PLIST_ENTRY pos = NULL;
		LIST_FOR_EACH(pos, &Reservelist)
		{
			MemBlockInfo *pTmp = (MemBlockInfo *)pos;
			wprintf(L"ReserveSpace->Index: %d, \tBase: 0x%016I64x, \tBlockSize: 0x%08x, \tAllocSize: 0x%08x\n", pTmp->bBlockSizeIndex, pTmp->ullAddressBase,
				pTmp->ulBlockSize, pTmp->ulAllocSize);

			ulTotleReserve += pTmp->ulAllocSize;
		}

		wprintf(L"UseSpace     Totle Use:%dKB\n", (ULONG)ulTotleUse / 1024);
		wprintf(L"FreeSpace    Totle Use:%dKB\n", (ULONG)ulTotleFree / 1024);
		wprintf(L"ReserveSpace Totle Use:%dKB\n", (ULONG)ulTotleReserve / 1024);
		wprintf(L"=======================%s Log End==========================\n", GetMemTypeString(mType));
	}
};




class CWinMemManager
{
public:
	CWinMemManager();
	~CWinMemManager();

	ULONGLONG WinMemSpaceAlloc(MemType emType, DWORD dwSize);

	bool WinMemSpaceFree(MemType emType, ULONGLONG pMemAddress);


	//申请保留地址，不释放 比如申请 SHARED_USER_DATA_VA 0x7ffe0000
	bool WinAddReserveBlockSpace(MemType emType, ULONGLONG pMemAddress, DWORD dwSize);



	void LOG(bool Is32Bit)
	{
		m_ullProcessInfoAddrSpaceMgr.MemManagerLog();
		m_ullStackAddrSpaceMgr.MemManagerLog();
		if (Is32Bit)
		{
			m_ull32BitHeapsAddrSpaceMgr.MemManagerLog();
		}
		else
		{
			m_ull64BitHeapsAddrSpaceMgr.MemManagerLog();
		}
	};
private:

	//进程线程信息地址空间管理
	MemManager m_ullProcessInfoAddrSpaceMgr;
	//栈地址空间管理
	MemManager m_ullStackAddrSpaceMgr;
	//32bit堆地址空间管理
	MemManager m_ull32BitHeapsAddrSpaceMgr;
	//64bit堆地址空间管理
	MemManager m_ull64BitHeapsAddrSpaceMgr;

private:
	bool InitilizeMemManager(MemManager *pMgr, ULONGLONG ullAddressBase, ULONGLONG ullAddressLimit, MemType mType);

	//地址空间申请
	ULONGLONG MemAlloc(MemManager *pMgr, DWORD dwSize);
	bool MemSpaceFree(MemManager *pMgr, ULONGLONG pMemAddress);

	bool MemAddReserveBlockSpace(MemManager *pMgr, ULONGLONG pMemAddress, DWORD dwSize);

	DWORD BinarySearch(const ULONG* nums, DWORD dwPoolIndex);
	MemBlockInfo *GetMemBlockInfoFromFreeList(MemManager *pMgr, DWORD dwSize);
	bool AddMemBlockInfoToUseList(MemManager *pMgr, MemBlockInfo *pBlockInfo);
	bool AddMemBlockInfoToList(PLIST_ENTRY pHead, MemBlockInfo *pBlockInfo);


	ULONGLONG GetSpaceRangeAddr(MemManager *pMgr, DWORD dwAlignSize);
	bool AddSpaceRangeAddr(MemManager *pMgr, ULONGLONG ullSpecialAddr, DWORD dwAlignSize);
	ULONGLONG GetSpaceRangeAddrBySpecial(MemManager *pMgr, ULONGLONG ullSpecialAddr, DWORD dwAlignSize);
};