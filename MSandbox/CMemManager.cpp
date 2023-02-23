#include "CMemManager.h"
#include "WinComm.h"
#include <assert.h>
#include <stdlib.h>

static const ULONG BlockSizes[POOL_COUNT] =
{
	1,      2,      4,      8,		16,		32,		48,		64,
	80,		96,		112,    128,	160,	192,	224,	256,
	288,	320,	384,    448,	512,	576,	640,	704,
	768,	896,	1024,   1168,	1360,	1632,	2048,	2336,
	2720,	3264,	4096,   4672,	5456,	6544,	8192,	9360,
	10912,	13104,	16384,  21840,	32768,  65536,  131072, 0
};

CWinMemManager::CWinMemManager()
{
	InitilizeMemManager(&m_ullProcessInfoAddrSpaceMgr, WIN_USERMODE_PROCESS_THREAD_INFO_BEGIN, WIN_USERMODE_PROCESS_THREAD_INFO_LIMIT, em_MTProcessInfoType);
	InitilizeMemManager(&m_ullStackAddrSpaceMgr, WIN_USERMODE_STACK_ADDRESS_BEGIN, WIN_USERMODE_STACK_ADDRESS_LIMIT, em_StackType);
	InitilizeMemManager(&m_ull32BitHeapsAddrSpaceMgr, WIN_USERMODE_HEAPS_ADDRESS_BEGIN, WIN_USERMODE_HEAPS_ADDRESS_32BIT_LIMIT, em_HeapsType32Bit);
	InitilizeMemManager(&m_ull64BitHeapsAddrSpaceMgr, WIN_USERMODE_HEAPS_ADDRESS_BEGIN, WIN_USERMODE_HEAPS_ADDRESS_64BIT_LIMIT, em_HeapsType64Bit);
}

CWinMemManager::~CWinMemManager()
{
}

ULONGLONG CWinMemManager::WinMemSpaceAlloc(MemType emType, DWORD dwSize)
{
	MemManager *pMgr = NULL;
	switch (emType)
	{
	case em_MTProcessInfoType:
		pMgr = &m_ullProcessInfoAddrSpaceMgr;
		break;
	case em_StackType:
		pMgr = &m_ullStackAddrSpaceMgr;
		break;
	case em_HeapsType32Bit:
		pMgr = &m_ull32BitHeapsAddrSpaceMgr;
		break;
	case em_HeapsType64Bit:
		pMgr = &m_ull64BitHeapsAddrSpaceMgr;
		break;
	default:
		break;
	}

	if (pMgr == NULL)
	{
		return 0;
	}

	return MemAlloc(pMgr, dwSize);
}

bool CWinMemManager::WinMemSpaceFree(MemType emType, ULONGLONG pMemAddress)
{
	MemManager *pMgr = NULL;
	switch (emType)
	{
	case em_MTProcessInfoType:
		pMgr = &m_ullProcessInfoAddrSpaceMgr;
		break;
	case em_StackType:
		pMgr = &m_ullStackAddrSpaceMgr;
		break;
	case em_HeapsType32Bit:
		pMgr = &m_ull32BitHeapsAddrSpaceMgr;
		break;
	case em_HeapsType64Bit:
		pMgr = &m_ull64BitHeapsAddrSpaceMgr;
		break;
	default:
		break;
	}

	if (pMgr == NULL)
	{
		return false;
	}

	return MemSpaceFree(pMgr, pMemAddress);
}

bool CWinMemManager::WinAddReserveBlockSpace(MemType emType, ULONGLONG pMemAddress, DWORD dwSize)
{
	MemManager *pMgr = NULL;
	switch (emType)
	{
	case em_MTProcessInfoType:
		pMgr = &m_ullProcessInfoAddrSpaceMgr;
		break;
	case em_StackType:
		pMgr = &m_ullStackAddrSpaceMgr;
		break;
	case em_HeapsType32Bit:
		pMgr = &m_ull32BitHeapsAddrSpaceMgr;
		break;
	case em_HeapsType64Bit:
		pMgr = &m_ull64BitHeapsAddrSpaceMgr;
		break;
	default:
		break;
	}

	if (pMgr == NULL)
	{
		return false;
	}

	return MemAddReserveBlockSpace(pMgr, pMemAddress, dwSize);
}

bool CWinMemManager::InitilizeMemManager(MemManager *pMgr, ULONGLONG ullAddressBase, ULONGLONG ullAddressLimit, MemType mType)
{
	memset(pMgr, 0, sizeof(MemManager));

	pMgr->mType = mType;
	pMgr->ullAddressBase = ullAddressBase;
	pMgr->ullAddressLimit = ullAddressLimit;

	pMgr->SpaceInfo = new std::vector<SpaceRange>;
	assert(pMgr->SpaceInfo);
	pMgr->SpaceInfo->clear();
	SpaceRange UseRange;
	UseRange.begin = ullAddressBase;
	UseRange.end = ullAddressLimit;
	pMgr->SpaceInfo->push_back(UseRange);

	InitializeCriticalSection(&pMgr->csUseLock);
	InitializeCriticalSection(&pMgr->csFreeLock);
	InitializeListHead(&pMgr->Reservelist);

	pMgr->allocMap = new std::map<ULONGLONG, ULONGLONG>;
	assert(pMgr->allocMap);

	for (int i = 0; i < POOL_COUNT; i++)
	{
		pMgr->ProcessInfoAddrSpaceUse[i].index = i;
		InitializeListHead(&pMgr->ProcessInfoAddrSpaceUse[i].list);

		pMgr->ProcessInfoAddrSpaceFree[i].index = i;
		InitializeListHead(&pMgr->ProcessInfoAddrSpaceFree[i].list);
	}
	
	return true;
}



MemBlockInfo *CWinMemManager::GetMemBlockInfoFromFreeList(MemManager *pMgr, DWORD dwSize)
{
	MemBlockInfo *pBlockInfo = NULL;
	DWORD dwAlignSize = ALIGN_SIZE_UP(dwSize, PAGE_SIZE);
	DWORD dwPoolIndex = dwAlignSize / PAGE_SIZE;

	//找出对应的块索引
	if (dwPoolIndex == 0)
	{
		dwPoolIndex = 0;
	}
	else if (dwPoolIndex > BlockSizes[POOL_COUNT - 2])
	{
		dwPoolIndex = POOL_COUNT - 1;
	}
	else
	{
		dwPoolIndex = BinarySearch(BlockSizes, dwPoolIndex);
	}


	if (pMgr->ProcessInfoAddrSpaceFree[dwPoolIndex].dwCount > 0)
	{
		pBlockInfo = (MemBlockInfo*)RemoveHeadList(&pMgr->ProcessInfoAddrSpaceFree[dwPoolIndex].list);
		assert(pBlockInfo);
		pMgr->ProcessInfoAddrSpaceFree[dwPoolIndex].dwCount--;
		pMgr->ProcessInfoAddrSpaceFree[dwPoolIndex].ullAllocSize -= pBlockInfo->ulAllocSize;
		pMgr->ProcessInfoAddrSpaceFree[dwPoolIndex].ullTotleSize -= pBlockInfo->ulBlockSize;
		//pBlockInfo->bBlockSizeIndex  索引好块大小在初始申请的时候就确定 
		//pBlockInfo->ulBlockSize      不用再修改
		pBlockInfo->ulAllocSize = dwSize;

		bool bRet = AddMemBlockInfoToUseList(pMgr, pBlockInfo);
		assert(bRet);
		if (bRet)
		{
			pBlockInfo->bBlockStatus = 1;
			pMgr->allocMap->insert(std::pair<ULONGLONG, ULONGLONG>(pBlockInfo->ullAddressBase, (ULONGLONG)pBlockInfo));
		}

	}
	else
	{
		DWORD dwNeedSize = 0;
		ULONGLONG ulAllocBase = 0;
		if (dwPoolIndex == POOL_COUNT - 1)
		{
			//超大块
			dwNeedSize = dwAlignSize;
		}
		else
		{
			dwNeedSize = BlockSizes[dwPoolIndex] * PAGE_SIZE;
		}

		ulAllocBase = GetSpaceRangeAddr(pMgr, dwNeedSize);
		if (ulAllocBase == NULL)
		{
			//无可用地址空间了
			assert(false);
			return NULL;
		}

		//新申请
		MemBlockInfo *pTmp = (MemBlockInfo*)malloc(sizeof(MemBlockInfo));
		assert(pTmp);
		if (pTmp == NULL)
		{
			AddSpaceRangeAddr(pMgr, ulAllocBase, dwNeedSize);
			return NULL;
		}
		memset(pTmp, 0, sizeof(MemBlockInfo));

		pTmp->mType = pMgr->mType;
		pTmp->ulAllocSize = dwSize;
		pTmp->ulBlockSize = dwNeedSize;
		pTmp->bBlockSizeIndex = (BYTE)dwPoolIndex;
		pTmp->bBlockStatus = (BYTE)1;
		pTmp->ullAddressBase = ulAllocBase;

		bool bRet = AddMemBlockInfoToUseList(pMgr, pTmp);
		assert(bRet);
		if (bRet)
		{
			pBlockInfo = pTmp;

			//加入映射
			pMgr->allocMap->insert(std::pair<ULONGLONG, ULONGLONG>(ulAllocBase, (ULONGLONG)pTmp));
		}
	}

	return pBlockInfo;
}


bool CWinMemManager::AddMemBlockInfoToList(PLIST_ENTRY pHead, MemBlockInfo *pBlockInfo)
{

	if (IsListEmpty(pHead))
	{
		InsertTailList(pHead, &pBlockInfo->list);
		return true;
	}
	else
	{
		//如果最后一个比当前的都大，就直接插到尾巴
		MemBlockInfo *pTmp = (MemBlockInfo*)pHead->Blink;
		if (pBlockInfo->ullAddressBase <= pTmp->ullAddressBase)
		{
			InsertTailList(pHead, &pBlockInfo->list);
			return true;
		}
	}

	PLIST_ENTRY pos = NULL;
	bool bInsert = false;
	LIST_FOR_EACH(pos, pHead)
	{
		MemBlockInfo *pTmp = (MemBlockInfo *)pos;
		if (pBlockInfo->ullAddressBase <= pTmp->ullAddressBase)
		{
			continue;
		}

		//插在这个节点之前
		InsertListEntry(&pBlockInfo->list, pTmp->list.Blink, &pTmp->list);
		bInsert = true;
		break;
	}

	if (!bInsert)
	{
		InsertTailList(pHead, &pBlockInfo->list);
		bInsert = true;
	}

	return bInsert;
}


bool CWinMemManager::AddMemBlockInfoToUseList(MemManager *pMgr, MemBlockInfo *pBlockInfo)
{
	if (pMgr == NULL || pBlockInfo == NULL)
	{
		return false;
	}

	bool bRet = AddMemBlockInfoToList(&pMgr->ProcessInfoAddrSpaceUse[pBlockInfo->bBlockSizeIndex].list, pBlockInfo);
	assert(bRet);
	if (bRet)
	{
		pMgr->ProcessInfoAddrSpaceUse[pBlockInfo->bBlockSizeIndex].dwCount++;
		pMgr->ProcessInfoAddrSpaceUse[pBlockInfo->bBlockSizeIndex].ullAllocSize += pBlockInfo->ulAllocSize;
		pMgr->ProcessInfoAddrSpaceUse[pBlockInfo->bBlockSizeIndex].ullTotleSize += pBlockInfo->ulBlockSize;
	}
	return bRet;
}

ULONGLONG CWinMemManager::GetSpaceRangeAddr(MemManager *pMgr, DWORD dwAlignSize)
{
	if (pMgr->SpaceInfo->size() == 0)
	{
		return 0;
	}

	DWORD dwMustAlignSize = ALIGN_SIZE_UP(dwAlignSize, PAGE_SIZE);
	ULONGLONG ullRet = 0;
	std::vector<SpaceRange>::iterator iter;
	for (iter = pMgr->SpaceInfo->begin(); iter != pMgr->SpaceInfo->end(); ++iter)
	{
		if (iter->end - iter->begin >= dwMustAlignSize)
		{
			ullRet = iter->begin;
			iter->begin += dwMustAlignSize;
			assert(iter->begin <= iter->end);

			if (iter->end - iter->begin <= PAGE_SIZE)
			{
				//这个区间已经用完
				pMgr->SpaceInfo->erase(iter);
			}
			return ullRet;
		}
	}
	return ullRet;
}

bool CWinMemManager::AddSpaceRangeAddr(MemManager * pMgr, ULONGLONG ullSpecialAddr, DWORD dwAlignSize)
{
	if ((ullSpecialAddr & ~PAGE_SIZE) != ullSpecialAddr ||
		(ALIGN_SIZE_UP(dwAlignSize, PAGE_SIZE)) != dwAlignSize)
	{
		//只能页对齐
		return false;
	}

	std::vector<SpaceRange>::iterator iter;
	for (iter = pMgr->SpaceInfo->begin(); iter != pMgr->SpaceInfo->end(); ++iter)
	{
		if ((ullSpecialAddr >= iter->begin && ullSpecialAddr <= iter->end) ||
			((ullSpecialAddr + dwAlignSize) >= iter->begin && (ullSpecialAddr + dwAlignSize) <= iter->end))
		{
			return false;
		}

		if ((iter->begin >= ullSpecialAddr && iter->begin <= (ullSpecialAddr + dwAlignSize)) ||
			(iter->end >= ullSpecialAddr && iter->end <= (ullSpecialAddr + dwAlignSize)))
		{
			return false;
		}
	}

	for (iter = pMgr->SpaceInfo->begin(); iter != pMgr->SpaceInfo->end(); ++iter)
	{
		std::vector<SpaceRange>::iterator iterTmp = iter++;
		if (ullSpecialAddr >= iter->end)
		{
			if (iterTmp == pMgr->SpaceInfo->end())
			{
				SpaceRange newtmp;
				newtmp.begin = ullSpecialAddr;
				newtmp.end = ullSpecialAddr + dwAlignSize;
				pMgr->SpaceInfo->insert(iter, newtmp);
				return true;
			}
			else if (ullSpecialAddr <= iterTmp->begin)
			{
				SpaceRange newtmp;
				newtmp.begin = ullSpecialAddr;
				newtmp.end = ullSpecialAddr + dwAlignSize;
				pMgr->SpaceInfo->insert(iter, newtmp);
				return true;
			}

			continue;
		}
	}

	return false;
}

ULONGLONG CWinMemManager::GetSpaceRangeAddrBySpecial(MemManager * pMgr, ULONGLONG ullSpecialAddr, DWORD dwAlignSize)
{
	if (pMgr->SpaceInfo->size() == 0)
	{
		return 0;
	}

	DWORD dwMustAlignSize = ALIGN_SIZE_UP(dwAlignSize, PAGE_SIZE);
	ULONGLONG ullAlignAddress = ullSpecialAddr & ~PAGE_SIZE;
	std::vector<SpaceRange>::iterator iter;
	for (iter = pMgr->SpaceInfo->begin(); iter != pMgr->SpaceInfo->end(); ++iter)
	{
		if (ullAlignAddress >= iter->begin  && (ullAlignAddress + dwMustAlignSize) <= iter->end)
		{
			SpaceRange sr = *iter;

			//再添加头部
			if (ullAlignAddress - sr.begin > PAGE_SIZE)
			{
				SpaceRange newtmp;
				newtmp.begin = sr.begin;
				newtmp.end = ullAlignAddress;
				iter = pMgr->SpaceInfo->insert(iter, newtmp);
				++iter;
			}

			//先添加尾部
			if (sr.end - (ullAlignAddress + dwMustAlignSize) > PAGE_SIZE)
			{
				SpaceRange newtmp;
				newtmp.begin = ullAlignAddress + dwMustAlignSize;
				newtmp.end = sr.end;
				iter = pMgr->SpaceInfo->insert(iter, newtmp);
				++iter;
			}

			//删除原来的
			pMgr->SpaceInfo->erase(iter);
			return ullAlignAddress;
		}
	}
	return 0;
}


DWORD CWinMemManager::BinarySearch(const ULONG* nums, DWORD dwPoolIndex) {
	int left = 0;
	int right = POOL_COUNT - 2;
	int mid = 0;

	while (left <= right) 
	{
		mid = (right + left) / 2;
		if (nums[mid] == dwPoolIndex)
		{
			return mid;
		}
		else if (nums[mid] < dwPoolIndex)
		{
			left = mid + 1;
		}
		else if (nums[mid] > dwPoolIndex)
		{
			right = mid - 1;
		}	
	}

	if (nums[mid] < dwPoolIndex)
	{
		assert(nums[mid + 1] >= dwPoolIndex);
		return mid + 1;
	}
	else
	{
		return mid;
	}
	return 0xFFFFFFFF;
}


ULONGLONG CWinMemManager::MemAlloc(MemManager *pMgr, DWORD dwSize)
{
	if (MAX_ALLOC_SIZE <= dwSize || dwSize == 0)
	{
		return 0;
	}

	MemBlockInfo *pInfo = GetMemBlockInfoFromFreeList(pMgr, dwSize);
	if (pInfo == NULL)
	{
		return 0;
	}
	return pInfo->ullAddressBase;
}

bool CWinMemManager::MemSpaceFree(MemManager *pMgr, ULONGLONG pMemAddress)
{
	std::map<ULONGLONG, ULONGLONG>::iterator iter;
	iter = pMgr->allocMap->find(pMemAddress);
	if (iter != pMgr->allocMap->end())
	{
		MemBlockInfo *pTmp = (MemBlockInfo *)iter->second;
		assert(pTmp->bBlockStatus == 1);

		pMgr->allocMap->erase(iter);

		RemoveEntryList(&pTmp->list);

		pMgr->ProcessInfoAddrSpaceUse[pTmp->bBlockSizeIndex].dwCount--;
		pMgr->ProcessInfoAddrSpaceUse[pTmp->bBlockSizeIndex].ullAllocSize -= pTmp->ulAllocSize;
		pMgr->ProcessInfoAddrSpaceUse[pTmp->bBlockSizeIndex].ullTotleSize -= pTmp->ulBlockSize;

		pTmp->bBlockStatus = 0;
		pTmp->ulAllocSize  = 0;
		
		InsertTailList(&pMgr->ProcessInfoAddrSpaceFree[pTmp->bBlockSizeIndex].list, &pTmp->list);
		pMgr->ProcessInfoAddrSpaceFree[pTmp->bBlockSizeIndex].dwCount++;
		pMgr->ProcessInfoAddrSpaceFree[pTmp->bBlockSizeIndex].ullTotleSize += pTmp->ulBlockSize;

		return true;
	}

	return false;
}

bool CWinMemManager::MemAddReserveBlockSpace(MemManager * pMgr, ULONGLONG pMemAddress, DWORD dwSize)
{
	if (dwSize == 0)
	{
		return false;
	}
	if (!(pMemAddress >= pMgr->ullAddressBase && pMemAddress + dwSize < pMgr->ullAddressLimit))
	{
		return false;
	}

	ULONGLONG ulAlignBase = pMemAddress & ~PAGE_SIZE;
	DWORD dwAlignSize = ALIGN_SIZE_UP(dwSize, PAGE_SIZE) + PAGE_SIZE;

	PLIST_ENTRY pos = NULL;
	LIST_FOR_EACH(pos, &pMgr->Reservelist)
	{
		MemBlockInfo *pTmp = (MemBlockInfo *)pos;
		if (ulAlignBase >= pTmp->ullAddressBase && ulAlignBase <= (pTmp->ullAddressBase + pTmp->ulBlockSize))
		{
			//地址空间冲突
			return false;
		}

		if ((ulAlignBase + dwAlignSize) >= pTmp->ullAddressBase && (ulAlignBase + dwAlignSize) <= (pTmp->ullAddressBase + pTmp->ulBlockSize))
		{
			//地址空间冲突
			return false;
		}

		if (pTmp->ullAddressBase >= ulAlignBase && pTmp->ullAddressBase <= (ulAlignBase + dwAlignSize))
		{
			//地址空间冲突
			return false;
		}

		if ((pTmp->ullAddressBase + pTmp->ulBlockSize) >= ulAlignBase && (pTmp->ullAddressBase + pTmp->ulBlockSize) <= (ulAlignBase + dwAlignSize))
		{
			//地址空间冲突
			return false;
		}
	}

	ULONGLONG ulRetAddr = GetSpaceRangeAddrBySpecial(pMgr, ulAlignBase, dwAlignSize);
	if (ulRetAddr == 0)
	{
		return false;
	}
	assert(ulRetAddr == ulAlignBase);


	MemBlockInfo *pNew = (MemBlockInfo *)malloc(sizeof(MemBlockInfo));
	assert(pNew);
	if (pNew == NULL)
	{
		AddSpaceRangeAddr(pMgr, ulAlignBase, dwAlignSize);
		return false;
	}
	memset(pNew, 0, sizeof(MemBlockInfo));

	pNew->mType = em_ReserveType;
	pNew->ulAllocSize = dwSize;
	pNew->ulBlockSize = dwAlignSize;
	pNew->bBlockSizeIndex = (BYTE)0;
	pNew->bBlockStatus = (BYTE)1;
	pNew->ullAddressBase = ulAlignBase;
	bool bret = AddMemBlockInfoToList(&pMgr->Reservelist, pNew);
	if (!bret)
	{
		AddSpaceRangeAddr(pMgr, ulAlignBase, dwAlignSize);
		assert(0);
		return false;
	}
	return bret;
}

