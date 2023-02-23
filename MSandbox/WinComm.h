#pragma once
#include <windows.h>
#include <wtypes.h>
#include <errno.h>
#include <map>
#include <vector>
#include <string.h>
#include <memory>
#include <list>
#include <assert.h>
#include <iostream>
#include <ctime>
#include <atlstr.h>

#define STRUCT_OFFECT(struct_name, struct_member) (DWORD)(ULONG_PTR)(&(((struct_name *)0)->struct_member))

#define PAGE_SIZE 0x1000ull
#define ALIGN_SIZE_UP(size, align) ((size + align - 1) & (~(align - 1)))
#define RVA2VA(image, rva, type) (type)(ULONG_PTR)((ULONGLONG)image + rva)

static inline void InitializeListHead(struct _LIST_ENTRY *head) 
{
	head->Flink = head->Blink = head;
}

static inline bool IsListEmpty(struct _LIST_ENTRY *head)
{
	if (head == head->Flink)
		return true;
	else
		return false;
}

static inline void RemoveEntryList(struct _LIST_ENTRY *entry) 
{
	entry->Blink->Flink = entry->Flink;
	entry->Flink->Blink = entry->Blink;
}

static inline struct _LIST_ENTRY *RemoveHeadList(struct _LIST_ENTRY *head)
{
	struct _LIST_ENTRY *entry = NULL;

	entry = head->Flink;
	if (entry == head)
		return NULL;
	else {
		RemoveEntryList(entry);
		return entry;
	}
}

static inline struct _LIST_ENTRY *RemoveTailList(struct _LIST_ENTRY *head) {
	struct _LIST_ENTRY *entry = NULL;

	entry = head->Blink;
	if (entry == head)
		return NULL;
	else {
		RemoveEntryList(entry);
		return entry;
	}
}

static inline void InsertListEntryEx(struct _LIST_ENTRY *entry, struct _LIST_ENTRY *New)
{
	struct _LIST_ENTRY *Tmp = entry->Flink;
	entry->Flink = New;
	Tmp->Blink = New;
	New->Flink = Tmp;
	New->Blink = entry;
}

static inline void InsertListEntry(struct _LIST_ENTRY *entry, struct _LIST_ENTRY *prev, struct _LIST_ENTRY *next)
{
	next->Blink = entry;
	entry->Flink = next;
	entry->Blink = prev;
	prev->Flink = entry;
}

static inline struct _LIST_ENTRY *InsertHeadList(struct _LIST_ENTRY *head, struct _LIST_ENTRY *entry) 
{
	struct _LIST_ENTRY *ret = NULL;

	if (IsListEmpty(head))
		ret = NULL;
	else
		ret = head->Flink;

	InsertListEntry(entry, head, head->Flink);
	return ret;
}

static inline struct _LIST_ENTRY *InsertTailList(struct _LIST_ENTRY *head, struct _LIST_ENTRY *entry)
{
	struct _LIST_ENTRY *ret = NULL;

	if (IsListEmpty(head))
		ret = NULL;
	else
		ret = head->Blink;

	InsertListEntry(entry, head->Blink, head);
	return ret;
}

#define LIST_FOR_EACH(pos, head)                                     \
        for (pos = (head)->Flink; pos != (head); pos = pos->Flink)



static inline ULONGLONG GetRandomUlonglong()
{
	srand((unsigned int)time(0));
	ULONGLONG ultmp = ((ULONG)rand() << 16) + (ULONG)rand();
	ultmp <<= 32;
	ultmp += ((ULONG)rand() << 16) + (ULONG)rand();
	return ultmp;
}




/*


typedef struct _VMPEB
{
	UCHAR InheritedAddressSpace;                                            //0x0
	UCHAR ReadImageFileExecOptions;                                         //0x1
	UCHAR BeingDebugged;                                                    //0x2
	union
	{
		UCHAR BitField;                                                     //0x3
		struct
		{
			UCHAR ImageUsesLargePages : 1;                                    //0x3
			UCHAR IsProtectedProcess : 1;                                     //0x3
			UCHAR IsLegacyProcess : 1;                                        //0x3
			UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
			UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
			UCHAR IsPackagedProcess : 1;                                      //0x3
			UCHAR IsAppContainer : 1;                                         //0x3
			UCHAR SpareBits : 1;                                              //0x3
		};
	};
	VOID* Mutant;                                                           //0x4
	VOID* ImageBaseAddress;                                                 //0x8
	struct _PEB_LDR_DATA* Ldr;                                              //0xc
	struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;                 //0x10
	VOID* SubSystemData;                                                    //0x14
	VOID* ProcessHeap;                                                      //0x18
	struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x1c
	VOID* AtlThunkSListPtr;                                                 //0x20
	VOID* IFEOKey;                                                          //0x24
	union
	{
		ULONG CrossProcessFlags;                                            //0x28
		struct
		{
			ULONG ProcessInJob : 1;                                           //0x28
			ULONG ProcessInitializing : 1;                                    //0x28
			ULONG ProcessUsingVEH : 1;                                        //0x28
			ULONG ProcessUsingVCH : 1;                                        //0x28
			ULONG ProcessUsingFTH : 1;                                        //0x28
			ULONG ReservedBits0 : 27;                                         //0x28
		};
	};
	union
	{
		VOID* KernelCallbackTable;                                          //0x2c
		VOID* UserSharedInfoPtr;                                            //0x2c
	};
	ULONG SystemReserved[1];                                                //0x30
	ULONG AtlThunkSListPtr32;                                               //0x34
	VOID* ApiSetMap;                                                        //0x38
	ULONG TlsExpansionCounter;                                              //0x3c
	VOID* TlsBitmap;                                                        //0x40
	ULONG TlsBitmapBits[2];                                                 //0x44
	VOID* ReadOnlySharedMemoryBase;                                         //0x4c
	VOID* HotpatchInformation;                                              //0x50
	VOID** ReadOnlyStaticServerData;                                        //0x54
	VOID* AnsiCodePageData;                                                 //0x58
	VOID* OemCodePageData;                                                  //0x5c
	VOID* UnicodeCaseTableData;                                             //0x60
	ULONG NumberOfProcessors;                                               //0x64
	ULONG NtGlobalFlag;                                                     //0x68
	union _LARGE_INTEGER CriticalSectionTimeout;                            //0x70
	ULONG HeapSegmentReserve;                                               //0x78
	ULONG HeapSegmentCommit;                                                //0x7c
	ULONG HeapDeCommitTotalFreeThreshold;                                   //0x80
	ULONG HeapDeCommitFreeBlockThreshold;                                   //0x84
	ULONG NumberOfHeaps;                                                    //0x88
	ULONG MaximumNumberOfHeaps;                                             //0x8c
	VOID** ProcessHeaps;                                                    //0x90
	VOID* GdiSharedHandleTable;                                             //0x94
	VOID* ProcessStarterHelper;                                             //0x98
	ULONG GdiDCAttributeList;                                               //0x9c
	struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0xa0
	ULONG OSMajorVersion;                                                   //0xa4
	ULONG OSMinorVersion;                                                   //0xa8
	USHORT OSBuildNumber;                                                   //0xac
	USHORT OSCSDVersion;                                                    //0xae
	ULONG OSPlatformId;                                                     //0xb0
	ULONG ImageSubsystem;                                                   //0xb4
	ULONG ImageSubsystemMajorVersion;                                       //0xb8
	ULONG ImageSubsystemMinorVersion;                                       //0xbc
	ULONG ActiveProcessAffinityMask;                                        //0xc0
	ULONG GdiHandleBuffer[34];                                              //0xc4
	VOID*PostProcessInitRoutine;                                            //0x14c
	VOID* TlsExpansionBitmap;                                               //0x150
	ULONG TlsExpansionBitmapBits[32];                                       //0x154
	ULONG SessionId;                                                        //0x1d4
	union _ULARGE_INTEGER AppCompatFlags;                                   //0x1d8
	union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x1e0
	VOID* pShimData;                                                        //0x1e8
	VOID* AppCompatInfo;                                                    //0x1ec
	struct _UNICODE_STRING CSDVersion;                                      //0x1f0
	VOID* ActivationContextData;                                            //0x1f8
	VOID* ProcessAssemblyStorageMap;                                        //0x1fc
	VOID* SystemDefaultActivationContextData;                               //0x200
	VOID* SystemAssemblyStorageMap;                                         //0x204
	ULONG MinimumStackCommit;                                               //0x208
	VOID* FlsCallback;                                                      //0x20c
	struct _LIST_ENTRY FlsListHead;                                         //0x210
	VOID* FlsBitmap;                                                        //0x218
	ULONG FlsBitmapBits[4];                                                 //0x21c
	ULONG FlsHighIndex;                                                     //0x22c
	VOID* WerRegistrationData;                                              //0x230
	VOID* WerShipAssertPtr;                                                 //0x234
	VOID* pUnused;                                                          //0x238
	VOID* pImageHeaderHash;                                                 //0x23c
	union
	{
		ULONG TracingFlags;                                                 //0x240
		struct
		{
			ULONG HeapTracingEnabled : 1;                                     //0x240
			ULONG CritSecTracingEnabled : 1;                                  //0x240
			ULONG LibLoaderTracingEnabled : 1;                                //0x240
			ULONG SpareTracingBits : 29;                                      //0x240
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x248
}VMPEB, *PVMPEB;


typedef struct _VMGDI_TEB_BATCH
{
	ULONG Offset;                                                           //0x0
	ULONG HDC;                                                              //0x4
	ULONG Buffer[310];                                                      //0x8
}VMGDI_TEB_BATCH, *PVMGDI_TEB_BATCH;

typedef struct _VMTEB
{
	struct _NT_TIB NtTib;                                                   //0x0
	VOID* EnvironmentPointer;                                               //0x1c
	struct _CLIENT_ID ClientId;                                             //0x20
	VOID* ActiveRpcHandle;                                                  //0x28
	VOID* ThreadLocalStoragePointer;                                        //0x2c
	struct _VMPEB* ProcessEnvironmentBlock;                                 //0x30
	ULONG LastErrorValue;                                                   //0x34
	ULONG CountOfOwnedCriticalSections;                                     //0x38
	VOID* CsrClientThread;                                                  //0x3c
	VOID* Win32ThreadInfo;                                                  //0x40
	ULONG User32Reserved[26];                                               //0x44
	ULONG UserReserved[5];                                                  //0xac
	VOID* WOW32Reserved;                                                    //0xc0
	ULONG CurrentLocale;                                                    //0xc4
	ULONG FpSoftwareStatusRegister;                                         //0xc8
	VOID* SystemReserved1[54];                                              //0xcc
	LONG ExceptionCode;                                                     //0x1a4
	VOID* ActivationContextStackPointer;                                    //0x1a8
	UCHAR SpareBytes[36];                                                   //0x1ac
	ULONG TxFsContext;                                                      //0x1d0
	struct _VMGDI_TEB_BATCH GdiTebBatch;                                      //0x1d4
	struct _CLIENT_ID RealClientId;                                         //0x6b4
	VOID* GdiCachedProcessHandle;                                           //0x6bc
	ULONG GdiClientPID;                                                     //0x6c0
	ULONG GdiClientTID;                                                     //0x6c4
	VOID* GdiThreadLocalInfo;                                               //0x6c8
	ULONG Win32ClientInfo[62];                                              //0x6cc
	VOID* glDispatchTable[233];                                             //0x7c4
	ULONG glReserved1[29];                                                  //0xb68
	VOID* glReserved2;                                                      //0xbdc
	VOID* glSectionInfo;                                                    //0xbe0
	VOID* glSection;                                                        //0xbe4
	VOID* glTable;                                                          //0xbe8
	VOID* glCurrentRC;                                                      //0xbec
	VOID* glContext;                                                        //0xbf0
	ULONG LastStatusValue;                                                  //0xbf4
	struct _UNICODE_STRING StaticUnicodeString;                             //0xbf8
	WCHAR StaticUnicodeBuffer[261];                                         //0xc00
	VOID* DeallocationStack;                                                //0xe0c
	VOID* TlsSlots[64];                                                     //0xe10
	struct _LIST_ENTRY TlsLinks;                                            //0xf10
	VOID* Vdm;                                                              //0xf18
	VOID* ReservedForNtRpc;                                                 //0xf1c
	VOID* DbgSsReserved[2];                                                 //0xf20
	ULONG HardErrorMode;                                                    //0xf28
	VOID* Instrumentation[9];                                               //0xf2c
	struct _GUID ActivityId;                                                //0xf50
	VOID* SubProcessTag;                                                    //0xf60
	VOID* PerflibData;                                                      //0xf64
	VOID* EtwTraceData;                                                     //0xf68
	VOID* WinSockData;                                                      //0xf6c
	ULONG GdiBatchCount;                                                    //0xf70
	union
	{
		struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0xf74
		ULONG IdealProcessorValue;                                          //0xf74
		struct
		{
			UCHAR ReservedPad0;                                             //0xf74
			UCHAR ReservedPad1;                                             //0xf75
			UCHAR ReservedPad2;                                             //0xf76
			UCHAR IdealProcessor;                                           //0xf77
		};
	};
	ULONG GuaranteedStackBytes;                                             //0xf78
	VOID* ReservedForPerf;                                                  //0xf7c
	VOID* ReservedForOle;                                                   //0xf80
	ULONG WaitingOnLoaderLock;                                              //0xf84
	VOID* SavedPriorityState;                                               //0xf88
	ULONG ReservedForCodeCoverage;                                          //0xf8c
	VOID* ThreadPoolData;                                                   //0xf90
	VOID** TlsExpansionSlots;                                               //0xf94
	ULONG MuiGeneration;                                                    //0xf98
	ULONG IsImpersonating;                                                  //0xf9c
	VOID* NlsCache;                                                         //0xfa0
	VOID* pShimData;                                                        //0xfa4
	USHORT HeapVirtualAffinity;                                             //0xfa8
	USHORT LowFragHeapDataSlot;                                             //0xfaa
	VOID* CurrentTransactionHandle;                                         //0xfac
	VOID* ActiveFrame;                                                      //0xfb0
	VOID* FlsData;                                                          //0xfb4
	VOID* PreferredLanguages;                                               //0xfb8
	VOID* UserPrefLanguages;                                                //0xfbc
	VOID* MergedPrefLanguages;                                              //0xfc0
	ULONG MuiImpersonation;                                                 //0xfc4
	union
	{
		volatile USHORT CrossTebFlags;                                      //0xfc8
		USHORT SpareCrossTebBits : 16;                                        //0xfc8
	};
	union
	{
		USHORT SameTebFlags;                                                //0xfca
		struct
		{
			USHORT SafeThunkCall : 1;                                         //0xfca
			USHORT InDebugPrint : 1;                                          //0xfca
			USHORT HasFiberData : 1;                                          //0xfca
			USHORT SkipThreadAttach : 1;                                      //0xfca
			USHORT WerInShipAssertCode : 1;                                   //0xfca
			USHORT RanProcessInit : 1;                                        //0xfca
			USHORT ClonedThread : 1;                                          //0xfca
			USHORT SuppressDebugMsg : 1;                                      //0xfca
			USHORT DisableUserStackWalk : 1;                                  //0xfca
			USHORT RtlExceptionAttached : 1;                                  //0xfca
			USHORT InitialThread : 1;                                         //0xfca
			USHORT SessionAware : 1;                                          //0xfca
			USHORT SpareSameTebBits : 4;                                      //0xfca
		};
	};
	VOID* TxnScopeEnterCallback;                                            //0xfcc
	VOID* TxnScopeExitCallback;                                             //0xfd0
	VOID* TxnScopeContext;                                                  //0xfd4
	ULONG LockCount;                                                        //0xfd8
	ULONG SpareUlong0;                                                      //0xfdc
	VOID* ResourceRetValue;                                                 //0xfe0
	VOID* ReservedForWdf;                                                   //0xfe4
}VMTEB, *PVMTEB;

*/