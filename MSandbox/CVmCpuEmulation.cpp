#include "CVmCpuEmulation.h"
#include <capstone/capstone.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <atlstr.h>
#include <shellapi.h>
#include "CPeLoader.h"
#include "CMemManager.h"
#include "CVmcpu.h"
#include "CVmApiHook.h"

#define EXCP00_DIVZ	    0
#define EXCP01_DB		1
#define EXCP02_NMI		2
#define EXCP03_INT3		3
#define EXCP04_INTO		4
#define EXCP05_BOUND	5
#define EXCP06_ILLOP	6
#define EXCP07_PREX		7
#define EXCP08_DBLE		8
#define EXCP09_XERR		9
#define EXCP0A_TSS		10
#define EXCP0B_NOSEG	11
#define EXCP0C_STACK	12
#define EXCP0D_GPF		13
#define EXCP0E_PAGE		14
#define EXCP10_COPR		16
#define EXCP11_ALGN		17
#define EXCP12_MCHK		18
#define EXCP_SYSCALL    0x100 /* only happens in user only emulation
								 for syscall instruction */


#include <pshpack1.h>
union SegmentSelector {
	unsigned short all;
	struct {
		unsigned short rpl : 2;  //!< Requested Privilege Level
		unsigned short ti : 1;   //!< Table Indicator
		unsigned short index : 13;
	} fields;
};
static_assert(sizeof(SegmentSelector) == 2, "Size check");
#include <poppack.h>

#include <pshpack8.h>
union SegmentDescriptor {
	ULONG64 all;
	struct {
		ULONG64 limit_low : 16;
		ULONG64 base_low : 16;
		ULONG64 base_mid : 8;
		ULONG64 type : 4;
		ULONG64 system : 1;
		ULONG64 dpl : 2;
		ULONG64 present : 1;
		ULONG64 limit_high : 4;
		ULONG64 avl : 1;
		ULONG64 l : 1;  //!< 64-bit code segment (IA-32e mode only)
		ULONG64 db : 1;
		ULONG64 gran : 1;
		ULONG64 base_high : 8;
	} fields;
};
static_assert(sizeof(SegmentDescriptor) == 8, "Size check");
#include <poppack.h>

struct SegmentDesctiptor64Bit {
	SegmentDescriptor descriptor;
	ULONG32 base_upper32;
	ULONG32 reserved;
};
static_assert(sizeof(SegmentDesctiptor64Bit) == 16, "Size check");

union FlagRegister {
	ULONG_PTR all;
	struct {
		ULONG_PTR cf : 1;          //!< [0] Carry flag
		ULONG_PTR reserved1 : 1;   //!< [1] Always 1
		ULONG_PTR pf : 1;          //!< [2] Parity flag
		ULONG_PTR reserved2 : 1;   //!< [3] Always 0
		ULONG_PTR af : 1;          //!< [4] Borrow flag
		ULONG_PTR reserved3 : 1;   //!< [5] Always 0
		ULONG_PTR zf : 1;          //!< [6] Zero flag
		ULONG_PTR sf : 1;          //!< [7] Sign flag
		ULONG_PTR tf : 1;          //!< [8] Trap flag
		ULONG_PTR intf : 1;        //!< [9] Interrupt flag
		ULONG_PTR df : 1;          //!< [10] Direction flag
		ULONG_PTR of : 1;          //!< [11] Overflow flag
		ULONG_PTR iopl : 2;        //!< [12:13] I/O privilege level
		ULONG_PTR nt : 1;          //!< [14] Nested task flag
		ULONG_PTR reserved4 : 1;   //!< [15] Always 0
		ULONG_PTR rf : 1;          //!< [16] Resume flag
		ULONG_PTR vm : 1;          //!< [17] Virtual 8086 mode
		ULONG_PTR ac : 1;          //!< [18] Alignment check
		ULONG_PTR vif : 1;         //!< [19] Virtual interrupt flag
		ULONG_PTR vip : 1;         //!< [20] Virtual interrupt pending
		ULONG_PTR id : 1;          //!< [21] Identification flag
		ULONG_PTR reserved5 : 10;  //!< [22:31] Always 0
	} fields;
};
static_assert(sizeof(FlagRegister) == sizeof(void*), "Size check");



#define MAX_GDT_SELECTER_COUNT 128
struct GDT_Descriptor
{
	GDT_Descriptor()
	{
		memset(&gdt64[0], 0, sizeof(SegmentDesctiptor64Bit) * MAX_GDT_SELECTER_COUNT);
		memset(&gdt32[0], 0, sizeof(SegmentDescriptor) * MAX_GDT_SELECTER_COUNT);
	}
	SegmentDesctiptor64Bit gdt64[MAX_GDT_SELECTER_COUNT];
	SegmentDescriptor gdt32[MAX_GDT_SELECTER_COUNT];
};








typedef struct _VMGDI_TEB_BATCH64
{
	ULONG Offset : 31;
	ULONG HasRenderingCommand : 1;
	ULONGLONG HDC;
	ULONG Buffer[310];
}VMGDI_TEB_BATCH64, *PVMGDI_TEB_BATCH64;

typedef struct _VMGDI_TEB_BATCH32
{
	ULONG Offset : 31;
	ULONG HasRenderingCommand : 1;
	ULONG HDC;
	ULONG Buffer[310];
}VMGDI_TEB_BATCH32, *PVMGDI_TEB_BATCH32;

typedef struct _UNICODE_STRING_64bit {
	USHORT Length;
	USHORT MaximumLength;
	ULONGLONG Buffer;
} UNICODE_STRING_64bit;

typedef struct _STRING_32bit {
	USHORT Length;
	USHORT MaximumLength;
	ULONG Buffer;
} STRING_32bit;

typedef struct _RTL_USER_PROCESS_PARAMETERS_64bit {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING_64bit ImagePathName;
	UNICODE_STRING_64bit CommandLine;
} RTL_USER_PROCESS_PARAMETERS_64bit, *PRTL_USER_PROCESS_PARAMETERS_64bit;

typedef struct _PEB_LDR_DATA_64bit {
	BYTE Reserved1[8];
	ULONGLONG Reserved2[3];
	LIST_ENTRY64 InMemoryOrderModuleList;
} PEB_LDR_DATA_64bit, *PPEB_LDR_DATA_64bit;

typedef struct _LDR_DATA_TABLE_ENTRY_64bit {
	ULONGLONG Reserved1[2];
	LIST_ENTRY64 InMemoryOrderLinks;
	ULONGLONG Reserved2[2];
	ULONGLONG DllBase;
	ULONGLONG Reserved3[2];
	UNICODE_STRING_64bit FullDllName;
	BYTE Reserved4[8];
	ULONGLONG Reserved5[3];
#pragma warning(push)
#pragma warning(disable: 4201) // we'll always use the Microsoft compiler
	union {
		ULONG CheckSum;
		ULONGLONG Reserved6;
	} DUMMYUNIONNAME;
#pragma warning(pop)
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_64bit, *PLDR_DATA_TABLE_ENTRY_64bit;

typedef struct _VMPEB64
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsesLargePages : 1;
			UCHAR IsProtectedProcess : 1;
			UCHAR IsLegacyProcess : 1;
			UCHAR IsImageDynamicallyRelocated : 1;
			UCHAR SkipPatchingUser32Forwarders : 1;
			UCHAR IsPackagedProcess : 1;
			UCHAR IsAppContainer : 1;
			UCHAR SpareBits : 1;
		};
	};
	ULONGLONG Mutant;
	ULONGLONG ImageBaseAddress;
	ULONGLONG Ldr;                    //struct _PEB_LDR_DATA*
	ULONGLONG ProcessParameters;      //struct _RTL_USER_PROCESS_PARAMETERS*             
	ULONGLONG SubSystemData;
	ULONGLONG ProcessHeap;
	ULONGLONG FastPebLock;                             
	ULONGLONG AtlThunkSListPtr;
	ULONGLONG IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ReservedBits0 : 27;
		};
	};
	union
	{
		ULONGLONG KernelCallbackTable;                                 
		ULONGLONG UserSharedInfoPtr;                                   
	};
	ULONG SystemReserved[1];                                           
	ULONG AtlThunkSListPtr32;                                          
	ULONGLONG ApiSetMap;                                               
	ULONG TlsExpansionCounter;                                         
	ULONGLONG TlsBitmap;                                               
	ULONG TlsBitmapBits[2];                                            
	ULONGLONG ReadOnlySharedMemoryBase;                                
	ULONGLONG HotpatchInformation;                                     
	ULONGLONG ReadOnlyStaticServerData;                                
	ULONGLONG AnsiCodePageData;                                        
	ULONGLONG OemCodePageData;                                         
	ULONGLONG UnicodeCaseTableData;                                    
	ULONG NumberOfProcessors;                                          
	ULONG NtGlobalFlag;                                                
	union _LARGE_INTEGER CriticalSectionTimeout;                       
	ULONG HeapSegmentReserve;                                          
	ULONG HeapSegmentCommit;                                           
	ULONG HeapDeCommitTotalFreeThreshold;                              
	ULONG HeapDeCommitFreeBlockThreshold;                              
	ULONG NumberOfHeaps;                                               
	ULONG MaximumNumberOfHeaps;                                        
	ULONGLONG ProcessHeaps;                                            
	ULONGLONG GdiSharedHandleTable;                                    
	ULONGLONG ProcessStarterHelper;                                    
	ULONG GdiDCAttributeList;                                          
	ULONGLONG LoaderLock;            //struct _RTL_CRITICAL_SECTION*
	ULONG OSMajorVersion;                                                
	ULONG OSMinorVersion;                                                
	USHORT OSBuildNumber;                                                
	USHORT OSCSDVersion;                                                 
	ULONG OSPlatformId;                                                  
	ULONG ImageSubsystem;                                                
	ULONG ImageSubsystemMajorVersion;                                    
	ULONG ImageSubsystemMinorVersion;                                    
	ULONG ActiveProcessAffinityMask;                                     
	ULONG GdiHandleBuffer[34];                                           
	ULONGLONG PostProcessInitRoutine;                                    
	ULONGLONG TlsExpansionBitmap;                                        
	ULONG TlsExpansionBitmapBits[32];                                    
	ULONG SessionId;                                                     
	union _ULARGE_INTEGER AppCompatFlags;                                
	union _ULARGE_INTEGER AppCompatFlagsUser;                            
	ULONGLONG pShimData;                                                 
	ULONGLONG AppCompatInfo;                                             
	struct _UNICODE_STRING_64bit CSDVersion;                             
	ULONGLONG ActivationContextData;                                     
	ULONGLONG ProcessAssemblyStorageMap;                                 
	ULONGLONG SystemDefaultActivationContextData;                        
	ULONGLONG SystemAssemblyStorageMap;                                  
	ULONG MinimumStackCommit;                                            
	ULONGLONG FlsCallback;                                               
	struct LIST_ENTRY64 FlsListHead;
	ULONGLONG FlsBitmap;                                                 
	ULONG FlsBitmapBits[4];                                              
	ULONG FlsHighIndex;                                                  
	ULONGLONG WerRegistrationData;                                       
	ULONGLONG WerShipAssertPtr;                                          
	ULONGLONG pUnused;                                                   
	ULONGLONG pImageHeaderHash;                                          
	union
	{
		ULONG TracingFlags;                                              
		struct
		{
			ULONG HeapTracingEnabled : 1;                                
			ULONG CritSecTracingEnabled : 1;                             
			ULONG LibLoaderTracingEnabled : 1;                           
			ULONG SpareTracingBits : 29;                                 
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	ULONG TppWorkerpListLock;                                       
	struct LIST_ENTRY64 TppWorkerpList;                             
	ULONGLONG WaitOnAddressHashTable[128];                          
	ULONGLONG TelemetryCoverageHeader;                              
	ULONG CloudFileFlags;                                           
	ULONG CloudFileDiagFlags;                                       
	CHAR PlaceholderCompatibilityMode;                              
	CHAR PlaceholderCompatibilityModeReserved[7];                   
	ULONGLONG LeapSecondData;										
	union
	{
		ULONG LeapSecondFlags;                                      
		struct
		{
			ULONG SixtySecondEnabled : 1;                           
			ULONG Reserved : 31;                                    
		};
	};
	ULONG NtGlobalFlag2;
}VMPEB64, *PVMPEB64;


typedef struct _EXCEPTION_REGISTRATION_RECORD_64bit
{
	ULONGLONG Next;
	ULONGLONG Handler;
} EXCEPTION_REGISTRATION_RECORD_64bit, *PEXCEPTION_REGISTRATION_RECORD_64bit;

typedef struct _NT_TIB_64bit 
{
	ULONGLONG ExceptionList;                                         
	ULONGLONG StackBase;                                             
	ULONGLONG StackLimit;                                            
	ULONGLONG SubSystemTib;                                          
	union
	{
		ULONGLONG FiberData;                                         
		ULONG Version;                                               
	};
	ULONGLONG ArbitraryUserPointer;                                  
	ULONGLONG Self;                                                  
} NT_TIB_64bit, *PNT_TIB_64bit;

typedef struct _NT_TIB_32bit
{
	ULONG ExceptionList;                                             
	ULONG StackBase;                                                 
	ULONG StackLimit;                                                
	ULONG SubSystemTib;                                              
	union
	{
		ULONG FiberData;                                             
		ULONG Version;                                               
	};
	ULONG ArbitraryUserPointer;                                      
	ULONG Self;                                                      
}NT_TIB_32bit, *PNT_TIB_32bit;

typedef struct _CLIENT_ID_64bit {
	ULONGLONG UniqueProcess;
	ULONGLONG UniqueThread;
} CLIENT_ID_64bit;

typedef struct _CLIENT_ID_32bit {
	ULONG UniqueProcess;
	ULONG UniqueThread;
} CLIENT_ID_32bit;

typedef struct _VM_ACTIVATION_CONTEXT_STACK64
{
	ULONGLONG ActiveFrame;                                           
	struct LIST_ENTRY64 FrameListCache;                              
	ULONG Flags;                                                     
	ULONG NextCookieSequenceNumber;                                  
	ULONG StackId;                                                   
}VM_ACTIVATION_CONTEXT_STACK64, PVM_ACTIVATION_CONTEXT_STACK64;

typedef struct _VM_ACTIVATION_CONTEXT_STACK32
{
	ULONG ActiveFrame;                                               
	struct LIST_ENTRY32 FrameListCache;                              
	ULONG Flags;                                                     
	ULONG NextCookieSequenceNumber;                                  
	ULONG StackId;                                                   
}VM_ACTIVATION_CONTEXT_STACK32, PVM_ACTIVATION_CONTEXT_STACK32;

typedef struct _VMTEB64
{
	struct _NT_TIB64 NtTib;                                          
	ULONGLONG EnvironmentPointer;                                    
	struct _CLIENT_ID_64bit ClientId;                                
	ULONGLONG ActiveRpcHandle;                                       
	ULONGLONG ThreadLocalStoragePointer;                             
	ULONGLONG ProcessEnvironmentBlock;                               
	ULONG LastErrorValue;                                            
	ULONG CountOfOwnedCriticalSections;                              
	ULONGLONG CsrClientThread;                                       
	ULONGLONG Win32ThreadInfo;                                       
	ULONG User32Reserved[26];                                        
	ULONG UserReserved[5];                                           
	ULONGLONG WOW32Reserved;                                         
	ULONG CurrentLocale;                                             
	ULONG FpSoftwareStatusRegister;                                   
	ULONGLONG ReservedForDebuggerInstrumentation[16];                 
	ULONGLONG SystemReserved1[30];                                    
	CHAR PlaceholderCompatibilityMode;                                
	UCHAR PlaceholderHydrationAlwaysExplicit;                         
	CHAR PlaceholderReserved[10];                                     
	ULONG ProxiedProcessId;                                           
	struct _VM_ACTIVATION_CONTEXT_STACK64 _ActivationStack;           
	UCHAR WorkingOnBehalfTicket[8];                                   
	LONG ExceptionCode;                                               
	UCHAR Padding0[4];                                                
	ULONGLONG ActivationContextStackPointer;                          
	ULONGLONG InstrumentationCallbackSp;                              
	ULONGLONG InstrumentationCallbackPreviousPc;                      
	ULONGLONG InstrumentationCallbackPreviousSp;                      
	ULONG TxFsContext;                                                
	UCHAR InstrumentationCallbackDisabled;                            
	UCHAR UnalignedLoadStoreExceptions;                               
	UCHAR Padding1[2];                                                
	struct _VMGDI_TEB_BATCH64 GdiTebBatch;                            
	struct _CLIENT_ID_64bit RealClientId;                             
	ULONGLONG GdiCachedProcessHandle;                                 
	ULONG GdiClientPID;                                               
	ULONG GdiClientTID;                                               
	ULONGLONG GdiThreadLocalInfo;                                     
	ULONGLONG Win32ClientInfo[62];                                    
	ULONGLONG glDispatchTable[233];                                   
	ULONGLONG glReserved1[29];                                        
	ULONGLONG glReserved2;                                            
	ULONGLONG glSectionInfo;                                          
	ULONGLONG glSection;                                              
	ULONGLONG glTable;                                                
	ULONGLONG glCurrentRC;                                            
	ULONGLONG glContext;                                              
	ULONG LastStatusValue;                                            
	UCHAR Padding2[4];                                                
	struct _UNICODE_STRING_64bit StaticUnicodeString;                 
	WCHAR StaticUnicodeBuffer[261];                                
	UCHAR Padding3[6];                                             
	ULONGLONG DeallocationStack;                                   
	ULONGLONG TlsSlots[64];                                        
	struct LIST_ENTRY64 TlsLinks;                                  
	ULONGLONG Vdm;                                                 
	ULONGLONG ReservedForNtRpc;                                    
	ULONGLONG DbgSsReserved[2];                                    
	ULONG HardErrorMode;                                           
	UCHAR Padding4[4];                                             
	ULONGLONG Instrumentation[11];                                 
	struct _GUID ActivityId;                                       
	ULONGLONG SubProcessTag;                                       
	ULONGLONG PerflibData;                                         
	ULONGLONG EtwTraceData;                                        
	ULONGLONG WinSockData;                                         
	ULONG GdiBatchCount;                                           
	union
	{
		struct _PROCESSOR_NUMBER CurrentIdealProcessor;            
		ULONG IdealProcessorValue;                                 
		struct
		{
			UCHAR ReservedPad0;                                    
			UCHAR ReservedPad1;                                    
			UCHAR ReservedPad2;                                    
			UCHAR IdealProcessor;                                  
		};
	};
	ULONG GuaranteedStackBytes;                                    
	UCHAR Padding5[4];                                             
	ULONGLONG ReservedForPerf;                                     
	ULONGLONG ReservedForOle;                                      
	ULONG WaitingOnLoaderLock;                                     
	UCHAR Padding6[4];                                             
	ULONGLONG SavedPriorityState;                                  
	ULONGLONG ReservedForCodeCoverage;                             
	ULONGLONG ThreadPoolData;                                      
	ULONGLONG TlsExpansionSlots;                                     
	ULONGLONG DeallocationBStore;                                    
	ULONGLONG BStoreLimit;                                           
	ULONG MuiGeneration;                                             
	ULONG IsImpersonating;                                           
	ULONGLONG NlsCache;                                              
	ULONGLONG pShimData;                                             
	ULONG HeapData;                                                  
	UCHAR Padding7[4];                                               
	ULONGLONG CurrentTransactionHandle;                              
	ULONGLONG ActiveFrame;                                           
	ULONGLONG FlsData;                                               
	ULONGLONG PreferredLanguages;                                    
	ULONGLONG UserPrefLanguages;                                     
	ULONGLONG MergedPrefLanguages;                                   
	ULONG MuiImpersonation;                                          
	union
	{
		volatile USHORT CrossTebFlags;                               
		USHORT SpareCrossTebBits : 16;                               
	};
	union
	{
		USHORT SameTebFlags;                                         
		struct
		{
			USHORT SafeThunkCall : 1;                                
			USHORT InDebugPrint : 1;                                 
			USHORT HasFiberData : 1;                                 
			USHORT SkipThreadAttach : 1;                             
			USHORT WerInShipAssertCode : 1;                          
			USHORT RanProcessInit : 1;                               
			USHORT ClonedThread : 1;                                 
			USHORT SuppressDebugMsg : 1;                             
			USHORT DisableUserStackWalk : 1;                         
			USHORT RtlExceptionAttached : 1;                         
			USHORT InitialThread : 1;                                
			USHORT SessionAware : 1;                                 
			USHORT LoadOwner : 1;                                    
			USHORT LoaderWorker : 1;                                 
			USHORT SkipLoaderInit : 1;                               
			USHORT SpareSameTebBits : 1;                             
		};
	};
	ULONGLONG TxnScopeEnterCallback;                                 
	ULONGLONG TxnScopeExitCallback;                                  
	ULONGLONG TxnScopeContext;                                       
	ULONG LockCount;                                                 
	LONG WowTebOffset;                                               
	ULONGLONG ResourceRetValue;                                      
	ULONGLONG ReservedForWdf;                                        
	ULONGLONG ReservedForCrt;                                        
	struct _GUID EffectiveContainerId;                               
}VMTEB64, *PVMTEB64;


typedef struct _VMPEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsesLargePages : 1;
			UCHAR IsProtectedProcess : 1;
			UCHAR IsImageDynamicallyRelocated : 1;
			UCHAR SkipPatchingUser32Forwarders : 1;
			UCHAR IsPackagedProcess : 1;
			UCHAR IsAppContainer : 1;
			UCHAR IsProtectedProcessLight : 1;
			UCHAR IsLongPathAwareProcess : 1;
		};
	};
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		};
	};
	union
	{
		ULONG KernelCallbackTable;
		ULONG UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
	ULONG TlsExpansionCounter;
	ULONG TlsBitmap;
	ULONG TlsBitmapBits[2];
	ULONG ReadOnlySharedMemoryBase;
	ULONG SharedData;
	ULONG ReadOnlyStaticServerData;
	ULONG AnsiCodePageData;
	ULONG OemCodePageData;
	ULONG UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	union _LARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	ULONG ProcessHeaps;
	ULONG GdiSharedHandleTable;
	ULONG ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	ULONG LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	ULONG ActiveProcessAffinityMask;
	ULONG GdiHandleBuffer[34];
	ULONG PostProcessInitRoutine;
	ULONG TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	union _ULARGE_INTEGER AppCompatFlags;
	union _ULARGE_INTEGER AppCompatFlagsUser;
	ULONG pShimData;
	ULONG AppCompatInfo;
	STRING_32bit CSDVersion;
	ULONG ActivationContextData;
	ULONG ProcessAssemblyStorageMap;
	ULONG SystemDefaultActivationContextData;
	ULONG SystemAssemblyStorageMap;
	ULONG MinimumStackCommit;
	ULONG SparePointers[4];
	ULONG SpareUlongs[5];
	ULONG WerRegistrationData;
	ULONG WerShipAssertPtr;
	ULONG pUnused;
	ULONG pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	ULONG TppWorkerpListLock;
	struct LIST_ENTRY32 TppWorkerpList;
	ULONG WaitOnAddressHashTable[128];
	ULONG TelemetryCoverageHeader;
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags;
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	ULONG LeapSecondData;
	union
	{
		ULONG LeapSecondFlags;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
}VMPEB32, *PVMPEB32;

typedef struct _VMTEB32
{
	struct _NT_TIB_32bit NtTib;
	ULONG EnvironmentPointer;                                           
	struct _CLIENT_ID_32bit ClientId;
	ULONG ActiveRpcHandle;                                              
	ULONG ThreadLocalStoragePointer;                                    
	ULONG ProcessEnvironmentBlock;                                      
	ULONG LastErrorValue;                                               
	ULONG CountOfOwnedCriticalSections;                                 
	ULONG CsrClientThread;                                              
	ULONG Win32ThreadInfo;                                              
	ULONG User32Reserved[26];                                           
	ULONG UserReserved[5];                                              
	ULONG WOW32Reserved;                                                
	ULONG CurrentLocale;                                                
	ULONG FpSoftwareStatusRegister;                                     
	ULONG ReservedForDebuggerInstrumentation[16];                       
	ULONG SystemReserved1[26];                                          
	CHAR PlaceholderCompatibilityMode;                                  
	UCHAR PlaceholderHydrationAlwaysExplicit;                           
	CHAR PlaceholderReserved[10];                                       
	ULONG ProxiedProcessId;                                             
	struct _VM_ACTIVATION_CONTEXT_STACK32 _ActivationStack;
	UCHAR WorkingOnBehalfTicket[8];                                     
	LONG ExceptionCode;                                                 
	ULONG ActivationContextStackPointer;                                
	ULONG InstrumentationCallbackSp;                                    
	ULONG InstrumentationCallbackPreviousPc;                            
	ULONG InstrumentationCallbackPreviousSp;                            
	UCHAR InstrumentationCallbackDisabled;                              
	UCHAR SpareBytes[23];                                               
	ULONG TxFsContext;                                                  
	struct _VMGDI_TEB_BATCH32 GdiTebBatch;
	struct _CLIENT_ID_32bit RealClientId;
	ULONG GdiCachedProcessHandle;                                       
	ULONG GdiClientPID;                                                 
	ULONG GdiClientTID;                                                 
	ULONG GdiThreadLocalInfo;                                           
	ULONG Win32ClientInfo[62];                                          
	ULONG glDispatchTable[233];                                         
	ULONG glReserved1[29];                                              
	ULONG glReserved2;                                                  
	ULONG glSectionInfo;                                                
	ULONG glSection;                                                    
	ULONG glTable;                                                      
	ULONG glCurrentRC;                                                  
	ULONG glContext;                                                    
	ULONG LastStatusValue;                                              
	STRING_32bit StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];                                     
	ULONG DeallocationStack;                                            
	ULONG TlsSlots[64];                                                 
	struct LIST_ENTRY32 TlsLinks;                                       
	ULONG Vdm;                                                          
	ULONG ReservedForNtRpc;                                             
	ULONG DbgSsReserved[2];                                             
	ULONG HardErrorMode;                                                
	ULONG Instrumentation[9];                                           
	struct _GUID ActivityId;                                            
	ULONG SubProcessTag;                                                
	ULONG PerflibData;                                                  
	ULONG EtwTraceData;                                                 
	ULONG WinSockData;                                                  
	ULONG GdiBatchCount;                                                
	union
	{
		struct _PROCESSOR_NUMBER CurrentIdealProcessor;                 
		ULONG IdealProcessorValue;                                      
		struct
		{
			UCHAR ReservedPad0;                                         
			UCHAR ReservedPad1;                                         
			UCHAR ReservedPad2;                                         
			UCHAR IdealProcessor;                                       
		};
	};
	ULONG GuaranteedStackBytes;                                         
	ULONG ReservedForPerf;                                              
	ULONG ReservedForOle;                                               
	ULONG WaitingOnLoaderLock;                                          
	ULONG SavedPriorityState;                                           
	ULONG ReservedForCodeCoverage;                                      
	ULONG ThreadPoolData;                                               
	ULONG TlsExpansionSlots;                                            
	ULONG MuiGeneration;                                                
	ULONG IsImpersonating;                                              
	ULONG NlsCache;                                                     
	ULONG pShimData;                                                    
	ULONG HeapData;                                                     
	ULONG CurrentTransactionHandle;                                     
	ULONG ActiveFrame;                                                  
	ULONG FlsData;                                                      
	ULONG PreferredLanguages;                                           
	ULONG UserPrefLanguages;                                            
	ULONG MergedPrefLanguages;                                          
	ULONG MuiImpersonation;                                             
	union
	{
		volatile USHORT CrossTebFlags;                                  
		USHORT SpareCrossTebBits : 16;                                  
	};
	union
	{
		USHORT SameTebFlags;                                            
		struct
		{
			USHORT SafeThunkCall : 1;                                   
			USHORT InDebugPrint : 1;                                    
			USHORT HasFiberData : 1;                                    
			USHORT SkipThreadAttach : 1;                                
			USHORT WerInShipAssertCode : 1;                             
			USHORT RanProcessInit : 1;                                  
			USHORT ClonedThread : 1;                                    
			USHORT SuppressDebugMsg : 1;                                
			USHORT DisableUserStackWalk : 1;                            
			USHORT RtlExceptionAttached : 1;                            
			USHORT InitialThread : 1;                                   
			USHORT SessionAware : 1;                                    
			USHORT LoadOwner : 1;                                       
			USHORT LoaderWorker : 1;                                    
			USHORT SkipLoaderInit : 1;                                  
			USHORT SpareSameTebBits : 1;                                
		};
	};
	ULONG TxnScopeEnterCallback;                                        
	ULONG TxnScopeExitCallback;                                         
	ULONG TxnScopeContext;                                              
	ULONG LockCount;                                                    
	LONG WowTebOffset;                                                  
	ULONG ResourceRetValue;                                             
	ULONG ReservedForWdf;                                               
	ULONGLONG ReservedForCrt;                                           
	struct _GUID EffectiveContainerId;                                  
}VMTEB32, *PVMTEB32;




static void CodeTraceCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
static void IntTraceCallback(uc_engine *uc, int exception, void *user_data);
static void MemUnMapedTraceCallback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void MemUnReadWriteTraceCallback(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
static void CodeHookerCallback(uc_engine *uc, uint64_t address, uint32_t size, void *pContext);
static int HexToAscii(unsigned char* HexData, int HexDataLen, unsigned char* AsciiData, int buflen, char splitchar);
static inline void InitilizeDescriptor64Bit(SegmentDesctiptor64Bit *desc, ULONGLONG base, ULONGLONG limit, bool isCode, bool is64Bit);
static inline void InitilizeDescriptor32Bit(SegmentDescriptor *desc, ULONG base, ULONG limit, bool isCode, bool is64Bit);



CVmCpuEmulation::CVmCpuEmulation()
{


}
CVmCpuEmulation::~CVmCpuEmulation()
{

}



EmulationItem *CVmCpuEmulation::EmulationInit(std::wstring wsFilePath, std::wstring wsRootPath, std::wstring wsParam)
{
	EmulationItem *pRetItem = NULL;
	bool bSuccess = false;
	do 
	{
		pRetItem = new EmulationItem();
		if (pRetItem == NULL)
		{
			break;
		}

		pRetItem->LoadPath.push_back(wsRootPath);

		pRetItem->pvmCpu = std::make_shared<CVmcpu>();
		assert(pRetItem->pvmCpu);

		pRetItem->pmemMgr = std::make_shared<CWinMemManager>();
		assert(pRetItem->pmemMgr);

		pRetItem->pLoader = std::make_shared<CPELoader>();
		assert(pRetItem->pLoader);

		pRetItem->pFileinfo = std::make_shared<sFileInfo>();
		assert(pRetItem->pFileinfo);

		pRetItem->pRegInfo = std::make_shared<sVmCpuRegContext>();
		assert(pRetItem->pRegInfo);
		
		if (!pRetItem->pLoader->LoaderGetFileInfo(wsFilePath.c_str(), pRetItem->pFileinfo))
		{
			break;
		}
	
		if (pRetItem->pFileinfo->arch != UC_ARCH_X86 ||
			pRetItem->pFileinfo->osType != em_windows_pe ||
			(pRetItem->pFileinfo->FileType != FILE_TYPE_EXEC && pRetItem->pFileinfo->FileType != FILE_TYPE_DYNAMIC && 
																pRetItem->pFileinfo->FileType != FILE_TYPE_KERNEL_SYS) ||
			(pRetItem->pFileinfo->BitType != BIT_TYPE_32 && pRetItem->pFileinfo->BitType != BIT_TYPE_64))
		{
			break;
		}

		pRetItem->ullGdtAddress = pRetItem->pFileinfo->BitType == BIT_TYPE_64 ? GDT_ADDRESS_X64 : GDT_ADDRESS_X86;

		if (!pRetItem->pvmCpu->InitilizeVmCpu(UC_ARCH_X86, pRetItem->pFileinfo->BitType == BIT_TYPE_32 ? UC_MODE_32 : UC_MODE_64))
		{
			assert(0);
			break;
		}

		if (CS_ERR_OK != cs_open(CS_ARCH_X86, pRetItem->pFileinfo->BitType == BIT_TYPE_64 ? 
										CS_MODE_64 : CS_MODE_32, (csh *)&pRetItem->ullCapstone))
		{
			assert(0);
			break;
		}

		//初始化主线程栈
		ULONGLONG ullStackBase = pRetItem->pmemMgr->WinMemSpaceAlloc(em_StackType, USERMODE_MAIN_THREAD_STACK_SIZE);
		if (ullStackBase == 0)
		{
			assert(0);
			break;
		}
		DWORD ulStackSize = USERMODE_MAIN_THREAD_STACK_SIZE;
		if (!pRetItem->pvmCpu->VmMapMemory(ullStackBase, ulStackSize, VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true))
		{
			pRetItem->pmemMgr->WinMemSpaceFree(em_StackType, ullStackBase);
			assert(0);
			break;
		}
		sHeapStackSpace sSpace;
		sSpace.ullBase = ullStackBase;
		sSpace.dwSize = ulStackSize;
		pRetItem->stacks.push_back(sSpace);

		ULONGLONG ullReserveHeap = pRetItem->pmemMgr->WinMemSpaceAlloc(pRetItem->pFileinfo->BitType == BIT_TYPE_32 ? 
												em_HeapsType32Bit : em_HeapsType64Bit, USERMODE_HEAPS_SIZE);
		if (ullReserveHeap == 0)
		{
			pRetItem->pmemMgr->WinMemSpaceFree(em_StackType, ullStackBase);
			pRetItem->pvmCpu->VmUnMapMemory(ullStackBase, ulStackSize);
			assert(0);
			break;
		}
		DWORD dwReserveHeapSize = USERMODE_HEAPS_SIZE;
		if (!pRetItem->pvmCpu->VmMapMemory(ullReserveHeap, dwReserveHeapSize, VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true))
		{
			pRetItem->pmemMgr->WinMemSpaceFree(em_StackType, ullStackBase);
			pRetItem->pmemMgr->WinMemSpaceFree(pRetItem->pFileinfo->BitType == BIT_TYPE_32 ? 
												em_HeapsType32Bit : em_HeapsType64Bit, ullReserveHeap);
			assert(0);
			break;
		}
		sSpace.ullBase = ullReserveHeap;
		sSpace.dwSize = (DWORD)dwReserveHeapSize;
		pRetItem->heaps.push_back(sSpace);

		pRetItem->ullMainStackBase = ullStackBase;
		pRetItem->dwStackSize = ulStackSize;
		pRetItem->ullReserveHeapBase = ullReserveHeap;
		pRetItem->dwReserveHeapSize = dwReserveHeapSize;

		InitlizePramEvnInfo(pRetItem, wsFilePath, wsParam);

		ULONGLONG ulImageSize = 0;
		std::shared_ptr<sLoadModule> mianModule = nullptr;
		mianModule = pRetItem->pLoader->LoaderLoadFileEx(wsFilePath.c_str(), pRetItem, mianModule);
		if (mianModule == NULL)
		{
			break;
		}
		mianModule->wsParam = wsParam;
		pRetItem->pModulesInfo = mianModule;

		mianModule->LoadModuleLog();

		if (BIT_TYPE_64 == pRetItem->pFileinfo->BitType)
		{
			// stack start : pRetItem->ullMainStackBase + pRetItem->dwStackSize - PAGE_SIZE
			// stack end   : pRetItem->ullMainStackBase + PAGE_SIZE
			pRetItem->pRegInfo->Regs.a.reg64Bit.Rsp = pRetItem->ullMainStackBase + pRetItem->dwStackSize - PAGE_SIZE;
			pRetItem->pRegInfo->Regs.a.reg64Bit.Rbp = pRetItem->pRegInfo->Regs.a.reg64Bit.Rsp;
			pRetItem->pvmCpu->VmProtectMemory(pRetItem->ullMainStackBase, PAGE_SIZE, VM_MEM_PROTECT_NONE);


			pRetItem->pRegInfo->Regs.a.reg64Bit.Rcx = mianModule->ullLoadbase;
			pRetItem->pRegInfo->Regs.a.reg64Bit.Rdx = DLL_PROCESS_ATTACH;
			pRetItem->pRegInfo->Regs.a.reg64Bit.R8 = 0;

			//entry
			pRetItem->pRegInfo->Regs.a.reg64Bit.Rip = pRetItem->pModulesInfo->ullImageEntry;
		}
		else
		{
			//32位栈初始化
			pRetItem->pRegInfo->Regs.a.reg32Bit.Esp = (ULONG)(pRetItem->ullMainStackBase + pRetItem->dwStackSize - PAGE_SIZE);
			pRetItem->pRegInfo->Regs.a.reg32Bit.Ebp = pRetItem->pRegInfo->Regs.a.reg32Bit.Esp;
			pRetItem->pvmCpu->VmProtectMemory(pRetItem->ullMainStackBase, PAGE_SIZE, VM_MEM_PROTECT_NONE);

			//entry
			pRetItem->pRegInfo->Regs.a.reg32Bit.Eip = (ULONG)pRetItem->pModulesInfo->ullImageEntry;
		}

		pRetItem->ulStartAddress = pRetItem->pModulesInfo->ullImageEntry;
		pRetItem->ulEndAddress   = mianModule->ullLoadbase + mianModule->dwImageSize;
		pRetItem->LastException  = 0;

		InitlizeProcess(pRetItem);

		InitlizePebTeb(pRetItem);

		InitKernelSharedUserData(pRetItem);

		InitlizeVCpuRegister(pRetItem);

		InitlizeHook(pRetItem);

		InitlizeFunctionHook(pRetItem);
		
		bSuccess = true;

		pRetItem->pmemMgr->LOG(BIT_TYPE_32 == pRetItem->pFileinfo->BitType);

	} while (false);

	 if (!bSuccess)
	 {
		 if (pRetItem)
		 {
			 pRetItem->pvmCpu->UnInitilizeVmCpu();
			 delete pRetItem;
			 pRetItem = NULL;
		 }

	 }


	return pRetItem;
}

bool CVmCpuEmulation::EmulationStart(EmulationItem *pEItem)
{
	while (true)
	{
		pEItem->pvmCpu->VmEmulationStart(pEItem->ulStartAddress, pEItem->ulEndAddress, 0, 0);

		if (pEItem->LastException != (LONG)0)
		{
			assert(0);
			return false;
		}
		else
		{
			break;
		}
	}

	return true;
}


bool CVmCpuEmulation::EmulationStop(EmulationItem *pEItem)
{
	pEItem->pvmCpu->VmEmulationStop();
	return true;
}

bool CVmCpuEmulation::EmulationFree(EmulationItem *pEItem)
{
	if (pEItem->uMemUnMapedTrace)
	{
		pEItem->pvmCpu->VmCpuHookDel(pEItem->uMemUnMapedTrace);
		pEItem->uMemUnMapedTrace = 0;
	}
	if (pEItem->uMemUnReadWriteTrace)
	{
		pEItem->pvmCpu->VmCpuHookDel(pEItem->uMemUnReadWriteTrace);
		pEItem->uMemUnReadWriteTrace = 0;
	}
	if (pEItem->uCodeTrace)
	{
		pEItem->pvmCpu->VmCpuHookDel(pEItem->uCodeTrace);
		pEItem->uCodeTrace = 0;
	}
	if (pEItem->uIntTrace)
	{
		pEItem->pvmCpu->VmCpuHookDel(pEItem->uIntTrace);
		pEItem->uIntTrace = 0;
	}

	UnInitlizeFunctionHook();

	if (pEItem->ullCapstone)
	{
		cs_close((csh *)&pEItem->ullCapstone);
		pEItem->ullCapstone = 0;
	}

	pEItem->pvmCpu->UnInitilizeVmCpu();

	return true;
}

static inline void InitilizeDescriptor64Bit(SegmentDesctiptor64Bit *desc, ULONGLONG base, ULONGLONG limit, bool isCode, bool is64Bit)
{
	desc->descriptor.all = 0;  //clear the descriptor
	desc->descriptor.fields.base_low = base;
	desc->descriptor.fields.base_mid = (base >> 16) & 0xff;
	desc->descriptor.fields.base_high = base >> 24;
	desc->base_upper32 = base >> 32;

	if (limit > 0xfffff) 
	{
		limit >>= 12;
		desc->descriptor.fields.gran = 1;
	}

	desc->descriptor.fields.limit_low = limit & 0xffff;
	desc->descriptor.fields.limit_high = limit >> 16;

	desc->descriptor.fields.dpl = 0;
	desc->descriptor.fields.present = 1;
	desc->descriptor.fields.db = 1;      //64 bit
	desc->descriptor.fields.type = isCode ? 0xb : 3;
	desc->descriptor.fields.system = 1;  //code or data
	desc->descriptor.fields.l = is64Bit ? 1 : 0;
}


static inline void InitilizeDescriptor32Bit(SegmentDescriptor *desc, ULONG base, ULONG limit, bool isCode, bool is64Bit)
{
	desc->all = 0;  //clear the descriptor
	desc->fields.base_low = base;
	desc->fields.base_mid = (base >> 16) & 0xff;
	desc->fields.base_high = base >> 24;
	if (limit > 0xfffff)
	{
		limit >>= 12;
		desc->fields.gran = 1;
	}
	desc->fields.limit_low = limit & 0xffff;
	desc->fields.limit_high = limit >> 16;
	desc->fields.dpl = 0;
	desc->fields.present = 1;
	desc->fields.db = 1;      //16 bit or 32 bit segment
	desc->fields.type = isCode ? 0xb : 3;
	desc->fields.system = 1;  //code or data
	desc->fields.l = is64Bit ? 1 : 0; //64 bit segment
}


bool CVmCpuEmulation::InitlizeProcess(EmulationItem * pEmulContext)
{
	uc_x86_mmr gdtr = {0};
	GDT_Descriptor GDT;

	gdtr.base  = pEmulContext->ullGdtAddress;
	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		gdtr.limit = sizeof(GDT.gdt32) - 1;
		InitilizeDescriptor32Bit(&GDT.gdt32[GDT_SEGMENTSELECTOR_INDEX_CS], 0, 0xffffffff, true, false);
		InitilizeDescriptor32Bit(&GDT.gdt32[GDT_SEGMENTSELECTOR_INDEX_DS], 0, 0xffffffff, false, false);
	}
	else
	{
		gdtr.limit = sizeof(GDT.gdt64) - 1;
		InitilizeDescriptor64Bit(&GDT.gdt64[GDT_SEGMENTSELECTOR_INDEX_CS], 0, 0xffffffffffffffff, true, true);
		InitilizeDescriptor64Bit(&GDT.gdt64[GDT_SEGMENTSELECTOR_INDEX_DS], 0, 0xffffffffffffffff, false, true);
	}
	DWORD dwVMGdtDescSize = ALIGN_SIZE_UP(gdtr.limit + 1, PAGE_SIZE);

	if (!pEmulContext->pvmCpu->VmMapMemory(pEmulContext->ullGdtAddress, dwVMGdtDescSize, UC_PROT_READ, true))
	{
		return false;
	}

	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		if (!pEmulContext->pvmCpu->VmWriteMemory(pEmulContext->ullGdtAddress, (const void *)&GDT.gdt32[0], sizeof(GDT.gdt32)))
		{
			pEmulContext->pvmCpu->VmUnMapMemory(pEmulContext->ullGdtAddress, dwVMGdtDescSize);
			return false;
		}
	}
	else
	{
		if (!pEmulContext->pvmCpu->VmWriteMemory(pEmulContext->ullGdtAddress, (const void *)&GDT.gdt64[0], sizeof(GDT.gdt64)))
		{
			pEmulContext->pvmCpu->VmUnMapMemory(pEmulContext->ullGdtAddress, dwVMGdtDescSize);
			return false;
		}
	}

	if (!pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_GDTR, &gdtr))
	{
		pEmulContext->pvmCpu->VmUnMapMemory(pEmulContext->ullGdtAddress, dwVMGdtDescSize);
		return false;
	}

	bool bRet = false;
	SegmentSelector cs = {0};
	cs.fields.index = GDT_SEGMENTSELECTOR_INDEX_CS;
	bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_CS, &cs.all);
	assert(bRet);
	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		pEmulContext->pRegInfo->Regs.a.reg32Bit.SegCs = cs.all;
	}
	else
	{
		pEmulContext->pRegInfo->Regs.a.reg64Bit.SegCs = cs.all;
	}
	
	SegmentSelector ds = {0};
	ds.fields.index = GDT_SEGMENTSELECTOR_INDEX_DS;
	bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_DS, &ds.all);
	assert(bRet);
	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		pEmulContext->pRegInfo->Regs.a.reg32Bit.SegDs = ds.all;
	}
	else
	{
		pEmulContext->pRegInfo->Regs.a.reg64Bit.SegDs = ds.all;
	}
	
	SegmentSelector ss = {0};
	ss.fields.index = GDT_SEGMENTSELECTOR_INDEX_DS;
	bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_SS, &ss.all);
	assert(bRet);
	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		pEmulContext->pRegInfo->Regs.a.reg32Bit.SegSs = ss.all;
	}
	else
	{
		pEmulContext->pRegInfo->Regs.a.reg64Bit.SegSs = ss.all;
	}

	SegmentSelector es = {0};
	es.fields.index = GDT_SEGMENTSELECTOR_INDEX_DS;
	bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_ES, &es.all);
	assert(bRet);
	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		pEmulContext->pRegInfo->Regs.a.reg32Bit.SegEs = es.all;
	}
	else
	{
		pEmulContext->pRegInfo->Regs.a.reg64Bit.SegEs = es.all;
	}

	FlagRegister eflags = {0};
	eflags.fields.id = 1;
	eflags.fields.intf = 1;
	eflags.fields.reserved1 = 1;
	bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_EFLAGS, &eflags.all);
	assert(bRet);
	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		pEmulContext->pRegInfo->Regs.a.reg32Bit.EFlags = (ULONG)eflags.all;
	}
	else
	{
		pEmulContext->pRegInfo->Regs.a.reg64Bit.EFlags = (ULONG)eflags.all;
	}

	ULONG cr8 = 0;
	bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_CR8, &cr8);
	assert(bRet);

	return true;
}

bool CVmCpuEmulation::InitlizePebTeb(EmulationItem * pEmulContext)
{
	VMPEB64 Peb64 = {0};
	VMPEB32 Peb32 = {0};
	ULONGLONG ullPebBase = 0;
	bool bRet = false;

	DWORD dwPebSize = 0;
	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		dwPebSize = ALIGN_SIZE_UP((DWORD)sizeof(VMPEB32), PAGE_SIZE);
	}
	else
	{
		dwPebSize = ALIGN_SIZE_UP((DWORD)sizeof(VMPEB64), PAGE_SIZE);
	}

	ullPebBase = pEmulContext->pmemMgr->WinMemSpaceAlloc(em_MTProcessInfoType, dwPebSize);
	if (ullPebBase == 0)
	{
		return false;
	}
	bRet = pEmulContext->pvmCpu->VmMapMemory(ullPebBase, dwPebSize, VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true);
	assert(bRet);

	//初始化heaps
	//初始化ldr链



	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		Peb32.ProcessHeap = NULL;
		Peb32.NumberOfProcessors = 4;
		Peb32.ImageBaseAddress = (ULONG)pEmulContext->pModulesInfo->ullLoadbase;
	}
	else
	{
		Peb64.ProcessHeap = NULL;
		Peb64.NumberOfProcessors = 4;
		Peb64.ImageBaseAddress = pEmulContext->pModulesInfo->ullLoadbase;
	}
	
	DWORD dwApiSetSize = 0;
	DWORD dwApiSetAlignSize = 0;
	PVOID pApiSet = pEmulContext->pLoader->GetApiSetData(&dwApiSetSize);
	ULONGLONG ApiSetMap = 0;
	if (pApiSet && dwApiSetSize > 0)
	{
		dwApiSetAlignSize = ALIGN_SIZE_UP(dwApiSetSize, PAGE_SIZE);
		ULONGLONG ApiSetMap = pEmulContext->pmemMgr->WinMemSpaceAlloc(em_MTProcessInfoType, dwApiSetAlignSize);
		if (ApiSetMap)
		{
			bRet = pEmulContext->pvmCpu->VmMapMemory(ApiSetMap, dwApiSetAlignSize, VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true);
			assert(bRet);
			if (!bRet)
			{
				ApiSetMap = NULL;
			}
		}
		if (ApiSetMap)
		{
			bRet = pEmulContext->pvmCpu->VmWriteMemory(ApiSetMap, (const void *)pApiSet, dwApiSetSize);
			assert(bRet);
		}
		free(pApiSet);
	}

	PVOID pVMPebAddr = NULL;
	DWORD dwVMPebSize = 0;
	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		Peb32.ApiSetMap = (ULONG)ApiSetMap;
		pVMPebAddr = (PVOID)&Peb32;
		dwVMPebSize = sizeof(VMPEB32);
	}
	else
	{
		Peb64.ApiSetMap = ApiSetMap;
		pVMPebAddr = (PVOID)&Peb64;
		dwVMPebSize = sizeof(VMPEB64);
	}

	if (!pEmulContext->pvmCpu->VmWriteMemory(ullPebBase, (const void *)pVMPebAddr, dwVMPebSize))
	{
		pEmulContext->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, ullPebBase);
		pEmulContext->pvmCpu->VmUnMapMemory(ullPebBase, dwPebSize);
		if (ApiSetMap)
		{
			pEmulContext->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, ApiSetMap);
			pEmulContext->pvmCpu->VmUnMapMemory(ApiSetMap, dwApiSetAlignSize);
		}
		assert(0);
		return false;
	}

	//teb 和 peb地址
	pEmulContext->ullPebAddress = ullPebBase;

	std::shared_ptr<ThreadInfoItem> MainThread = EmulationCreateThreadTeb(pEmulContext, pEmulContext->ulStartAddress, true);
	if (MainThread == NULL)
	{
		pEmulContext->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, ullPebBase);
		pEmulContext->pvmCpu->VmUnMapMemory(ullPebBase, dwPebSize);
		if (ApiSetMap)
		{
			pEmulContext->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, ApiSetMap);
			pEmulContext->pvmCpu->VmUnMapMemory(ApiSetMap, dwApiSetAlignSize);
		}
		assert(0);
		return false;
	}
	pEmulContext->dwMainThreadID = MainThread->ThreadID;
	pEmulContext->mThreads.insert(std::pair<DWORD, std::shared_ptr<ThreadInfoItem>>(MainThread->ThreadID, MainThread));


	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		//fs
		//gs

		GDT_Descriptor GDT;
		if (!pEmulContext->pvmCpu->VmReadMemory(pEmulContext->ullGdtAddress, &GDT.gdt32[0], sizeof(GDT.gdt32)))
		{
			assert(0);
			return false;
		}
		InitilizeDescriptor32Bit(&GDT.gdt32[GDT_SEGMENTSELECTOR_INDEX_FS], (ULONG)MainThread->ullTebAddress, (ULONG)sizeof(VMTEB32), false, false);
		InitilizeDescriptor32Bit(&GDT.gdt32[GDT_SEGMENTSELECTOR_INDEX_GS], (ULONG)MainThread->ullTebAddress, (ULONG)sizeof(VMTEB32), false, false);
		if (!pEmulContext->pvmCpu->VmWriteMemory(pEmulContext->ullGdtAddress, (const void *)&GDT.gdt32[0], sizeof(GDT.gdt32)))
		{
			assert(0);
			return false;
		}
		SegmentSelector fs = { 0 };
		fs.fields.index = GDT_SEGMENTSELECTOR_INDEX_FS;
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_FS, &fs.all);
		assert(bRet);

		SegmentSelector gs = { 0 };
		gs.fields.index = GDT_SEGMENTSELECTOR_INDEX_GS;
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_GS, &gs.all);
		assert(bRet);
	}
	else
	{
		uc_x86_msr msr = { 0 };
		msr.rid = (ULONG)MSRS::kIa32GsBase;
		msr.value = MainThread->ullTebAddress;
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_MSR, (uc_x86_msr *)&msr);
		assert(bRet);
	}
	return bRet;
}


bool CVmCpuEmulation::InitKernelSharedUserData(EmulationItem * pEmulContext)
{
	ULONGLONG ullShareDataAddr = pEmulContext->pFileinfo->BitType == BIT_TYPE_32 ? KERNEL_SHARE_DATA_USER_BASE_X86 : KERNEL_SHARE_DATA_USER_BASE_X64;
	bool bRet = pEmulContext->pmemMgr->WinAddReserveBlockSpace(pEmulContext->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, 
																ullShareDataAddr, KERNEL_SHARE_DATA_USER_SIZE);
	if (!bRet)
	{
		assert(0);
		return false;
	}
	bRet = pEmulContext->pvmCpu->VmMapMemory(ullShareDataAddr, KERNEL_SHARE_DATA_USER_SIZE, VM_MEM_PROTECT_READ, true);
	if (!bRet)
	{
		assert(0);
		return false;
	}
	return true;
}

bool CVmCpuEmulation::InitlizeVCpuRegister(EmulationItem * pEmulContext)
{
	bool bRet = false;
	if (pEmulContext->pFileinfo->BitType == BIT_TYPE_32)
	{
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_EAX, &pEmulContext->pRegInfo->Regs.a.reg32Bit.Eax);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_EBX, &pEmulContext->pRegInfo->Regs.a.reg32Bit.Ebx);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_ECX, &pEmulContext->pRegInfo->Regs.a.reg32Bit.Ecx);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_EDX, &pEmulContext->pRegInfo->Regs.a.reg32Bit.Edx);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_ESI, &pEmulContext->pRegInfo->Regs.a.reg32Bit.Esi);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_EDI, &pEmulContext->pRegInfo->Regs.a.reg32Bit.Edi);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_EBP, &pEmulContext->pRegInfo->Regs.a.reg32Bit.Ebp);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_ESP, &pEmulContext->pRegInfo->Regs.a.reg32Bit.Esp);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_EIP, &pEmulContext->pRegInfo->Regs.a.reg32Bit.Eip);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_EFLAGS, &pEmulContext->pRegInfo->Regs.a.reg32Bit.EFlags);
		assert(bRet);
	}
	else
	{
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_RAX, &pEmulContext->pRegInfo->Regs.a.reg64Bit.Rax);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_RBX, &pEmulContext->pRegInfo->Regs.a.reg64Bit.Rbx);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_RCX, &pEmulContext->pRegInfo->Regs.a.reg64Bit.Rcx);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_RDX, &pEmulContext->pRegInfo->Regs.a.reg64Bit.Rdx);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_RSI, &pEmulContext->pRegInfo->Regs.a.reg64Bit.Rsi);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_RDI, &pEmulContext->pRegInfo->Regs.a.reg64Bit.Rdi);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_R8, &pEmulContext->pRegInfo->Regs.a.reg64Bit.R8);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_R9, &pEmulContext->pRegInfo->Regs.a.reg64Bit.R9);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_R10, &pEmulContext->pRegInfo->Regs.a.reg64Bit.R10);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_R11, &pEmulContext->pRegInfo->Regs.a.reg64Bit.R11);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_R12, &pEmulContext->pRegInfo->Regs.a.reg64Bit.R12);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_R13, &pEmulContext->pRegInfo->Regs.a.reg64Bit.R13);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_R14, &pEmulContext->pRegInfo->Regs.a.reg64Bit.R14);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_R15, &pEmulContext->pRegInfo->Regs.a.reg64Bit.R15);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_RBP, &pEmulContext->pRegInfo->Regs.a.reg64Bit.Rbp);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_RSP, &pEmulContext->pRegInfo->Regs.a.reg64Bit.Rsp);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_RIP, &pEmulContext->pRegInfo->Regs.a.reg64Bit.Rip);
		assert(bRet);
		bRet = pEmulContext->pvmCpu->VmRegWrite(UC_X86_REG_EFLAGS, &pEmulContext->pRegInfo->Regs.a.reg64Bit.EFlags);
		assert(bRet);
	}
	return bRet;
}


static void MemUnMapedTraceCallback(uc_engine *uc, uc_mem_type type,
	uint64_t address, int size, int64_t value, void *user_data)
{
	EmulationItem *pEItem = (EmulationItem *)user_data;
	ULONGLONG rip = 0;
	if (pEItem->pFileinfo->BitType == BIT_TYPE_32)
	{
		pEItem->pvmCpu->VmRegRead(UC_X86_REG_EIP, &rip);
	}
	else
	{
		pEItem->pvmCpu->VmRegRead(UC_X86_REG_RIP, &rip);
	}

	sLoadModule::sModuleInfo info;
	pEItem->pModulesInfo->GetModuleNameByAddress(rip, info);

	switch (type) {
	case UC_MEM_FETCH_PROT: {
		std::cout << "UC_MEM_FETCH_PROT -> "<< CW2A(info.name.c_str()) << ", Eip: 0x" << std::hex << rip << ", Section: "<<
						info.SectionName << ", Function: "<< CW2A(info.ExportFunctionName.c_str()) <<"\n";
		pEItem->pvmCpu->VmEmulationStop();
		break;
	}
	case UC_MEM_WRITE_PROT: {
		std::cout << "UC_MEM_WRITE_PROT -> " << CW2A(info.name.c_str()) << ", Eip: " << std::hex << rip << ", Section: " <<
						info.SectionName << ", Function: " << CW2A(info.ExportFunctionName.c_str()) << "\n";
		pEItem->pvmCpu->VmEmulationStop();
		break;
	}
	case UC_MEM_FETCH_UNMAPPED: {
		std::cout << "UC_MEM_FETCH_UNMAPPED -> " << CW2A(info.name.c_str()) << ", Eip: " << std::hex << rip << ", Section: " <<
						info.SectionName << ", Function: " << CW2A(info.ExportFunctionName.c_str()) << "\n";
		pEItem->pvmCpu->VmEmulationStop();
		break;
	}
	case UC_MEM_READ_UNMAPPED: {
		std::cout << "UC_MEM_READ_UNMAPPED -> " << CW2A(info.name.c_str()) << ", Eip: " << std::hex << rip << ", Section: " <<
						info.SectionName << ", Function: " << CW2A(info.ExportFunctionName.c_str()) << "\n";
		pEItem->pvmCpu->VmEmulationStop();
		break;
	}
	case UC_MEM_WRITE_UNMAPPED: {
		std::cout << "UC_MEM_WRITE_UNMAPPED -> " << CW2A(info.name.c_str()) << ", Eip: " << std::hex << rip << ", Section: " <<
						info.SectionName << ", Function: " << CW2A(info.ExportFunctionName.c_str()) << "\n";
		pEItem->pvmCpu->VmEmulationStop();
		break;
	}
	}

}

static void MemUnReadWriteTraceCallback(uc_engine *uc, uc_mem_type type,
	uint64_t address, int size, int64_t value, void *user_data)
{
	EmulationItem *pEItem = (EmulationItem *)user_data;
	ULONGLONG rip = 0;
	if (pEItem->pFileinfo->BitType == BIT_TYPE_32)
	{
		pEItem->pvmCpu->VmRegRead(UC_X86_REG_EIP, &rip);
	}
	else
	{
		pEItem->pvmCpu->VmRegRead(UC_X86_REG_RIP, &rip);
	}

	switch (type) {
	case UC_MEM_READ: {

		break;
	}
	case UC_MEM_WRITE: {

		break;
	}
	case UC_MEM_FETCH: {
		break;
	}
	}
}

#define CODE_HEX_TO_STR_BUF_LEN(HEX_LEN) (HEX_LEN * 2 + HEX_LEN + 1)
static int HexToAscii(unsigned char* HexData, int HexDataLen, unsigned char* AsciiData, int buflen, char splitchar)
{
	unsigned char tmp = { 0 };
	unsigned int ascii_index = 0;
	unsigned int splitcount = 0;

	if (buflen < CODE_HEX_TO_STR_BUF_LEN(HexDataLen))
	{
		return -1;
	}

	for (int i = 0; i < HexDataLen; )
	{
		tmp = *(HexData + i);
		if (ascii_index % 2 == 0)
		{
			tmp = tmp >> 4;
		}
		else
		{
			tmp = tmp & 0x0F;
			i++;
		}

		if (tmp >= 0x00 && tmp <= 0x09)
		{
			*(AsciiData + splitcount + ascii_index) = tmp + 0x30;
		}
		else if (tmp >= 0x0a && tmp <= 0x0f)
		{
			*(AsciiData + splitcount + ascii_index) = tmp + 0x57;
		}
		else
		{
			*(AsciiData + splitcount + ascii_index) = tmp;
		}
		ascii_index++;

		if (splitchar != 0 && ascii_index % 2 == 0)
		{
			*(AsciiData + splitcount + ascii_index) = splitchar;
			splitcount++;
		}
	}

	for (unsigned int j = 0; j < (buflen - splitcount - ascii_index - 1); j++)
	{
		*(AsciiData + splitcount + ascii_index + j) = splitchar;
	}

	*(AsciiData + buflen - 1) = 0;

	return 0;
}


static void CodeTraceCallback(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	EmulationItem *pEItem = (EmulationItem *)user_data;
	
	#define CODE_HEX_BUF_LEN 16
	unsigned char codeBuffer[CODE_HEX_BUF_LEN] = { 0 };
	unsigned char codeHex[CODE_HEX_TO_STR_BUF_LEN(CODE_HEX_BUF_LEN) + 1] = { 0 };
	cs_insn insn = { 0 };
	uint64_t virtualBase = address;
	uint8_t *code        = codeBuffer;
	size_t codeSize      = size > CODE_HEX_BUF_LEN ? CODE_HEX_BUF_LEN : size;

	bool bRet = pEItem->pvmCpu->VmReadMemory(address, codeBuffer, (DWORD)codeSize);
	assert(bRet);

	size_t disasmSize = codeSize;
	cs_disasm_iter((csh)pEItem->ullCapstone, (const uint8_t **)&code, &disasmSize, &virtualBase, &insn);

	HexToAscii(codeBuffer, (int)codeSize, codeHex, CODE_HEX_TO_STR_BUF_LEN((size > 12 ? CODE_HEX_BUF_LEN : 12)), ' ');

	sLoadModule::sModuleInfo info;
	pEItem->pModulesInfo->GetModuleNameByAddress(address, info);

	if (pEItem->pFileinfo->BitType == BIT_TYPE_32)
	{
		wprintf(L"%-16s(0x%08x)(%s)-> 0x%08x    %-16s %-16s %-16s\n", info.name.c_str(),
			(ULONG)(address - info.ullLoadbase), info.ExportFunctionName.c_str(), (ULONG)address, CA2W((char *)codeHex).m_szBuffer, CA2W(insn.mnemonic).m_szBuffer, CA2W(insn.op_str).m_szBuffer);
	}
	else
	{
		wprintf(L"%-16s(0x%08x)(%s)-> 0x%016I64x    %-16s %-16s %-16s\n", info.name.c_str(),
			(ULONG)(address - info.ullLoadbase), info.ExportFunctionName.c_str(), address, CA2W((char *)codeHex).m_szBuffer, CA2W(insn.mnemonic).m_szBuffer, CA2W(insn.op_str).m_szBuffer);
	}
	
	if (info.ExportFunctionName.size() > 0)
	{
		vFucntionCallItem FItem;
		FItem.wsModuleName = info.name;
		FItem.wsFunction = info.ExportFunctionName;
		FItem.ullAddress = address;
		pEItem->FucntionCallLog.push_back(FItem);
	}
}

static void IntTraceCallback(uc_engine *uc, int exception, void *user_data)
{
	EmulationItem *pEItem = (EmulationItem *)user_data;

	std::cout << "exception #" << std::hex << exception << "\n";


	if (exception == EXCP01_DB)
	{
		pEItem->LastException = STATUS_SINGLE_STEP;
	}
	else if (exception == EXCP03_INT3)
	{
		pEItem->LastException = STATUS_BREAKPOINT;
	}
	else
	{
		pEItem->LastException = 0;
	}

	pEItem->pvmCpu->VmEmulationStop();
}

bool CVmCpuEmulation::InitlizeHook(EmulationItem * pEmulContext)
{
	DWORD dwType = UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT | UC_HOOK_MEM_WRITE_PROT;
	bool bRet = pEmulContext->pvmCpu->VmCpuHookAdd(&pEmulContext->uMemUnMapedTrace, dwType, MemUnMapedTraceCallback, (PVOID)pEmulContext, 1, 0);
	assert(bRet);

	dwType = UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH;
	bRet = pEmulContext->pvmCpu->VmCpuHookAdd(&pEmulContext->uMemUnReadWriteTrace, dwType, MemUnReadWriteTraceCallback, (PVOID)pEmulContext, 1, 0);
	assert(bRet);

	dwType = UC_HOOK_CODE;
	bRet = pEmulContext->pvmCpu->VmCpuHookAdd(&pEmulContext->uCodeTrace, dwType, CodeTraceCallback, (PVOID)pEmulContext, 1, 0);
	assert(bRet);

	dwType = UC_HOOK_INTR;
	bRet = pEmulContext->pvmCpu->VmCpuHookAdd(&pEmulContext->uIntTrace, dwType, IntTraceCallback, (PVOID)pEmulContext, 1, 0);
	assert(bRet);

	return bRet;
}

bool CVmCpuEmulation::InitlizePramEvnInfo(EmulationItem * pEmulContext, std::wstring &peFilePath, std::wstring &param)
{
	int nCount = 0;
	pEmulContext->Param.push_back(peFilePath);
	if (param != L"")
	{
		LPWSTR *wsParams = CommandLineToArgvW(param.c_str(), &nCount);
		if (wsParams != NULL)
		{
			for (int i = 0; i < nCount; i++)
			{
				pEmulContext->Param.push_back(wsParams[i]);
			}

			LocalFree(wsParams);
		}
	}
	
	//env





	nCount = (int)pEmulContext->Param.size();
	ULONGLONG ulParamBase = pEmulContext->pmemMgr->WinMemSpaceAlloc(em_MTProcessInfoType, PAGE_SIZE);
	if (ulParamBase == 0)
	{
		assert(0);
		return false;
	}
	pEmulContext->vmParamEvnInfo.ullArgcAddr = ulParamBase;
	pEmulContext->vmParamEvnInfo.ullArgvAddr = ulParamBase + 4;
	pEmulContext->pvmCpu->VmMapMemory(ulParamBase, PAGE_SIZE, VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true);
	pEmulContext->pvmCpu->VmWriteMemory(ulParamBase, &nCount, 4);

	BYTE pointSize = pEmulContext->pFileinfo->BitType == BIT_TYPE_32 ? sizeof(DWORD) : sizeof(ULONGLONG);
	ULONGLONG pArgvString = pEmulContext->vmParamEvnInfo.ullArgvAddr + ((nCount + 1) * pointSize);
	ULONGLONG ullArgvAddrTmp = pEmulContext->vmParamEvnInfo.ullArgvAddr;
	for (std::vector<std::wstring>::const_iterator iter = pEmulContext->Param.begin(); iter != pEmulContext->Param.end(); ++iter)
	{
		std::string stmp;
		stmp = CW2A(iter->c_str());
		if (pArgvString + 1 + stmp.length() >= ulParamBase + PAGE_SIZE)
		{
			break;
		}
		pEmulContext->pvmCpu->VmWriteMemory(pArgvString, stmp.c_str(), (DWORD)stmp.length() + 1);
		pEmulContext->pvmCpu->VmWriteMemory(ullArgvAddrTmp, &pArgvString, pointSize);
		ullArgvAddrTmp += pointSize;
		pArgvString += stmp.length() + 1;
	}

	//env
	ULONGLONG ulEnvBase = pEmulContext->pmemMgr->WinMemSpaceAlloc(em_MTProcessInfoType, PAGE_SIZE);
	if (ulEnvBase == 0)
	{
		pEmulContext->pvmCpu->VmUnMapMemory(ulParamBase, PAGE_SIZE);
		pEmulContext->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, ulParamBase);
		assert(0);
		return false;
	}
	pEmulContext->vmParamEvnInfo.ullEnvAddr = ulEnvBase;
	pEmulContext->pvmCpu->VmMapMemory(ulEnvBase, PAGE_SIZE, VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true);

	return true;
}


static void CodeHookerCallback(uc_engine *uc, uint64_t address, uint32_t size, void *pContext)
{
	HookHadle *pHandle = (HookHadle *)pContext;
	((pCodeTraceCallback)pHandle->pCallback)(address, size, (const HookContext *)&pHandle->Context);
	/*
	std::cout << "HookerCallback->" << CW2A(pHandle->Context.HookModuleName.c_str()) << "!" << CW2A(pHandle->Context.HookFunctionName.c_str()) 
		<< "\tCallback: 0x" << std::hex << pHandle->pCallback << "\tFuncAddr: 0x" << std::hex << pHandle->Context.ulFunctionAddr
		<< "\tAddress: 0x" << std::hex << address << "\tSize: " << size << "\n";
	*/
}

bool CVmCpuEmulation::EmulationAddFunctionHook(EmulationItem *pEItem, const WCHAR *wsModuleName, const WCHAR *wsFunctionName, byte FuncCallType, byte bArgCount,
									pCodeTraceCallback pCallBack, PVOID pContext, OUT HookHadle **pRetHooker, DWORD dwHookFlag)
{
	if (dwHookFlag != FUNCTION_NAME_HOOK_FLAG_FILTER &&
		dwHookFlag != FUNCTION_NAME_HOOK_FLAG_HOOK_RETURN)
	{
		return false;
	}
	if (FuncCallType != FUNC_CALL_TYPE_STDCALL && FuncCallType != FUNC_CALL_TYPE_CDECL && FuncCallType != FUNC_CALL_TYPE_FASTCALL)
	{
		return false;
	}

	std::wstring wsMName = wsModuleName;
	std::wstring wsFName = wsFunctionName;
	ULONGLONG ulFunctionAddr = pEItem->pLoader->GetMoudleExportFunctionAddr(pEItem->pModulesInfo, wsMName, wsFName);
	if (ulFunctionAddr == 0)
	{
		return false;
	}

	HookHadle *pRet = new HookHadle();
	pRet->pCallback = (PVOID)pCallBack;
	pRet->Context.pContext = pContext;
	pRet->Context.pEItem = pEItem;
	pRet->Context.HookModuleName = wsMName;
	pRet->Context.HookFunctionName = wsFName;
	pRet->Context.ulFunctionAddr = ulFunctionAddr;
	pRet->dwFlag = dwHookFlag;
	pRet->ArgCount = bArgCount;
	pRet->CallType = FuncCallType;
	pRet->FixByteCount = 0;

	bool bRet = pEItem->pvmCpu->VmCpuHookAdd(&pRet->uc_Hooker, UC_HOOK_CODE, CodeHookerCallback, (PVOID)pRet, ulFunctionAddr, ulFunctionAddr);
	if (!bRet)
	{
		delete pRet;
		return false;
	}

	if (dwHookFlag == FUNCTION_NAME_HOOK_FLAG_HOOK_RETURN)
	{
		//x64
		unsigned char ReturnCode[5] = { 0xc3, 0, 0, 0, 0 };
		pRet->FixByteCount = 1;
		if (pEItem->pFileinfo->BitType == BIT_TYPE_32)
		{
			if (FuncCallType == FUNC_CALL_TYPE_STDCALL && bArgCount > 0)
			{
				pRet->FixByteCount = 3;
				*(unsigned short *)&ReturnCode[1] = bArgCount * 4;
				ReturnCode[0] = 0xc2;
			}
			else if (FuncCallType == FUNC_CALL_TYPE_FASTCALL && bArgCount > 2)
			{
				pRet->FixByteCount = 3;
				*(unsigned short *)&ReturnCode[1] = (bArgCount - 2) * 4;
				ReturnCode[0] = 0xc2;
			}
		}
		bRet = pEItem->pvmCpu->VmReadMemory(ulFunctionAddr, &pRet->FixOrgCode[0], pRet->FixByteCount);
		assert(bRet);
		bRet = pEItem->pvmCpu->VmWriteMemory(ulFunctionAddr, &ReturnCode[0], pRet->FixByteCount);
		assert(bRet);
	}

	*pRetHooker = pRet;
	return true;
}

bool CVmCpuEmulation::EmulationAddAddressHook(EmulationItem * pEItem, ULONGLONG ullHookAddress, pCodeTraceCallback pCallBack, PVOID pContext, OUT HookHadle ** pRetHooker)
{
	HookHadle *pRet = new HookHadle();
	pRet->pCallback = (PVOID)pCallBack;
	pRet->Context.pContext = pContext;
	pRet->Context.pEItem = pEItem;
	pRet->Context.ulFunctionAddr = ullHookAddress;

	bool bRet = pEItem->pvmCpu->VmCpuHookAdd(&pRet->uc_Hooker, UC_HOOK_CODE, CodeHookerCallback, (PVOID)pRet, ullHookAddress, ullHookAddress);
	if (!bRet)
	{
		delete pRet;
		return false;
	}

	*pRetHooker = pRet;
	return true;
}

bool CVmCpuEmulation::EmulationAddExecCodeHook(EmulationItem * pEItem, pCodeTraceCallback pCallBack, PVOID pContext, OUT HookHadle ** pRetHooker)
{
	HookHadle *pRet = new HookHadle();
	pRet->pCallback = (PVOID)pCallBack;
	pRet->Context.pContext = pContext;
	pRet->Context.pEItem = pEItem;
	pRet->Context.ulFunctionAddr = 0;
	bool bRet = pEItem->pvmCpu->VmCpuHookAdd(&pRet->uc_Hooker, UC_HOOK_CODE, CodeHookerCallback, (PVOID)pRet, 1, 0);
	if (!bRet)
	{
		delete pRet;
		return false;
	}
	*pRetHooker = pRet;
	return true;
}

bool CVmCpuEmulation::EmulationDelHook(HookHadle *pRetHooker)
{
	if (pRetHooker && pRetHooker->uc_Hooker && pRetHooker->Context.pEItem)
	{
		pRetHooker->Context.pEItem->pvmCpu->VmCpuHookDel((uc_hook)pRetHooker->uc_Hooker);
		if (pRetHooker->dwFlag == FUNCTION_NAME_HOOK_FLAG_HOOK_RETURN && pRetHooker->FixByteCount > 0)
		{
			bool bRet = pRetHooker->Context.pEItem->pvmCpu->VmWriteMemory(pRetHooker->Context.ulFunctionAddr, 
														&pRetHooker->FixOrgCode[0], pRetHooker->FixByteCount);
			//assert(bRet);
		}
		delete pRetHooker;
		return true;
	}
	return false;
}

std::shared_ptr<ThreadInfoItem> CVmCpuEmulation::EmulationCreateThreadTeb(EmulationItem * pEItem, ULONGLONG ulRunEntry, bool bMainThread)
{
	VMTEB64 Teb64 = { 0 };
	VMTEB32 Teb32 = { 0 };
	PVOID pTebAddr = pEItem->pFileinfo->BitType == BIT_TYPE_32 ? (PVOID)&Teb32 : (PVOID)&Teb64;
	DWORD dwTebSize = pEItem->pFileinfo->BitType == BIT_TYPE_32 ? (DWORD)sizeof(VMTEB32) : (DWORD)sizeof(VMTEB64);
	DWORD dwTebAlignSize = 0;
	bool bRet = false;
	dwTebAlignSize = ALIGN_SIZE_UP(dwTebSize, PAGE_SIZE);

	if (pEItem->ullPebAddress == 0)
	{
		return false;
	}

	std::shared_ptr<ThreadInfoItem> threadInfo = std::make_shared<ThreadInfoItem>();
	if (threadInfo == NULL)
	{
		return NULL;
	}
	threadInfo->ThreadID    = pEItem->AllocThreadID();
	threadInfo->ullRunEntry = ulRunEntry;

	threadInfo->ullTebAddress = pEItem->pmemMgr->WinMemSpaceAlloc(em_MTProcessInfoType, dwTebAlignSize);
	if (threadInfo->ullTebAddress == 0)
	{
		return NULL;
	}

	//init Tls Fls
	threadInfo->ulTlsVmAddr = pEItem->pmemMgr->WinMemSpaceAlloc(pEItem->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, 
																ALIGN_SIZE_UP(sizeof(ULONGLONG) * TLS_FLS_COUNT * 2, PAGE_SIZE));
	if (threadInfo->ulTlsVmAddr == 0)
	{
		pEItem->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, threadInfo->ullTebAddress);
		assert(0);
		return NULL;
	}
	bRet = pEItem->pvmCpu->VmMapMemory(threadInfo->ulTlsVmAddr, ALIGN_SIZE_UP(sizeof(ULONGLONG) * TLS_FLS_COUNT * 2, PAGE_SIZE), VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true);
	if (!bRet)
	{
		pEItem->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, threadInfo->ullTebAddress);
		assert(0);
		return NULL;
	}
	threadInfo->ulFlsVmAddr = (ULONGLONG)((PBYTE)threadInfo->ulTlsVmAddr + (sizeof(ULONGLONG) * TLS_FLS_COUNT));

	if (pEItem->pFileinfo->BitType == BIT_TYPE_32)
	{
		Teb32.NtTib.Self = (ULONG)threadInfo->ullTebAddress;
		Teb32.ProcessEnvironmentBlock   = (ULONG)pEItem->ullPebAddress;
		Teb32.ClientId.UniqueProcess    = (ULONG)pEItem->dwProcessID;
		Teb32.ClientId.UniqueThread     = (ULONG)threadInfo->ThreadID;
		Teb32.ThreadLocalStoragePointer = (ULONG)threadInfo->ulTlsVmAddr;

		if (bMainThread)
		{
			// stack start : pRetItem->ullMainStackBase + pRetItem->dwStackSize - PAGE_SIZE
			// stack end   : pRetItem->ullMainStackBase + PAGE_SIZE
			threadInfo->ullStackBase = pEItem->ullMainStackBase;
			threadInfo->dwStackSize  = pEItem->dwStackSize;
			Teb32.NtTib.StackBase    = (ULONG)(threadInfo->ullStackBase + threadInfo->dwStackSize - PAGE_SIZE);
			Teb32.NtTib.StackLimit   = (ULONG)(threadInfo->ullStackBase + PAGE_SIZE);
			threadInfo->bMainThread  = 1;
		}
		else
		{
			//USERMODE_THREAD_STACK_SIZE
			threadInfo->ullStackBase = pEItem->pmemMgr->WinMemSpaceAlloc(em_StackType, ALIGN_SIZE_UP(USERMODE_THREAD_STACK_SIZE, PAGE_SIZE));
			if (threadInfo->ullStackBase == 0)
			{
				pEItem->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, threadInfo->ullTebAddress);
				pEItem->pmemMgr->WinMemSpaceFree(pEItem->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, threadInfo->ulTlsVmAddr);
				pEItem->pvmCpu->VmUnMapMemory(threadInfo->ulTlsVmAddr, ALIGN_SIZE_UP(sizeof(ULONGLONG) * TLS_FLS_COUNT * 2, PAGE_SIZE));
				assert(0);
				return NULL;
			}
			bRet = pEItem->pvmCpu->VmMapMemory(threadInfo->ullStackBase, ALIGN_SIZE_UP(USERMODE_THREAD_STACK_SIZE, PAGE_SIZE), VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true);
			assert(bRet);
			threadInfo->dwStackSize = USERMODE_THREAD_STACK_SIZE;
			Teb32.NtTib.StackBase   = (ULONG)(threadInfo->ullStackBase + threadInfo->dwStackSize - PAGE_SIZE);
			Teb32.NtTib.StackLimit  = (ULONG)(threadInfo->ullStackBase + PAGE_SIZE);
			threadInfo->bMainThread = 0;
		}
	}
	else
	{
		Teb64.NtTib.Self = threadInfo->ullTebAddress;
		Teb64.ProcessEnvironmentBlock   = pEItem->ullPebAddress;
		Teb64.ClientId.UniqueProcess    = pEItem->dwProcessID;
		Teb64.ClientId.UniqueThread     = threadInfo->ThreadID;
		Teb64.ThreadLocalStoragePointer = threadInfo->ulTlsVmAddr;

		if (bMainThread)
		{
			// stack start : pRetItem->ullMainStackBase + pRetItem->dwStackSize - PAGE_SIZE
			// stack end   : pRetItem->ullMainStackBase + PAGE_SIZE
			threadInfo->ullStackBase = pEItem->ullMainStackBase;
			threadInfo->dwStackSize = pEItem->dwStackSize;
			Teb64.NtTib.StackBase = threadInfo->ullStackBase + threadInfo->dwStackSize - PAGE_SIZE;
			Teb64.NtTib.StackLimit = threadInfo->ullStackBase + PAGE_SIZE;
			threadInfo->bMainThread = 1;
		}
		else
		{
			//USERMODE_THREAD_STACK_X64_SIZE
			threadInfo->ullStackBase = pEItem->pmemMgr->WinMemSpaceAlloc(em_StackType, ALIGN_SIZE_UP(USERMODE_THREAD_STACK_SIZE, PAGE_SIZE));
			if (threadInfo->ullStackBase == 0)
			{
				pEItem->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, threadInfo->ullTebAddress);
				pEItem->pmemMgr->WinMemSpaceFree(pEItem->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, threadInfo->ulTlsVmAddr);
				pEItem->pvmCpu->VmUnMapMemory(threadInfo->ulTlsVmAddr, ALIGN_SIZE_UP(sizeof(ULONGLONG) * TLS_FLS_COUNT * 2, PAGE_SIZE));
				assert(0);
				return NULL;
			}
			bRet = pEItem->pvmCpu->VmMapMemory(threadInfo->ullStackBase, ALIGN_SIZE_UP(USERMODE_THREAD_STACK_SIZE, PAGE_SIZE), VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true);
			assert(bRet);
			threadInfo->dwStackSize = USERMODE_THREAD_STACK_SIZE;
			Teb64.NtTib.StackBase = threadInfo->ullStackBase + threadInfo->dwStackSize - PAGE_SIZE;
			Teb64.NtTib.StackLimit = threadInfo->ullStackBase + PAGE_SIZE;
			threadInfo->bMainThread = 0;
		}
	}

	bRet = pEItem->pvmCpu->VmMapMemory(threadInfo->ullTebAddress, dwTebAlignSize, VM_MEM_PROTECT_READ | VM_MEM_PROTECT_WRITE, true);
	if (!bRet)
	{
		pEItem->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, threadInfo->ullTebAddress);
		pEItem->pmemMgr->WinMemSpaceFree(pEItem->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, threadInfo->ulTlsVmAddr);
		pEItem->pvmCpu->VmUnMapMemory(threadInfo->ulTlsVmAddr, ALIGN_SIZE_UP(sizeof(ULONGLONG) * TLS_FLS_COUNT * 2, PAGE_SIZE));
		if (threadInfo->bMainThread == 0)
		{
			pEItem->pmemMgr->WinMemSpaceFree(em_StackType, threadInfo->ullStackBase);
			pEItem->pvmCpu->VmUnMapMemory(threadInfo->ullStackBase, ALIGN_SIZE_UP(USERMODE_THREAD_STACK_SIZE, PAGE_SIZE));
		}
		assert(bRet);
		return NULL;
	}
	
	if (!pEItem->pvmCpu->VmWriteMemory(threadInfo->ullTebAddress, (const void *)pTebAddr, dwTebSize))
	{
		pEItem->pmemMgr->WinMemSpaceFree(em_MTProcessInfoType, threadInfo->ullTebAddress);
		pEItem->pvmCpu->VmUnMapMemory(threadInfo->ullTebAddress, dwTebAlignSize);
		if (threadInfo->bMainThread == 0)
		{
			pEItem->pmemMgr->WinMemSpaceFree(em_StackType, threadInfo->ullStackBase);
			pEItem->pvmCpu->VmUnMapMemory(threadInfo->ullStackBase, ALIGN_SIZE_UP(USERMODE_THREAD_STACK_SIZE, PAGE_SIZE));
		}

		pEItem->pmemMgr->WinMemSpaceFree(pEItem->pFileinfo->BitType == BIT_TYPE_32 ? em_HeapsType32Bit : em_HeapsType64Bit, threadInfo->ulTlsVmAddr);
		pEItem->pvmCpu->VmUnMapMemory(threadInfo->ulTlsVmAddr, ALIGN_SIZE_UP(sizeof(ULONGLONG) * TLS_FLS_COUNT * 2, PAGE_SIZE));
		assert(0);
		return NULL;
	}
	
	return threadInfo;
}

DWORD CVmCpuEmulation::GetCurrentThreadID(EmulationItem * pEItem)
{
	uc_x86_msr msr = { 0 };
	ULONGLONG gs = 0;
	bool bRet = pEItem->pvmCpu->VmRegRead(UC_X86_REG_GS_BASE, (PVOID)&gs);
	assert(bRet);


	struct _CLIENT_ID_64bit ClientId = {0};
	bRet = pEItem->pvmCpu->VmReadMemory(gs + STRUCT_OFFECT(VMTEB64, ClientId), (PVOID)&ClientId, sizeof(struct _CLIENT_ID_64bit));
	assert(bRet);

	return (DWORD)ClientId.UniqueThread;
}

std::shared_ptr<ThreadInfoItem> CVmCpuEmulation::GetThreadInfo(EmulationItem * pEItem, DWORD dwThreadID)
{
	std::map<DWORD, std::shared_ptr<ThreadInfoItem>>::iterator iter = pEItem->mThreads.find(dwThreadID);
	if (iter == pEItem->mThreads.end())
	{
		return NULL;
	}
	return iter->second;
}

#define ADD_FUNCTION_HOOK(__CONTEXT, __MODULE, __FUNCTION, __CALLTYPE, __ARGCOUNT, __FILTER, __PHOOKER) \
EmulationAddFunctionHook(__CONTEXT, __MODULE, __FUNCTION, __CALLTYPE, __ARGCOUNT,	\
__FILTER, NULL, &__PHOOKER, FUNCTION_NAME_HOOK_FLAG_HOOK_RETURN);\
if (__PHOOKER)\
{\
	m_FuncHookHadle.push_back(__PHOOKER);\
	__PHOOKER = NULL;\
}

bool CVmCpuEmulation::InitlizeFunctionHook(EmulationItem * pEmulContext)
{
	HookHadle *pHooker = NULL;
	ADD_FUNCTION_HOOK(pEmulContext, L"kernel32.dll", L"GetSystemTimeAsFileTime", FUNC_CALL_TYPE_STDCALL, 1, (pCodeTraceCallback)CVmApiHook::EmuGetSystemTimeAsFileTime, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"kernel32.dll", L"QueryPerformanceCounter", FUNC_CALL_TYPE_STDCALL, 1, (pCodeTraceCallback)CVmApiHook::EmuQueryPerformanceCounter, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"kernel32.dll", L"OutputDebugStringW", FUNC_CALL_TYPE_STDCALL, 1, (pCodeTraceCallback)CVmApiHook::EMU_HOOK_FUCNTION_NAME(OutputDebugStringW), pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"kernel32.dll", L"IsProcessorFeaturePresent", FUNC_CALL_TYPE_STDCALL, 1, (pCodeTraceCallback)CVmApiHook::EMU_HOOK_FUCNTION_NAME(IsProcessorFeaturePresent), pHooker);


	ADD_FUNCTION_HOOK(pEmulContext, L"kernel32.dll", L"LoadLibraryA", FUNC_CALL_TYPE_STDCALL, 1, (pCodeTraceCallback)CVmApiHook::EMU_HOOK_FUCNTION_NAME(LoadLibraryA), pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"kernel32.dll", L"LoadLibraryW", FUNC_CALL_TYPE_STDCALL, 1, (pCodeTraceCallback)CVmApiHook::EMU_HOOK_FUCNTION_NAME(LoadLibraryW), pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"kernel32.dll", L"LoadLibraryExA", FUNC_CALL_TYPE_STDCALL, 3, (pCodeTraceCallback)CVmApiHook::EMU_HOOK_FUCNTION_NAME(LoadLibraryExA), pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"kernel32.dll", L"LoadLibraryExW", FUNC_CALL_TYPE_STDCALL, 3, (pCodeTraceCallback)CVmApiHook::EMU_HOOK_FUCNTION_NAME(LoadLibraryExW), pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"kernel32.dll", L"GetProcAddress", FUNC_CALL_TYPE_STDCALL, 3, (pCodeTraceCallback)CVmApiHook::EMU_HOOK_FUCNTION_NAME(GetProcAddress), pHooker);


	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbased.dll", L"_initterm_e", FUNC_CALL_TYPE_CDECL, 2, (pCodeTraceCallback)CVmApiHook::Emu_initterm_e, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbased.dll", L"_initterm", FUNC_CALL_TYPE_CDECL, 2, (pCodeTraceCallback)CVmApiHook::Emu_initterm, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbased.dll", L"_get_initial_narrow_environment", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emu_get_initial_narrow_environment, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbased.dll", L"__p___argc", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emu__p___argc, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbased.dll", L"__p___argv", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emu__p___argv, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbased.dll", L"exit", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emuexit, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbased.dll", L"printf", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emuexit, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbase.dll", L"__stdio_common_vfprintf", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::EMU_HOOK_FUCNTION_NAME(__stdio_common_vfprintf), pHooker);

	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbase.dll", L"_initterm_e", FUNC_CALL_TYPE_CDECL, 2, (pCodeTraceCallback)CVmApiHook::Emu_initterm_e, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbase.dll", L"_initterm", FUNC_CALL_TYPE_CDECL, 2, (pCodeTraceCallback)CVmApiHook::Emu_initterm, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbase.dll", L"_get_initial_narrow_environment", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emu_get_initial_narrow_environment, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbase.dll", L"__p___argc", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emu__p___argc, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbase.dll", L"__p___argv", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emu__p___argv, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbase.dll", L"exit", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emuexit, pHooker);
	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbase.dll", L"printf", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::Emuexit, pHooker);

	ADD_FUNCTION_HOOK(pEmulContext, L"ucrtbase.dll", L"__stdio_common_vfprintf", FUNC_CALL_TYPE_CDECL, 0, (pCodeTraceCallback)CVmApiHook::EMU_HOOK_FUCNTION_NAME(__stdio_common_vfprintf), pHooker);
	

	return true;
}


bool CVmCpuEmulation::UnInitlizeFunctionHook()
{
	for (std::vector<HookHadle *>::iterator iter = m_FuncHookHadle.begin(); iter != m_FuncHookHadle.end(); ++iter)
	{
		EmulationDelHook(*iter);
	}
	return true;
}
