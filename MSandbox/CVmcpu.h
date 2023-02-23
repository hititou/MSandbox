#pragma once
#include <unicorn/unicorn.h>


#define VM_MEM_PROTECT_NONE  0
#define VM_MEM_PROTECT_READ  1
#define VM_MEM_PROTECT_WRITE 2
#define VM_MEM_PROTECT_EXEC  4
#define VM_MEM_PROTECT_ALL   (VM_MEM_PROTECT_READ | VM_MEM_PROTECT_READ | VM_MEM_PROTECT_READ)


#include <pshpack4.h>
typedef struct _CONTEXT32 {

	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;

	WORD   SegCs;
	WORD   SegDs;
	WORD   SegEs;
	WORD   SegFs;
	WORD   SegGs;
	WORD   SegSs;
	DWORD EFlags;

	DWORD   Eax;
	DWORD   Ecx;
	DWORD   Edx;
	DWORD   Ebx;
	DWORD   Esp;
	DWORD   Ebp;
	DWORD   Esi;
	DWORD   Edi;
	DWORD   Eip;

} CONTEXT32;
#include <poppack.h>

typedef struct DECLSPEC_ALIGN(16) _CONTEXT64 {

	DWORD64 Dr0;
	DWORD64 Dr1;
	DWORD64 Dr2;
	DWORD64 Dr3;
	DWORD64 Dr6;
	DWORD64 Dr7;

	WORD   SegCs;
	WORD   SegDs;
	WORD   SegEs;
	WORD   SegFs;
	WORD   SegGs;
	WORD   SegSs;
	DWORD EFlags;

	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 Rip;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;
	
	DWORD MxCsr;

	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

} CONTEXT64;


typedef struct _RegContext
{
	union
	{
		CONTEXT32 reg32Bit;
		CONTEXT64 reg64Bit;
	}a;

}RegContext, *PRegContext;


struct sVmCpuRegContext
{
	sVmCpuRegContext()
	{
		memset(&Regs, 0, sizeof(RegContext));
	};
	RegContext Regs;
};

class CVmcpu
{
public:
	CVmcpu();
	~CVmcpu();

	bool InitilizeVmCpu(uc_arch arch, uc_mode mode);
	void UnInitilizeVmCpu();

	bool VmMapMemory(ULONGLONG base, DWORD dwSize, ULONG ulProtect, bool bZero);
	bool VmUnMapMemory(ULONGLONG base, DWORD dwSize);
	bool VmReadMemory(ULONGLONG base, void *bytes, DWORD dwSize);
	bool VmWriteMemory(ULONGLONG base, const void *bytes, DWORD dwSize);
	bool VmProtectMemory(ULONGLONG base, DWORD dwSize, ULONG ulProtect);

	bool VmRegRead(int regid, void *value);
	bool VmRegWrite(int regid, const void *value);

	bool VmDumpRegContext(sVmCpuRegContext &RegContext, uc_arch arch);

	bool VmCpuHookAdd(OUT uc_hook *pRetHooker, DWORD dwType, void *callback, void *pContext, ULONGLONG ullBegin, ULONGLONG ullEnd);
	bool VmCpuHookDel(uc_hook pHooker);

	bool VmEmulationStart(ULONGLONG ullBegin, ULONGLONG ullUntil, ULONGLONG Timeout, size_t Count);

	void VmEmulationStop();

	//void VmEmulationClose();


private:

	uc_engine *m_uc;
};

