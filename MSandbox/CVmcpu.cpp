#include "CVmcpu.h"
#include "WinComm.h"
#include <assert.h>


CVmcpu::CVmcpu() : m_uc(NULL)
{
}

CVmcpu::~CVmcpu()
{
	if (m_uc)
	{
		uc_close(m_uc);
		m_uc = NULL;
	}
}

bool CVmcpu::InitilizeVmCpu(uc_arch arch, uc_mode mode)
{
	if (m_uc == NULL)
	{
		uc_err err = uc_open(arch, mode, &m_uc);
		if (err != UC_ERR_OK)
		{
			m_uc = NULL;
			return false;
		}
		assert(m_uc);
		return true;
	}
	return true;
}

void CVmcpu::UnInitilizeVmCpu()
{
	if (m_uc)
	{
		uc_close(m_uc);
		m_uc = NULL;
	}
}

bool CVmcpu::VmMapMemory(ULONGLONG base, DWORD dwSize, ULONG ulProtect, bool bZero)
{
	if (m_uc == NULL)
	{
		return false;
	}
	if ((base & ~(ULONGLONG)(PAGE_SIZE - 1)) != base ||
		(dwSize & ~(DWORD)(PAGE_SIZE - 1)) != dwSize)
	{
		return false;
	}
	uc_err uRet = uc_mem_map(m_uc, base, dwSize, ulProtect);
	if (uRet != UC_ERR_OK)
	{
		return false;
	}

	BYTE ZeroBuf[PAGE_SIZE] = { 0 };
	if (bZero)
	{
		for (DWORD i = 0; i < (dwSize / PAGE_SIZE); i++)
		{
			uRet = uc_mem_write(m_uc, base + (i * PAGE_SIZE), ZeroBuf, PAGE_SIZE);
			assert(uRet == UC_ERR_OK);
		}
	}
	return true;
}


bool CVmcpu::VmUnMapMemory(ULONGLONG base, DWORD dwSize)
{
	if (m_uc == NULL)
	{
		return false;
	}
	if ((base & ~(ULONGLONG)(PAGE_SIZE - 1)) != base ||
		(dwSize & ~(DWORD)(PAGE_SIZE - 1)) != dwSize)
	{
		return false;
	}
	uc_err uRet = uc_mem_unmap(m_uc, base, dwSize);
	if (uRet != UC_ERR_OK)
	{
		return false;
	}
	return true;
}


bool CVmcpu::VmReadMemory(ULONGLONG base, void *bytes, DWORD dwSize)
{
	if (m_uc == NULL)
	{
		return false;
	}
	uc_err uRet = uc_mem_read(m_uc, base, bytes, dwSize);
	if (uRet != UC_ERR_OK)
	{
		return false;
	}
	return true;
}


bool CVmcpu::VmWriteMemory(ULONGLONG base, const void *bytes, DWORD dwSize)
{
	if (m_uc == NULL)
	{
		return false;
	}
	uc_err uRet = uc_mem_write(m_uc, base, bytes, dwSize);
	if (uRet != UC_ERR_OK)
	{
		return false;
	}
	return true;
}


bool CVmcpu::VmProtectMemory(ULONGLONG base, DWORD dwSize, ULONG ulProtect)
{
	if (m_uc == NULL)
	{
		return false;
	}
	uc_err uRet = uc_mem_protect(m_uc, base, dwSize, ulProtect);
	if (uRet != UC_ERR_OK)
	{
		return false;
	}
	return true;
}

bool CVmcpu::VmRegRead(int regid, void *value)
{
	if (m_uc == NULL)
	{
		return false;
	}
	uc_err uRet = uc_reg_read(m_uc, regid, value);
	if (uRet != UC_ERR_OK)
	{
		return false;
	}
	return true;
}

bool CVmcpu::VmRegWrite(int regid, const void *value)
{
	if (m_uc == NULL)
	{
		return false;
	}
	uc_err uRet = uc_reg_write(m_uc, regid, value);
	if (uRet != UC_ERR_OK)
	{
		return false;
	}
	return true;
}


bool CVmcpu::VmDumpRegContext(sVmCpuRegContext &RegContext, uc_arch arch)
{
	if (m_uc == NULL)
	{
		return false;
	}
	/*
	uc_reg_read(m_uc, UC_X86_REG_CS, &RegContext.RegInfo.SegCs);
	uc_reg_read(m_uc, UC_X86_REG_DS, &RegContext.RegInfo.SegDs);
	uc_reg_read(m_uc, UC_X86_REG_ES, &RegContext.RegInfo.SegEs);
	uc_reg_read(m_uc, UC_X86_REG_FS, &RegContext.RegInfo.SegFs);
	uc_reg_read(m_uc, UC_X86_REG_GS, &RegContext.RegInfo.SegGs);
	uc_reg_read(m_uc, UC_X86_REG_EFLAGS, &RegContext.RegInfo.EFlags);
	uc_reg_read(m_uc, UC_X86_REG_DR0, &RegContext.RegInfo.Dr0);
	uc_reg_read(m_uc, UC_X86_REG_DR1, &RegContext.RegInfo.Dr1);
	uc_reg_read(m_uc, UC_X86_REG_DR2, &RegContext.RegInfo.Dr2);
	uc_reg_read(m_uc, UC_X86_REG_DR3, &RegContext.RegInfo.Dr3);
	uc_reg_read(m_uc, UC_X86_REG_DR6, &RegContext.RegInfo.Dr6);
	uc_reg_read(m_uc, UC_X86_REG_DR7, &RegContext.RegInfo.Dr7);
	uc_reg_read(m_uc, UC_X86_REG_RAX, &RegContext.RegInfo.Rax);
	uc_reg_read(m_uc, UC_X86_REG_RCX, &RegContext.RegInfo.Rcx);
	uc_reg_read(m_uc, UC_X86_REG_RDX, &RegContext.RegInfo.Rdx);
	uc_reg_read(m_uc, UC_X86_REG_RBX, &RegContext.RegInfo.Rbx);
	uc_reg_read(m_uc, UC_X86_REG_RSP, &RegContext.RegInfo.Rsp);
	uc_reg_read(m_uc, UC_X86_REG_RBP, &RegContext.RegInfo.Rbp);
	uc_reg_read(m_uc, UC_X86_REG_RSI, &RegContext.RegInfo.Rsi);
	uc_reg_read(m_uc, UC_X86_REG_RDI, &RegContext.RegInfo.Rdi);
	uc_reg_read(m_uc, UC_X86_REG_R8, &RegContext.RegInfo.R8);
	uc_reg_read(m_uc, UC_X86_REG_R9, &RegContext.RegInfo.R9);
	uc_reg_read(m_uc, UC_X86_REG_R10, &RegContext.RegInfo.R10);
	uc_reg_read(m_uc, UC_X86_REG_R11, &RegContext.RegInfo.R11);
	uc_reg_read(m_uc, UC_X86_REG_R12, &RegContext.RegInfo.R12);
	uc_reg_read(m_uc, UC_X86_REG_R13, &RegContext.RegInfo.R13);
	uc_reg_read(m_uc, UC_X86_REG_R14, &RegContext.RegInfo.R14);
	uc_reg_read(m_uc, UC_X86_REG_R15, &RegContext.RegInfo.R15);
	uc_reg_read(m_uc, UC_X86_REG_RIP, &RegContext.Rip);
	*/
	return true;
}

bool CVmcpu::VmCpuHookAdd(OUT uc_hook* pRetHooker, DWORD dwType, void * callback, void * pContext, ULONGLONG ullBegin, ULONGLONG ullEnd)
{
	if (m_uc == NULL)
	{
		return false;
	}
	if (uc_hook_add(m_uc, pRetHooker, dwType, callback, pContext, ullBegin, ullEnd) != UC_ERR_OK)
	{
		return false;
	}
	return true;
}

bool CVmcpu::VmCpuHookDel(uc_hook pHooker)
{
	if (m_uc == NULL)
	{
		return false;
	}
	if (uc_hook_del(m_uc, pHooker) != UC_ERR_OK)
	{
		return false;
	}
	return true;
}

bool CVmcpu::VmEmulationStart(ULONGLONG ullBegin, ULONGLONG ullUntil, ULONGLONG Timeout, size_t Count)
{
	if (m_uc == NULL)
	{
		return false;
	}
	if (uc_emu_start(m_uc, ullBegin, ullUntil, Timeout, Count) != UC_ERR_OK)
	{
		return false;
	}
	return true;
}

void CVmcpu::VmEmulationStop()
{
	if (m_uc)
	{
		uc_emu_stop(m_uc);
		m_uc = NULL;
	}
}