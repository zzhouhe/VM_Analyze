#ifndef _EMU_H
#define _EMU_H
#include "../unicorn-1.0.2-win32/include/unicorn/unicorn.h"
#include "../capstone-4.0.2-win32/include/capstone/capstone.h"

// memory address of the code section
typedef struct _SEG_MAP{
	DWORD			base;
	unsigned int	size;
	char			*file_name;
	unsigned char	*buf;		//contain the file buf
} SEG_MAP;

typedef struct _REGS{
	union{
	struct {
		DWORD r_eax;
		DWORD r_ecx;    
		DWORD r_edx;
		DWORD r_ebx;
		DWORD r_esp;
		DWORD r_ebp;
		DWORD r_esi;
		DWORD r_edi;
		DWORD r_eip;
		DWORD r_efl;
	} regs;
	DWORD u[10];
	};
} REGS;

typedef struct _REG_STATE{
	BYTE	eax_h;
	BYTE	ah;
	BYTE	al;
	BYTE	ecx_h;
	BYTE	ch;
	BYTE	cl;
	BYTE	edx_h;
	BYTE	dh;
	BYTE	dl;
	BYTE	ebx_h;
	BYTE	bh;
	BYTE	bl;
	BYTE	esi_h;
	BYTE	si;
	BYTE	edi_h;
	BYTE	di;
	BYTE	esp_h;
	BYTE	sp;
	BYTE	ebp_h;
	BYTE	bp;
	BYTE	eip;
	BYTE	eflags;
} REG_STATE;

extern void init_gdt(uc_engine *uc);
void taint_addr(DWORD addr);
void taint_reg(x86_reg reg);
void untaint_reg(x86_reg reg);
void untaint_addr(DWORD addr);
bool is_addr_tainted(DWORD addr);
bool is_reg_tainted(x86_reg reg);
bool do_taint(cs_insn* insn);
void print_taint_addr();
void print_taint_reg();
#endif