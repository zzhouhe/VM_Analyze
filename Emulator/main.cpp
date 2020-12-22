#include <stdio.h>
#include <stdlib.h>

#include "emu.h"
#pragma comment(lib, "../unicorn-1.0.2-win32/unicorn.lib")
#pragma comment(lib, "../capstone-4.0.2-win32/capstone_dll.lib")
SEG_MAP segs[] = {
	//base			size			file name
	{0x00404000,	0x8c000,		"sample.vmp_00404000.bin",				NULL},
	{0x0019B000,	0x5000,			"sample.vmp_0019B000.bin",				NULL},
	{0x00403000,	0x1000,			"sample.vmp_00403000.bin",				NULL},

};


#define INIT_EAX			0x00000001
#define INIT_EBX			0x00000000
#define INIT_ECX			0x75105AA0
#define INIT_EDX			0x751545D0
#define INIT_EBP			0x0019FF70
#define INIT_ESP			0x0019FF20
#define INIT_ESI			0x75105584
#define INIT_EDI			0x75105AD4
#define INIT_EIP			0x00424596
#define INIT_EFL			0x00000206

uc_engine *uc;

REGS regs;


void print_stack(DWORD esp)
{
	DWORD val;
	for(int i = 0; i<10; i++)
	{
		uc_mem_read(uc, esp, &val, 4);
		printf("|%p|\n", val);
		esp+=4;
	}
}



void read_regs()
{
	uc_reg_read(uc, UC_X86_REG_EAX,    &regs.regs.r_eax);
	uc_reg_read(uc, UC_X86_REG_ECX,    &regs.regs.r_ecx);
	uc_reg_read(uc, UC_X86_REG_EDX,    &regs.regs.r_edx);
	uc_reg_read(uc, UC_X86_REG_EBX,    &regs.regs.r_ebx);
	uc_reg_read(uc, UC_X86_REG_ESP,    &regs.regs.r_esp);
	uc_reg_read(uc, UC_X86_REG_EBP,    &regs.regs.r_ebp);
	uc_reg_read(uc, UC_X86_REG_ESI,    &regs.regs.r_esi);
	uc_reg_read(uc, UC_X86_REG_EDI,    &regs.regs.r_edi);
	uc_reg_read(uc, UC_X86_REG_EIP,    &regs.regs.r_eip);
	uc_reg_read(uc, UC_X86_REG_EFLAGS, &regs.regs.r_efl);
}
void write_regs(){
	uc_reg_write(uc, UC_X86_REG_EAX,    &regs.regs.r_eax);
	uc_reg_write(uc, UC_X86_REG_ECX,    &regs.regs.r_ecx);
	uc_reg_write(uc, UC_X86_REG_EDX,    &regs.regs.r_edx);
	uc_reg_write(uc, UC_X86_REG_EBX,    &regs.regs.r_ebx);
	uc_reg_write(uc, UC_X86_REG_ESP,    &regs.regs.r_esp);
	uc_reg_write(uc, UC_X86_REG_EBP,    &regs.regs.r_ebp);
	uc_reg_write(uc, UC_X86_REG_ESI,    &regs.regs.r_esi);
	uc_reg_write(uc, UC_X86_REG_EDI,    &regs.regs.r_edi);
	uc_reg_write(uc, UC_X86_REG_EIP,    &regs.regs.r_eip);
	uc_reg_write(uc, UC_X86_REG_EFLAGS, &regs.regs.r_efl);
}
void print_regs(){
	printf("eax = %p\n", regs.regs.r_eax);
	printf("ebx = %p\n", regs.regs.r_ebx);
	printf("ecx = %p\n", regs.regs.r_ecx);
	printf("edx = %p\n", regs.regs.r_edx);
	printf("ebp = %p\n", regs.regs.r_ebp);
	printf("esp = %p\n", regs.regs.r_esp);
	printf("esi = %p\n", regs.regs.r_esi);
	printf("edi = %p\n", regs.regs.r_edi);
	printf("eip = %p\n", regs.regs.r_eip);
	printf("efl = %p\n", regs.regs.r_efl);
}


int main(int argc, char **argv, char **envp)
{
	regs.regs.r_eax = INIT_EAX;
	regs.regs.r_ecx = INIT_ECX;			 
	regs.regs.r_edx = INIT_EDX;     
	regs.regs.r_ebx = INIT_EBX;
	regs.regs.r_esp = INIT_ESP;
	regs.regs.r_ebp = INIT_EBP;
	regs.regs.r_esi = INIT_ESI;
	regs.regs.r_edi = INIT_EDI;
	regs.regs.r_eip = INIT_EIP;
	regs.regs.r_efl = INIT_EFL;

	uc_err err;
	csh handle;
	cs_insn* insn;

	printf("Emulate i386 code\n");

	// Initialize emulator in X86-32bit mode
	err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
	if (err != UC_ERR_OK) {
		printf("Failed on uc_open() with error returned: %u\n", err);
		return -1;
	}

	for(int i = 0; i < sizeof(segs)/sizeof(SEG_MAP); i++) {
		segs[i].buf = (unsigned char *)malloc(segs[i].size);
		FILE *fp = fopen(segs[i].file_name, "rb");
		fread(segs[i].buf, segs[i].size, 1, fp);
		fclose(fp);
		// map memory for this emulation
		err = uc_mem_map(uc, segs[i].base, segs[i].size, UC_PROT_ALL);
		// write machine code to be emulated to memory
		err = uc_mem_write(uc, segs[i].base, segs[i].buf, segs[i].size);
		free(segs[i].buf);
	} 

	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle)) {
		printf("ERROR: Failed to initialize engine!\n");
		return -1;
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	write_regs();
	init_gdt(uc);

	BYTE code[32];
	int count = 0;
	// emulate code in infinite time & unlimited instructions
	while (1){
		count++;
		uc_mem_read(uc, regs.regs.r_eip, code, 32);
		cs_disasm(handle, code, 32, regs.regs.r_eip, 1, &insn);

		switch (regs.regs.r_eip)
		{

		case 0:
			goto DEFAULT;
DEFAULT:
		default:
			{	/*DWORD val; 
				uc_mem_read(uc, 0x12f468, &val, 4);*/
				if ( /*is_reg_tainted(X86_REG_EBP)*/
					//regs.regs.r_ebp == INIT_EBP
					//&& !strcmp(insn->mnemonic, "ret")
					//&& is_reg_tainted(X86_REG_EDI)
					//is_addr_tainted(0x662dc3)
					//0
					//count == 4118
					0)
				{
					print_regs();
					//print_taint_reg();
					//print_taint_addr();
					print_stack(regs.regs.r_esp);
				}
				//if (do_taint(insn))
				//{
				//	//printf("%p\t%s %s\n", regs.regs.r_eip, insn->mnemonic, insn->op_str);
				//	//print_taint_reg();
				//}
			}
		}

		err=uc_emu_start(uc, regs.regs.r_eip, 0xffffffff, 0, 1);
		if (err) {
			printf("Exception with error returned %u: %s\n",
				err, uc_strerror(err));
			print_regs();
			print_stack(regs.regs.r_esp);
			__asm int 3
			break;
		}
		read_regs();
		
		cs_free(insn, 1);

	}
	printf("count = %d\n", count);

	cs_close(&handle);
	uc_close(uc);

	system("pause");
	return 0;
}