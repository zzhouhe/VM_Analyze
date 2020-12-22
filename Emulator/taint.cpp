#include <stdio.h>
#include <stdlib.h>
#include <set>


#include "emu.h"
extern REGS regs;

DWORD reg_transfer_table[X86_REG_ENDING]={
	-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1, 0, 5,
	3, 1, 7, 2, 9,
	8,-1,-1, 6, 4,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,
};

REG_STATE		g_reg_state = {0};
std::set<DWORD>	g_tainted_addr_set;
bool		g_taint_handled;
void taint_addr(DWORD addr){
	g_tainted_addr_set.insert(addr);
	g_taint_handled = true;
}
void untaint_addr(DWORD addr){
	int x = g_tainted_addr_set.erase(addr);
}
void print_taint_addr(){
	std::set<DWORD>::iterator it;
	DWORD addr = 0;
	int size = 0;
	for (it = g_tainted_addr_set.begin(); it != g_tainted_addr_set.end(); it ++){
		DWORD the_addr = *it;
		if (the_addr - addr < 4)
		{
			size += 1;
		} else {
			if (addr)
				printf("%p\t%d\n", addr, size+1);
			addr = the_addr;
			size = 0;
		}
	}
		if (addr)
			printf("%p\t%d\n", addr, size+1);
}

void print_taint_reg(){
	if (is_reg_tainted(X86_REG_EAX))
		printf("eax, ");
	if (is_reg_tainted(X86_REG_ECX))
		printf("ecx, ");
	if (is_reg_tainted(X86_REG_EDX))
		printf("edx, ");
	if (is_reg_tainted(X86_REG_EBX))
		printf("ebx, ");
	if (is_reg_tainted(X86_REG_ESP))
		printf("esp, ");
	if (is_reg_tainted(X86_REG_EBP))
		printf("ebp, ");
	if (is_reg_tainted(X86_REG_ESI))
		printf("esi, ");
	if (is_reg_tainted(X86_REG_EDI))
		printf("edi, ");
	printf("\n");
}

bool is_addr_tainted(DWORD addr){
	return g_tainted_addr_set.find(addr) != g_tainted_addr_set.end();
}

void inline taint_reg_ex(x86_reg reg, int type){
	switch (reg){
	case X86_REG_EAX:
		g_reg_state.eax_h = type;
		g_reg_state.ah = type;
		g_reg_state.al = type;
		break;
	case X86_REG_AX:
		g_reg_state.ah = type;
		g_reg_state.al = type;
		break;
	case X86_REG_AH:
		g_reg_state.ah = type;
		break;
	case X86_REG_AL:
		g_reg_state.al = type;
		break;

	case X86_REG_ECX:
		g_reg_state.ecx_h = type;
		g_reg_state.ch = type;
		g_reg_state.cl = type;
		break;
	case X86_REG_CX:
		g_reg_state.ch = type;
		g_reg_state.cl = type;
		break;
	case X86_REG_CH:
		g_reg_state.ch = type;
		break;
	case X86_REG_CL:
		g_reg_state.cl = type;
		break;

	case X86_REG_EDX:
		g_reg_state.edx_h = type;
		g_reg_state.dh = type;
		g_reg_state.dl = type;
		break;
	case X86_REG_DX:
		g_reg_state.dh = type;
		g_reg_state.dl = type;
		break;
	case X86_REG_DH:
		g_reg_state.dh = type;
		break;
	case X86_REG_DL:
		g_reg_state.dl = type;
		break;

	case X86_REG_EBX:
		g_reg_state.ebx_h = type;
		g_reg_state.bh = type;
		g_reg_state.bl = type;
		break;
	case X86_REG_BX:
		g_reg_state.bh = type;
		g_reg_state.bl = type;
		break;
	case X86_REG_BH:
		g_reg_state.ah = type;
		break;
	case X86_REG_BL:
		g_reg_state.bl = type;
		break;

	case X86_REG_ESP:
		g_reg_state.esp_h = type;
		g_reg_state.sp = type;
		break;
	case X86_REG_SP:
		g_reg_state.sp = type;
		break;

	case X86_REG_EBP:
		g_reg_state.ebp_h = type;
		g_reg_state.bp = type;
		break;
	case X86_REG_BP:
		g_reg_state.bp = type;
		break;
	case X86_REG_ESI:
		g_reg_state.esi_h = type;
		g_reg_state.si = type;
		break;
	case X86_REG_SI:
		g_reg_state.si = type;
		break;

	case X86_REG_EDI:
		g_reg_state.edi_h = type;
		g_reg_state.di = type;
		break;
	case X86_REG_DI:
		g_reg_state.di = type;
		break;

	case X86_REG_EIP:
		g_reg_state.eip = type;
		break;
	case X86_REG_EFLAGS:
		g_reg_state.eflags = type;
		break;

	default:
		__asm int 3
	}
	if (type)
		g_taint_handled = true;
}

void taint_reg(x86_reg reg){
	taint_reg_ex(reg, 1);
	g_taint_handled = true;
}
void untaint_reg(x86_reg reg){
	taint_reg_ex(reg, 0);
}
bool is_reg_tainted(x86_reg reg){
	switch (reg){
	case X86_REG_EAX:
		return (g_reg_state.eax_h || g_reg_state.ah || g_reg_state.al);
	case X86_REG_AX:
		return (g_reg_state.ah || g_reg_state.al);
	case X86_REG_AH:
		return g_reg_state.ah;
	case X86_REG_AL:
		return g_reg_state.al;
	case X86_REG_ECX:
		return (g_reg_state.ecx_h || g_reg_state.ch || g_reg_state.cl );
	case X86_REG_CX:
		return (g_reg_state.ch || g_reg_state.cl );
	case X86_REG_CH:
		return g_reg_state.ch;
	case X86_REG_CL:
		return g_reg_state.cl;
	case X86_REG_EDX:
		return (g_reg_state.edx_h || g_reg_state.dh || g_reg_state.dl );
	case X86_REG_DX:
		return (g_reg_state.dh || g_reg_state.dl );
	case X86_REG_DH:
		return g_reg_state.dh;
	case X86_REG_DL:
		return g_reg_state.dl;
	case X86_REG_EBX:
		return (g_reg_state.ebx_h || g_reg_state.bh || g_reg_state.bl );
	case X86_REG_BX:
		return (g_reg_state.bh || g_reg_state.bl );
	case X86_REG_BH:
		return g_reg_state.bh;
	case X86_REG_BL:
		return g_reg_state.bl;
	case X86_REG_ESP:
		return g_reg_state.esp_h || g_reg_state.sp;
	case X86_REG_SP:
		return g_reg_state.sp;
	case X86_REG_EBP:
		return g_reg_state.ebp_h || g_reg_state.bp;
	case X86_REG_BP:
		return g_reg_state.bp;
	case X86_REG_ESI:
		return (g_reg_state.esi_h || g_reg_state.si);
	case X86_REG_SI:
		return g_reg_state.si;
	case X86_REG_EDI:
		return (g_reg_state.edi_h || g_reg_state.di );
	case X86_REG_DI:
		return g_reg_state.di;
	case X86_REG_EIP:
		return g_reg_state.eip;
	case X86_REG_EFLAGS:
		return g_reg_state.eflags;
	default:
		__asm int 3
	}
}
//void taint_mem_ex(x86_op_mem mem, int type){
//	DWORD base = 0;
//	DWORD index = 0;
//
//	if (mem.base != X86_REG_INVALID)
//		base = regs.u[reg_transfer_table[mem.base]];
//	if (mem.index != X86_REG_INVALID)
//		index = regs.u[reg_transfer_table[mem.index]];
//	DWORD addr = base + index*mem.scale + mem.disp;
//	if (type)
//		taint_addr(addr);
//	else
//		untaint_addr(addr);
//}
//void taint_mem(x86_op_mem mem){
//	taint_mem_ex(mem, 1);
//}
//void untaint_mem(x86_op_mem mem){
//	taint_mem_ex(mem, 0);
//}
DWORD get_mem_addr(x86_op_mem mem){
	DWORD base = 0;
	DWORD index = 0;

	if (mem.base != X86_REG_INVALID)
	{
		if (reg_transfer_table[mem.base]==-1)
			__asm int 3
		base = regs.u[reg_transfer_table[mem.base]];
	}
	if (mem.index != X86_REG_INVALID)
	{
		if (reg_transfer_table[mem.index]==-1)
			__asm int 3
		index = regs.u[reg_transfer_table[mem.index]];
	}
	DWORD addr = base + index*mem.scale + mem.disp;
	return addr;
}
inline static void taint_op(cs_x86_op op, int type)
{
	switch (op.type){
	case X86_OP_MEM:
		{
			int size = op.size;
			x86_op_mem mem = op.mem;
			if((mem.base && is_reg_tainted(mem.base)) || (mem.index && is_reg_tainted(mem.index)))
				__asm int 3
			DWORD addr = get_mem_addr(mem);
			if (type)
			{
				for (int i = 0; i<size; i++)
					taint_addr(addr+i);
			}
			else{
				for (int i = 0; i<size; i++)
					untaint_addr(addr+i);
			}
		}
		break;
	case X86_OP_REG:
		{
			x86_reg reg = op.reg;
			taint_reg_ex(reg, type);
		}
		break;
	}

}

inline static bool is_op_tainted(cs_x86_op &op){
	switch(op.type)
	{
	case X86_OP_IMM:
		return false;
	case X86_OP_REG:
		return is_reg_tainted(op.reg);
	case X86_OP_MEM:
		{
			x86_op_mem mem = op.mem;
			DWORD addr = get_mem_addr(mem);
			for (int i=0; i< op.size; i++)
			{
				if (is_addr_tainted(addr + i))
					return true;
			}
			
			if ((mem.base && is_reg_tainted(mem.base)) || (mem.index && is_reg_tainted(mem.index)))
			{
				if ((op.access & CS_AC_WRITE) == 0)
					return true;
				else
				// in this case, this mem is tainted, AND some other mem must be tained ��ʽ!
				__asm int 3
			}
			return false;
		}
		break;
	default:
		__asm int 3
	}
}

inline static void do_taint_sp_push(cs_x86_op &op)
{
	DWORD esp_after = regs.u[reg_transfer_table[X86_REG_ESP]] - 4;

	switch (op.type)
	{
	case X86_OP_MEM:
		{
			DWORD addr = get_mem_addr(op.mem);
			if (is_addr_tainted(addr) || is_addr_tainted(addr+1) || is_addr_tainted(addr+2) || is_addr_tainted(addr+3)){
				for (int i = 0; i<4; i++)
					taint_addr(esp_after + i);
			} else {
				for (int i = 0; i<4; i++)
					untaint_addr(esp_after + i);
			}
		}
		break;

	case X86_OP_REG:
		{
			x86_reg reg = op.reg;
			if (is_reg_tainted(reg)){
				for (int i = 0; i<4; i++)
					taint_addr(esp_after + i);
			} else {
				for (int i = 0; i<4; i++)
					untaint_addr(esp_after + i);
			}
		}
		break;

	case X86_OP_IMM:
		for (int i = 0; i<4; i++)
			untaint_addr(esp_after + i);
		break;

	default:
		__asm int 3
	}
}
inline static void do_taint_sp_pop(cs_x86_op &op)
{
	DWORD esp = regs.u[reg_transfer_table[X86_REG_ESP]];
	bool b = is_addr_tainted(esp) || is_addr_tainted(esp + 1) || is_addr_tainted(esp + 2) || is_addr_tainted(esp + 3);
	switch (op.type)
	{
	case X86_OP_MEM:
		{
			DWORD addr = get_mem_addr(op.mem);
			if(op.mem.base && op.mem.base == X86_REG_ESP)
				addr += 4;	//example: pop [esp]
			if (b){
				for (int i = 0; i < op.size; i++)
					taint_addr(addr + i);
			} else {
				for (int i = 0; i < op.size; i++)
					untaint_addr(addr + i);
			}
		}
		break;

	case X86_OP_REG:
		{
			x86_reg reg = op.reg;
			if (b){
				taint_reg(reg);
			} else {
				untaint_reg(reg);
			}
		}
		break;

	default:
		__asm int 3
	}
}

inline static void do_taint_sp_pushad()
{
	DWORD addr = regs.u[reg_transfer_table[X86_REG_ESP]] - 4;
	if (is_reg_tainted(X86_REG_EAX))
	{
		for (int i = 0; i < 4; i++)
			taint_addr(addr + i);
	} else {
		for (int i = 0; i < 4; i++)
			untaint_addr(addr + i);
	}
	addr -= 4;
	if (is_reg_tainted(X86_REG_ECX))
	{
		for (int i = 0; i < 4; i++)
			taint_addr(addr + i);
	} else {
		for (int i = 0; i < 4; i++)
			untaint_addr(addr + i);
	}
	addr -= 4;
	if (is_reg_tainted(X86_REG_EDX))
	{
		for (int i = 0; i < 4; i++)
			taint_addr(addr + i);
	} else {
		for (int i = 0; i < 4; i++)
			untaint_addr(addr + i);
	}
	addr -= 4;
	if (is_reg_tainted(X86_REG_EBX))
	{
		for (int i = 0; i < 4; i++)
			taint_addr(addr + i);
	} else {
		for (int i = 0; i < 4; i++)
			untaint_addr(addr + i);
	}
	addr -= 4;
	if (is_reg_tainted(X86_REG_ESP))
	{
		for (int i = 0; i < 4; i++)
			taint_addr(addr + i);
	} else {
		for (int i = 0; i < 4; i++)
			untaint_addr(addr + i);
	}
	addr -= 4;
	if (is_reg_tainted(X86_REG_EBP))
	{
		for (int i = 0; i < 4; i++)
			taint_addr(addr + i);
	} else {
		for (int i = 0; i < 4; i++)
			untaint_addr(addr + i);
	}
	addr -= 4;
	if (is_reg_tainted(X86_REG_ESI))
	{
		for (int i = 0; i < 4; i++)
			taint_addr(addr + i);
	} else {
		for (int i = 0; i < 4; i++)
			untaint_addr(addr + i);
	}
	addr -= 4;
	if (is_reg_tainted(X86_REG_EDI))
	{
		for (int i = 0; i < 4; i++)
			taint_addr(addr + i);
	} else {
		for (int i = 0; i < 4; i++)
			untaint_addr(addr + i);
	}
}

inline static void do_taint_sp_popad()
{
	DWORD addr = regs.u[reg_transfer_table[X86_REG_ESP]] + 0x1c;
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
	{
		taint_reg(X86_REG_EAX);
	} else {
		untaint_reg(X86_REG_EAX);
	}
	addr -= 4;
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
	{
		taint_reg(X86_REG_ECX);
	} else {
		untaint_reg(X86_REG_ECX);
	}
	addr -= 4;
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
	{
		taint_reg(X86_REG_EDX);
	} else {
		untaint_reg(X86_REG_EDX);
	}
	addr -= 4;
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
	{
		taint_reg(X86_REG_EBX);
	} else {
		untaint_reg(X86_REG_EBX);
	}
	addr -= 4;
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
	{
		taint_reg(X86_REG_ESP);
	} else {
		untaint_reg(X86_REG_ESP);
	}
	addr -= 4;
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
	{
		taint_reg(X86_REG_EBP);
	} else {
		untaint_reg(X86_REG_EBP);
	}
	addr -= 4;
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
	{
		taint_reg(X86_REG_ESI);
	} else {
		untaint_reg(X86_REG_ESI);
	}
	addr -= 4;
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
	{
		taint_reg(X86_REG_EDI);
	} else {
		untaint_reg(X86_REG_EDI);
	}
}

inline static void do_taint_sp_jmp(cs_insn* insn)
{
	cs_x86_op op = insn->detail->x86.operands[0];
	switch (op.type)
	{
	case X86_OP_MEM:
		{
			DWORD addr = get_mem_addr(op.mem);
			if (is_addr_tainted(addr))
				__asm int 3
		}
		break;

	case X86_OP_REG:
		{
			if (is_reg_tainted(op.reg))
				__asm int 3
		}
		break;

	case X86_OP_IMM:
		break;

	default:
		__asm int 3
	}
	DWORD addr = regs.u[reg_transfer_table[X86_REG_ESP]] - 4;
	for (int i = 0; i < 4; i++)
		untaint_addr(addr+i);
}
inline static void do_taint_sp_ret()
{
	DWORD addr = regs.u[reg_transfer_table[X86_REG_ESP]];
	if (is_addr_tainted(addr))
		__asm int 3
}
inline static void do_taint_sp_pushfd()
{
	DWORD addr = regs.u[reg_transfer_table[X86_REG_ESP]] - 4;
	if (is_reg_tainted(X86_REG_EFLAGS))
	{
		for (int i = 0; i < 4; i++)
			taint_addr(addr + i);
	}
	else
	{
		for (int i = 0; i < 4; i++)
			untaint_addr(addr + i);
	}
}
inline static void do_taint_sp_popfd()
{
	DWORD addr = regs.u[reg_transfer_table[X86_REG_ESP]];
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
		taint_reg(X86_REG_EFLAGS);
	else
		untaint_reg(X86_REG_EFLAGS);
}
inline static void do_taint_sp_leave()
{	//mov esp,ebp
	if (is_reg_tainted(X86_REG_EBP))
		taint_reg(X86_REG_ESP);
	else
		untaint_reg(X86_REG_ESP);
	//pop ebp
	DWORD addr = regs.u[reg_transfer_table[X86_REG_ESP]];
	if (is_addr_tainted(addr) || is_addr_tainted(addr + 1) || is_addr_tainted(addr + 2) || is_addr_tainted(addr + 3))
		taint_reg(X86_REG_EBP);
	else
		untaint_reg(X86_REG_EBP);
}
inline static void do_taint_sp_lea(cs_x86 *x86)
{
	if (x86->op_count != 2)
		__asm int 3
	if (x86->operands[1].type != X86_OP_MEM)
		__asm int 3
	if (x86->operands[0].type != X86_OP_REG)
		__asm int 3
	x86_op_mem mem = x86->operands[1].mem;
	x86_reg reg = x86->operands[0].reg;
	if ((mem.base && is_reg_tainted(mem.base)) || (mem.index && is_reg_tainted(mem.index)))
		taint_reg(reg);
	else
		untaint_reg(reg);
} 
inline static void do_taint_sp_xchg(cs_x86 *x86){
	if (x86->op_count !=2 )
		__asm int 3
	bool op0state = is_op_tainted(x86->operands[0]);
	bool op1state = is_op_tainted(x86->operands[1]);
	if (op0state)
		taint_op(x86->operands[1], 1);
	else 
		taint_op(x86->operands[1], 0);
	if (op1state)
		taint_op(x86->operands[0], 1);
	else 
		taint_op(x86->operands[0], 0);
}
inline static void do_taint_sp_lahf(){
	if (is_reg_tainted(X86_REG_EFLAGS))
		taint_reg(X86_REG_AH);
	else
		untaint_reg(X86_REG_AH);
}
inline static void do_taint_sp_xadd(cs_x86 *x86){
	if (x86->op_count !=2 )
		__asm int 3
	/*if (is_op_tainted(x86->operands[0]) || is_op_tainted(x86->operands[0]))
		__asm int 3*/
	bool op0state = is_op_tainted(x86->operands[0]);
	bool op1state = is_op_tainted(x86->operands[1]);
	if (op0state )
		taint_op(x86->operands[1], 1);
	else 
		taint_op(x86->operands[1], 0);
	if (op1state || op1state)
		taint_op(x86->operands[0], 1);
	else 
		taint_op(x86->operands[0], 0);
}
inline static void do_taint_sp_shrd(cs_x86 *x86){
	if (x86->op_count !=3 )
		__asm int 3
	if (is_op_tainted(x86->operands[0]) || is_op_tainted(x86->operands[0]))
		__asm int 3
}
inline static void do_taint_sp_setcc(cs_x86 *x86){
	if (is_reg_tainted(X86_REG_EFLAGS))
		taint_op(x86->operands[0], 1);
	else
		taint_op(x86->operands[0], 0);
}
inline static void do_taint_sp_cwde(){
	//�� AX ��չΪ EAX
	if (is_reg_tainted(X86_REG_AX))
		taint_reg(X86_REG_EAX);
	else
		untaint_reg(X86_REG_EAX);
}
inline static void do_taint_sp_cwd(){
	//�� AX ��չΪ DX:AX
	if (is_reg_tainted(X86_REG_AX))
		taint_reg(X86_REG_DX);
	else
		untaint_reg(X86_REG_DX);
}
inline static void do_taint_sp_cbw(){
	//�� AL ��չΪ AX
	if (is_reg_tainted(X86_REG_AL))
		taint_reg(X86_REG_AX);
	else
		untaint_reg(X86_REG_AX);
}
inline static void do_taint_sp_cdq(){
	//�� EAX ��չΪ 64 λ�� EDX:EAX
	if (is_reg_tainted(X86_REG_EAX))
		taint_reg(X86_REG_EDX);
	else
		untaint_reg(X86_REG_EDX);
}

bool do_taint(cs_insn* insn){
	g_taint_handled = false;
	cs_x86 x86 = insn->detail->x86;
	if (!strcmp(insn->mnemonic, "push"))
	{//push
		cs_x86_op op = x86.operands[0];
		do_taint_sp_push(op);
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "pushal"))
	{//pushad
		do_taint_sp_pushad();
		//return g_taint_handled;
		return false;
	} else if (!strcmp(insn->mnemonic, "pop"))
	{//pop
		cs_x86_op op = x86.operands[0];
		do_taint_sp_pop(op);
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "popal"))
	{//popad
		do_taint_sp_popad();
		//return g_taint_handled;
		return false;
	} else if (!strcmp(insn->mnemonic, "pushfd"))
	{//pushfd
		do_taint_sp_pushfd();
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "popfd"))
	{//popfd
		do_taint_sp_popfd();
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "ret"))
	{//ret
		do_taint_sp_ret();
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "leave"))
	{//leave
		do_taint_sp_leave();
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "nop"))
	{//nop
		return false;
	} else if (!strcmp(insn->mnemonic, "rdtsc"))
	{//rdtsc
		return false;
	} else if (!strcmp(insn->mnemonic, "lea"))
	{//lea
		do_taint_sp_lea(&x86);
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "lahf"))
	{//lahf
		do_taint_sp_lahf();
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "cwde"))
	{//cwde
		do_taint_sp_cwde();
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "cwd"))
	{//cwd
		do_taint_sp_cwd();
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "cbw"))
	{//cbw
		do_taint_sp_cbw();
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "cdq"))
	{//cdq
		do_taint_sp_cdq();
		return g_taint_handled;
	} else if (//!strcmp(insn->mnemonic, "ror") 
	//	|| !strcmp(insn->mnemonic, "rol")
	//	|| !strcmp(insn->mnemonic, "rcr")
	//	|| !strcmp(insn->mnemonic, "rcl")
		 !strcmp(insn->mnemonic, "xadd"))
	{//xadd
		do_taint_sp_xadd(&x86);
		return g_taint_handled;
	} 
	else if (!strcmp(insn->mnemonic, "xchg"))
	{//xchg
		do_taint_sp_xchg(&x86);
		return g_taint_handled;
	} else if (insn->mnemonic[0]=='s' && insn->mnemonic[1]=='e' && insn->mnemonic[2]=='t'
		&& x86.op_count == 1 && insn->detail->regs_read_count == 1
		&& insn->detail->regs_read[0] == X86_REG_EFLAGS)
	{//setcc=
		do_taint_sp_setcc(&x86);
		return g_taint_handled;
	}else if (!strcmp(insn->mnemonic, "jmp")
		|| !strcmp(insn->mnemonic, "call"))
	{//jmp, call
		do_taint_sp_jmp(insn);
		return g_taint_handled;
	} else if (!strcmp(insn->mnemonic, "clc") 
		|| !strcmp(insn->mnemonic, "cmc")
		|| !strcmp(insn->mnemonic, "stc")
		|| !strcmp(insn->mnemonic, "adc")
		|| strstr(insn->mnemonic, "cmov")
		)
	{//clc, ...
		return false;
	}else {
		if(x86.op_count > 2)
			//__asm int 3
			return false;
		if (!strcmp(insn->mnemonic, "xor")
			&& x86.op_count ==2
			&& x86.operands[0].type == X86_OP_REG
			&& x86.operands[1].type == X86_OP_REG
			&& x86.operands[0].reg == x86.operands[1].reg)
		{
			untaint_reg(x86.operands[0].reg);
			return false;
		}
		//if (insn->detail->regs_read_count > 1)
		for (int i = 0; i < insn->detail->regs_read_count; i++)
		{
			x86_reg reg = (x86_reg)insn->detail->regs_read[i];
			switch (reg)
			{
			case X86_REG_EFLAGS:			//maybe jcc or movcc
				if (is_reg_tainted(X86_REG_EFLAGS))	
				{
					if(x86.op_count > 0 && is_op_tainted(x86.operands[0]))
						//already tainted, no use to stop any more
						break;
					else
						__asm int 3
				}
				break;
			default:
				//类似于 rep scasb 之类的指令, 建议对eip单独处理
				{
					if (!strcmp(insn->mnemonic, "shr")
						|| !strcmp(insn->mnemonic, "shl")
						|| !strcmp(insn->mnemonic, "sar")
						|| !strcmp(insn->mnemonic, "sal")
						|| !strcmp(insn->mnemonic, "ror")
						|| !strcmp(insn->mnemonic, "rol")
						|| !strcmp(insn->mnemonic, "rcr")
						|| !strcmp(insn->mnemonic, "rcl"))
					// 此时第二操作数已经有读属性, 可以交给正常处理流程
					break;
				}
				__asm int 3
			}
		}
		for (int i = 0; i < insn->detail->regs_write_count; i++)
		{
			x86_reg reg = (x86_reg)insn->detail->regs_write[i];
			switch (reg)
			{
			case X86_REG_EFLAGS:			//example: test eax, eax
				switch(x86.op_count)
				{
				case 1:
					if (is_op_tainted(x86.operands[0]))
						taint_reg(X86_REG_EFLAGS);
					else 
						untaint_reg(X86_REG_EFLAGS);
					break;
				case 2:
					if (is_op_tainted(x86.operands[0]) || is_op_tainted(x86.operands[1]))
						taint_reg(X86_REG_EFLAGS);
					else 
						untaint_reg(X86_REG_EFLAGS);
					break;
				default:
					__asm int 3
				}
				break;
			default:
				__asm int 3
			}
		}
		/*
		general hadle
		*/
		switch (x86.op_count)
		{
		case 1://one oprand
			{
				switch (x86.operands[0].access)
				{
				case CS_AC_READ | CS_AC_WRITE:
					//example: inc eax
					switch(x86.operands[0].type) {
					case X86_OP_REG:
						// there is no need to taint this reg again
						break;
					case X86_OP_MEM:
						{// there is no need to check if this addr is tainted
							// only check if mem.base or mem.index is tainted
							x86_op_mem mem = x86.operands[0].mem;
							if ((mem.base && is_reg_tainted(mem.base)) || (mem.index && is_reg_tainted(mem.index)))
								__asm int 3
						}
						break;
					default:
						__asm int 3
					}
					break;
				case CS_AC_READ:
					__asm int 3
					break;
				case CS_AC_WRITE:
					__asm int 3
					break;
				}
			}
			break;
		case 2://two oprands
			{
				if (x86.operands[1].type == X86_OP_IMM)
				{
					/*if (x86.operands[0].access & CS_AC_WRITE)
						taint_op(x86.operands[0], 0);*/
					switch (x86.operands[0].access)
					{
						case CS_AC_READ | CS_AC_WRITE:
							if (is_op_tainted(x86.operands[0]))
								taint_op(x86.operands[0], 1);
							break;
						case CS_AC_WRITE:
							taint_op(x86.operands[0], 0);
							break;
						case CS_AC_READ:
							break;
						default:
							__asm int 3
					}
					break;
				}
				

				switch (x86.operands[1].access)
				{
				case CS_AC_READ | CS_AC_WRITE:
					__asm int 3
					break;
				case CS_AC_READ:
					{//general case
						switch(x86.operands[1].type)
						{
						case X86_OP_IMM:
							//{
							//	if (x86.operands[0].access != CS_AC_WRITE)
							//		__asm int 3
							//	else { // untaint operands[0]
							//		taint_op(x86.operands[0], 0);
							//	}
							//}
							__asm int 3		// this case should already be handled
							break;
						case X86_OP_REG:
							{
								switch (x86.operands[0].access) {
								case CS_AC_WRITE:
									{
										if (is_reg_tainted(x86.operands[1].reg))
											taint_op(x86.operands[0], 1);
										else
											taint_op(x86.operands[0], 0);
									}
									break;
								case CS_AC_READ | CS_AC_WRITE:
									{// read | write, example: add eax, ecx
										if (is_reg_tainted(x86.operands[1].reg))
											taint_op(x86.operands[0], 1);
										else { // op[1] is not tainted, but op[0] is tainted
											switch(x86.operands[0].type) {
											case X86_OP_REG:
												// there is no need to taint this reg again
												break;
											case X86_OP_MEM:
												{// there is no need to check if this addr is tainted
													// only check if mem.base or mem.index is tainted
													x86_op_mem mem = x86.operands[0].mem;
													if ((mem.base && is_reg_tainted(mem.base)) || (mem.index && is_reg_tainted(mem.index)))
														__asm int 3
												}
												break;
											default:
												__asm int 3
											}
										}
									}
									break;
								case CS_AC_READ:
									// only read op[0]
									// for example: test eax, eax
									// no need to handle it here, eflgs shoud be already handled
									break;
								default:
									__asm int 3
								}
							}
							break;
						case X86_OP_MEM:
							{
								switch (x86.operands[0].access) 
								{
								case CS_AC_READ:
									// only read op[0]
									// for example: test eax, eax
									// no need to handle it here, eflgs shoud be already handled
									break;

								case CS_AC_WRITE:
									{
										if (is_op_tainted(x86.operands[1]))
											taint_op(x86.operands[0], 1);
										else
											taint_op(x86.operands[0], 0);
									}
									break;
								case CS_AC_WRITE | CS_AC_READ:
									if (!is_op_tainted(x86.operands[0]))
									{
										if (is_op_tainted(x86.operands[1]))
											taint_op(x86.operands[0], 1);
										else
											taint_op(x86.operands[0], 0);
									} else {
										//op[0] has already been tainted, but taint it again
										//example: add [eax], ecx	if eax is tainted, should taint [eax]
										taint_op(x86.operands[0], 1);
									}
									break;
								}
						
							}
							break;
						}

					}
					break;
				case CS_AC_WRITE:
					__asm int 3
					break;
				}
			}
			break;
		default:// 0 oprand?
			__asm int 3
		}
		return g_taint_handled;
	}
}

