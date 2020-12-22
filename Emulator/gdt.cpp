#include "../unicorn-1.0.2-win32/include/unicorn/unicorn.h"

#pragma pack(push, 1)
struct SegmentDescriptor {
	union {
		struct {   
#if __BYTE_ORDER == __LITTLE_ENDIAN
			unsigned short limit0;
			unsigned short base0;
			unsigned char base1;
			unsigned char type:4;
			unsigned char system:1;      /* S flag */
			unsigned char dpl:2;
			unsigned char present:1;     /* P flag */
			unsigned char limit1:4;
			unsigned char avail:1;
			unsigned char is_64_code:1;  /* L flag */
			unsigned char db:1;          /* DB flag */
			unsigned char granularity:1; /* G flag */
			unsigned char base2;
#else
			unsigned char base2;
			unsigned char granularity:1; /* G flag */
			unsigned char db:1;          /* DB flag */
			unsigned char is_64_code:1;  /* L flag */
			unsigned char avail:1;
			unsigned char limit1:4;
			unsigned char present:1;     /* P flag */
			unsigned char dpl:2;
			unsigned char system:1;      /* S flag */
			unsigned char type:4;
			unsigned char base1;
			unsigned short base0;
			unsigned short limit0;
#endif
		};
		uint64_t desc;
	};
};
#pragma pack(pop)

#define SEGBASE(d) ((uint32_t)((((d).desc >> 16) & 0xffffff) | (((d).desc >> 32) & 0xff000000)))
#define SEGLIMIT(d) ((d).limit0 | (((unsigned int)(d).limit1) << 16))

/**
* Assert that err matches expect
*/
#define uc_assert_err(expect, err)                                  \
	do {                                                                \
	uc_err __err = err;                                             \
	if (__err != expect) {                                          \
	fprintf(stderr, "%s", uc_strerror(__err));                  \
	exit(1);                                                    \
	}                                                               \
	} while (0)

/**
* Assert that err is UC_ERR_OK
*/
#define uc_assert_success(err)  uc_assert_err(UC_ERR_OK, err)

/**
* Assert that err is anything but UC_ERR_OK
*
* Note: Better to use uc_assert_err(<specific error>, err),
* as this serves to document which errors a function will return
* in various scenarios.
*/
#define uc_assert_fail(err)                                         \
	do {                                                                \
	uc_err __err = err;                                             \
	if (__err == UC_ERR_OK) {                                       \
	fprintf(stderr, "%s", uc_strerror(__err));                  \
	exit(1);                                                    \
	}                                                               \
	} while (0)

#define OK(x)   uc_assert_success(x)

/******************************************************************************/


//VERY basic descriptor init function, sets many fields to user space sane defaults
static void init_descriptor(struct SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
	desc->desc = 0;  //clear the descriptor
	desc->base0 = base & 0xffff;
	desc->base1 = (base >> 16) & 0xff;
	desc->base2 = base >> 24;
	if (limit > 0xfffff) {
		//need Giant granularity
		limit >>= 12;
		desc->granularity = 1;
	}
	desc->limit0 = limit & 0xffff;
	desc->limit1 = limit >> 16;

	//some sane defaults
	desc->dpl = 3;
	desc->present = 1;
	desc->db = 1;   //32 bit
	desc->type = is_code ? 0xb : 3;
	desc->system = 1;  //code or data
}

void init_gdt(uc_engine *uc)
{
	uc_hook hook1, hook2;
	uc_err err;
	uint8_t buf[128];
	uc_x86_mmr gdtr;
	int i;

	const uint64_t gdt_address = 0xc0000000;

	struct SegmentDescriptor *gdt = (struct SegmentDescriptor*)calloc(31, sizeof(struct SegmentDescriptor));

	int r_cs = 0x73;
	int r_ss = 0x88;      //ring 0
	int r_ds = 0x7b;
	int r_es = 0x7b;
	int r_fs = 0x83;

	gdtr.base = gdt_address;  
	gdtr.limit = 31 * sizeof(struct SegmentDescriptor) - 1;

	init_descriptor(&gdt[14], 0, 0xfffff000, 1);  //code segment
	init_descriptor(&gdt[15], 0, 0xfffff000, 0);  //data segment
	init_descriptor(&gdt[16], 0x7FFDF000, 0xfff, 0);  //one page data segment simulate fs
	init_descriptor(&gdt[17], 0, 0xfffff000, 0);  //ring 0 data
	gdt[17].dpl = 0;  //set descriptor privilege level

	// map 64k for a GDT
	err = uc_mem_map(uc, gdt_address, 0x10000, UC_PROT_WRITE | UC_PROT_READ);
	uc_assert_success(err);

	//set up a GDT BEFORE you manipulate any segment registers
	err = uc_reg_write(uc, UC_X86_REG_GDTR, &gdtr);
	uc_assert_success(err);

	// write gdt to be emulated to memory
	err = uc_mem_write(uc, gdt_address, gdt, 31 * sizeof(struct SegmentDescriptor));
	uc_assert_success(err);



	// when setting SS, need rpl == cpl && dpl == cpl
	// emulator starts with cpl == 0, so we need a dpl 0 descriptor and rpl 0 selector
	err = uc_reg_write(uc, UC_X86_REG_SS, &r_ss);
	uc_assert_success(err);

	err = uc_reg_write(uc, UC_X86_REG_CS, &r_cs);
	uc_assert_success(err);
	err = uc_reg_write(uc, UC_X86_REG_DS, &r_ds);
	uc_assert_success(err);
	err = uc_reg_write(uc, UC_X86_REG_ES, &r_es);
	uc_assert_success(err);
	err = uc_reg_write(uc, UC_X86_REG_FS, &r_fs);
	uc_assert_success(err);

}
