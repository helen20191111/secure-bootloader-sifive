/* Copyright 2019 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */
/* ----------------------------------- */
/* ----------------------------------- */

OUTPUT_ARCH("riscv")

ENTRY(_enter)

MEMORY
{
	rom (xa!ri) : ORIGIN = 0x00010000, LENGTH = 0x00014000
	ram (wxa!ri) : ORIGIN = 0x80000000, LENGTH = 0x0000a800
	otp (wxi!ra) : ORIGIN = 0x8000a800, LENGTH = 0x00000800
	iflash (wxa!ri) : ORIGIN = 0x8000b000, LENGTH = 0x00004000
	itim (wx!rai) : ORIGIN = 0x8000f000, LENGTH = 0x00001000
	flash (rxai!w) : ORIGIN = 0x30000000, LENGTH = 0x00001000
}

PHDRS
{
	flash PT_LOAD;
	rom PT_LOAD;
	otp PT_LOAD;
	iflash PT_NULL;
	ram_init PT_LOAD;
	itim_init PT_LOAD;
	ram PT_NULL;
	itim PT_NULL;
}

SECTIONS
{
	__stack_size = DEFINED(__stack_size) ? __stack_size : 0x1000;
	PROVIDE(__stack_size = __stack_size);
	__heap_size = DEFINED(__heap_size) ? __heap_size : 0x400;
	PROVIDE(__metal_boot_hart = 0);
	PROVIDE(__metal_chicken_bit = 0);

	__section_protocol_ram_end = (ORIGIN(ram) + LENGTH(ram));
	__fake_otp_size = 0x800;

	.init 		:
	{
		KEEP (*(.text.metal.init.enter))
		KEEP (*(.text.metal.init.*))
		KEEP (*(SORT_NONE(.init)))
		KEEP (*(.text.libgloss.start))
	} >rom AT>rom :rom

	.fini 		:
	{
		KEEP (*(SORT_NONE(.fini)))
	} >rom AT>rom :rom

	.text 		:
	{
		*(.text.unlikely .text.unlikely.*)
		*(.text.startup .text.startup.*)
		*(.text .text.*)
		*(.gnu.linkonce.t.*)
	} >rom AT>rom :rom

	PROVIDE (__etext = .);
	PROVIDE (_etext = .);
	PROVIDE (etext = .);

	.rodata 		:
	{
		*(.rdata)
		*(.rodata .rodata.*)
		*(.gnu.linkonce.r.*)
		. = ALIGN(8);
		*(.srodata.cst16)
		*(.srodata.cst8)
		*(.srodata.cst4)
		*(.srodata.cst2)
		*(.srodata .srodata.*)
	} >rom AT>rom :rom


	. = ALIGN(8);


	.preinit_array 		:
	{
		PROVIDE_HIDDEN (__preinit_array_start = .);
		KEEP (*(.preinit_array))
		PROVIDE_HIDDEN (__preinit_array_end = .);
	} >rom AT>rom :rom


	.init_array 		:
	{
		PROVIDE_HIDDEN (__init_array_start = .);
		KEEP (*(SORT_BY_INIT_PRIORITY(.init_array.*) SORT_BY_INIT_PRIORITY(.ctors.*)))
		KEEP (*(.init_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .ctors))
		PROVIDE_HIDDEN (__init_array_end = .);
		PROVIDE_HIDDEN ( metal_constructors_start = .);
		KEEP (*(SORT_BY_INIT_PRIORITY(.metal.init_array.*)));
		KEEP (*(.metal.init_array));
		PROVIDE_HIDDEN ( metal_constructors_end = .);
	} >rom AT>rom :rom


	.fini_array 		:
	{
		PROVIDE_HIDDEN (__fini_array_start = .);
		KEEP (*(SORT_BY_INIT_PRIORITY(.fini_array.*) SORT_BY_INIT_PRIORITY(.dtors.*)))
		KEEP (*(.fini_array EXCLUDE_FILE (*crtbegin.o *crtbegin?.o *crtend.o *crtend?.o ) .dtors))
		PROVIDE_HIDDEN (__fini_array_end = .);
		PROVIDE_HIDDEN ( metal_destructors_start = .);
		KEEP (*(SORT_BY_INIT_PRIORITY(.metal.fini_array.*)));
		KEEP (*(.metal.fini_array));
		PROVIDE_HIDDEN ( metal_destructors_end = .);
	} >rom AT>rom :rom


	.ctors 		:
	{
		KEEP (*crtbegin.o(.ctors))
		KEEP (*crtbegin?.o(.ctors))
		KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .ctors))
		KEEP (*(SORT(.ctors.*)))
		KEEP (*(.ctors))
		KEEP (*(.metal.ctors metal.ctors.*));
	} >rom AT>rom :rom


	.dtors 		:
	{
		KEEP (*crtbegin.o(.dtors))
		KEEP (*crtbegin?.o(.dtors))
		KEEP (*(EXCLUDE_FILE (*crtend.o *crtend?.o ) .dtors))
		KEEP (*(SORT(.dtors.*)))
		KEEP (*(.dtors))
		KEEP (*(.metal.dtors metal.dtors.*));
	} >rom AT>rom :rom

	.itim : ALIGN(8) {
		*(.itim .itim.*)
	} >itim AT>ram :itim_init

	PROVIDE( metal_segment_itim_source_start = LOADADDR(.itim) );
	PROVIDE( metal_segment_itim_target_start = ADDR(.itim) );
	PROVIDE( metal_segment_itim_target_end = ADDR(.itim) + SIZEOF(.itim) );

	.data : ALIGN(8)
	{
		*(.data)
		__patch_table_storage_start = .;
		*(.data.patch.*)
		__patch_table_storage_end = .;
		*(.data.*)
		*(.gnu.linkonce.d.*)
		. = ALIGN(8);
		PROVIDE( __global_pointer$ = . + 0x800 );
		*(.sdata .sdata.* .sdata2.*)
		*(.gnu.linkonce.s.*)
		. = ALIGN(8);
		*(.srodata.cst16)
		*(.srodata.cst8)
		*(.srodata.cst4)
		*(.srodata.cst2)
		*(.srodata .srodata.*)
		. = ALIGN(8);
		*(.rdata)
		*(.rodata .rodata.*)
		*(.gnu.linkonce.r.*)
	} >ram AT>rom :ram_init

	PROVIDE( metal_segment_data_source_start = LOADADDR(.data) );
	PROVIDE( metal_segment_data_target_start = ADDR(.data) );
	PROVIDE( metal_segment_data_target_end = ADDR(.data) + SIZEOF(.data) );

	.bss 		:
	{
		*(.sbss*)
		*(.gnu.linkonce.sb.*)
		*(.bss .bss.*)
		*(.gnu.linkonce.b.*)
		*(COMMON)
	} >ram AT>ram :ram
	PROVIDE( metal_segment_bss_target_start = ADDR(.bss) );
	PROVIDE( metal_segment_bss_target_end = ADDR(.bss) + SIZEOF(.bss) );

	.stack : ALIGN(0x10)
	{
		PROVIDE(metal_segment_stack_begin = .);
		. = __stack_size;
		PROVIDE( _sp = . );
		PROVIDE(metal_segment_stack_end = .);
	} >ram AT>ram :ram


	.heap :
	{
		PROVIDE( metal_segment_heap_target_start = . );
		. = __heap_size;
		PROVIDE( metal_segment_heap_target_end = . );
		PROVIDE( _heap_end = . );
	} >ram AT>ram :ram

	__sbcm_free_start_addr = .;
	__sbcm_free_end_addr = __section_protocol_ram_end - __fake_otp_size;
	__sbcm_free_size = __sbcm_free_end_addr - __sbcm_free_start_addr;

	.otp.mapping	ORIGIN(otp) :
	{
		__otp_start = . ;
		KEEP(*(*otp*))
		__otp_end = . ;
	} >otp AT>rom :otp

	/**  */
	__otp_size_real = __otp_end - __otp_start;
	__otp_load_start = LOADADDR(.otp.mapping);
	__otp_load_end = __otp_load_start + __otp_size_real;

	.internal_flash ORIGIN(iflash) :
	{
		__iflash_start = .;
		KEEP(*(*iflash*))
		__iflash_end = .;

	} >iflash AT>iflash :iflash
}

