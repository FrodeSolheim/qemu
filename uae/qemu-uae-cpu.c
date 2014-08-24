/*
 * PowerPC CPU library code for use with UAE
 * Copyright 2014 Frode Solheim <frode@fs-uae.net>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "uae/ppc.h"

#include "hw/hw.h"
#include "hw/timer/m48t59.h"
#include "hw/i386/pc.h"
#include "hw/char/serial.h"
#include "hw/block/fdc.h"
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "hw/isa/isa.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_host.h"
#include "hw/ppc/ppc.h"
#include "hw/boards.h"
#include "qemu/log.h"
#include "hw/ide.h"
#include "hw/loader.h"
#include "hw/timer/mc146818rtc.h"
#include "hw/isa/pc87312.h"
#include "sysemu/blockdev.h"
#include "sysemu/arch_init.h"
#include "sysemu/qtest.h"
#include "exec/address-spaces.h"
#include "elf.h"
#include "cpu-models.h"
#include "helper_regs.h"
#include "qemu/module.h"

PPCAPI uae_ppc_io_mem_read_function g_uae_ppc_io_mem_read;
PPCAPI uae_ppc_io_mem_write_function g_uae_ppc_io_mem_write;
PPCAPI uae_ppc_io_mem_read64_function g_uae_ppc_io_mem_read64;
PPCAPI uae_ppc_io_mem_write64_function g_uae_ppc_io_mem_write64;

static PowerPCCPU *g_cpu = NULL;
static CPUPPCState *g_env = NULL;

static uint64_t indirect_read(void *opaque, hwaddr addr, unsigned size)
{
    addr += (uintptr_t) opaque;
    if (size == 8) {
        uint64_t retval = 0;
        g_uae_ppc_io_mem_read64(addr, &retval);
        return retval;
    }
    else {
        uint32_t retval = 0;
        g_uae_ppc_io_mem_read(addr, &retval, size);
        return retval;
    }
}

static void indirect_write(void *opaque, hwaddr addr, uint64_t data, unsigned size)
{
    addr += (uintptr_t) opaque;
    if (size == 8) {
        g_uae_ppc_io_mem_write64(addr, data);
    }
    else {
        //printf("%s: 0x%08x => 0x%08" PRIx32 "\n", __func__, (uint32_t) addr, value);
        g_uae_ppc_io_mem_write(addr, data, size);
    }
}

static const MemoryRegionOps indirect_ops = {
	.read = indirect_read,
	.write = indirect_write,
	.endianness = DEVICE_BIG_ENDIAN,
	.valid = {
		.min_access_size = 1,
		.max_access_size = 8,
		//.unaligned = true,
	},
	.impl = {
		.min_access_size = 1,
		.max_access_size = 8,
		//.unaligned = true,
	},
};

static bool initialize(uint32_t pvr)
{
	static bool initialized = false;
	if (initialized) {
		return false;
	}
	initialized = true;

	// needed to initialize the class system (and probably other stuff)
	printf("MODULE_INIT_QOM\n");
	module_call_init(MODULE_INIT_QOM);

	// needed to initialize timer lists
	init_clocks();

	// allocate translation buffer (what is a suitable size?)
	tcg_exec_init(1024 * 1024);

	const char *cpu_model = NULL;
	if (pvr == CPU_POWERPC_604E_v24) {
		cpu_model = "604e_v2.4";
	}
	else if (pvr == CPU_POWERPC_603E7v1) {
		cpu_model = "603e7v1";
	}
	else {
		printf("Unknown CPU PVR, initialization failed\n");
		return false;
	}

	printf("Initializing PPC CPU model %s (0x%08x)\n", cpu_model, pvr);
	g_cpu = cpu_ppc_init(cpu_model);
	g_env = &g_cpu->env;

	// needed to initialize system_memory variable
	printf("cpu_exec_init_all\n");
	cpu_exec_init_all();

	// set time-base frequency to XX Mhz (??)
	// needed to initialize the translation engine
	cpu_ppc_tb_init(g_env, 66UL * 1000UL * 1000UL);

	// perhaps needed
	ppc_translate_init();

	hreg_store_msr(g_env, 1 << MSR_EP, 0);

	return true;
}

bool ppc_cpu_init(uint32_t pvr)
{
	printf("ppc_cpu_init pvr=0x%08x\n", pvr);
	if (!initialize(pvr)) {
		return false;
	}

	if (g_env->spr[SPR_PVR] != pvr) {
		printf("PVR (0x%08x) does not match requested PVR (0x%08x)\n", g_env->spr[SPR_PVR], pvr);;
		return false;
	}

	return true;
}

void ppc_cpu_map_memory(uint32_t addr, uint32_t size, void *memory, const char *name)
{
	printf("ppc_cpu_map_memory %08x [size %x] => %p\n", addr, size, memory);
	MemoryRegion* mem = g_new(MemoryRegion, 1);
	if (memory != NULL) {
		memory_region_init_ram_ptr(mem, NULL, name, size, memory);
	}
	else {
		memory_region_init_io(mem, NULL, &indirect_ops, (void *) (uintptr_t) addr, name, size);
	}
	memory_region_add_subregion(get_system_memory(), addr, mem);
}

void ppc_cpu_free(void)
{
	printf("ppc_cpu_free\n");
}

void ppc_cpu_stop(void)
{
	printf("ppc_cpu_stop\n");
	cpu_exit(ENV_GET_CPU(g_env));
}

void ppc_cpu_atomic_raise_ext_exception(void)
{
	printf("ppc_cpu_atomic_raise_ext_exception\n");
	ppc_set_irq(g_cpu, PPC_INTERRUPT_EXT, 1);
}

void ppc_cpu_atomic_cancel_ext_exception(void)
{
	printf("ppc_cpu_atomic_cancel_ext_exception\n");
	ppc_set_irq(g_cpu, PPC_INTERRUPT_EXT, 0);
}

void ppc_cpu_set_pc(int cpu, uint32_t value)
{
	printf("ppc_cpu_set_pc %x (cpu=%d)\n", value, cpu);

	// for now
	//assert(env->nip == 0);

	// set instruction pointer (hack? better way?)
	g_env->nip = value;
}

void ppc_cpu_run_continuous(void)
{
	printf("ppc_cpu_run_continuous\n");
	cpu_exec(g_env);
}

void ppc_cpu_run_single(int count)
{
	printf("ppc_cpu_run_single count=%d\n", count);
}

uint64_t ppc_cpu_get_dec(void)
{
	return cpu_ppc_load_decr(g_env);
}

void ppc_cpu_do_dec(int value)
{
	printf("ppc_cpu_do_dec %d\n", value);
	cpu_ppc_store_decr(g_env, value);
}

/*
 * Just used to debug that the library initialization is run.
 */
static void __attribute__ ((constructor)) qemu_uae_cpu_init(void)
{
        printf(" ----------- qemu_uae_cpu_init ----------- \n");
}
