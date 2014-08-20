/*
 *	PowerPC CPU library code for use with UAE
 *	Copyright 2014 Frode Solheim <frode@fs-uae.net>
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

#include "ppc.h"

#define NEED_CPU_H

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

static PowerPCCPU *cpu = NULL;
static CPUPPCState *env = NULL;

static void indirect_writeb (void *opaque, hwaddr addr, uint32_t value)
{
	addr += (uintptr_t) opaque;
	printf("%s: 0x%08x => 0x%08" PRIx32 "\n", __func__, (uint32_t) addr, value);
	uae_ppc_io_mem_write(addr, value, 1);
}

static void indirect_writew (void *opaque, hwaddr addr, uint32_t value)
{
	addr += (uintptr_t) opaque;
	printf("%s: 0x%08x => 0x%08" PRIx32 "\n", __func__, (uint32_t) addr, value);
	uae_ppc_io_mem_write(addr, value, 2);
}

static void indirect_writel (void *opaque, hwaddr addr, uint32_t value)
{
	addr += (uintptr_t) opaque;
	printf("%s: 0x%08x => 0x%08" PRIx32 "\n", __func__, (uint32_t) addr, value);
	uae_ppc_io_mem_write(addr, value, 4);
}

static uint32_t indirect_readb (void *opaque, hwaddr addr)
{
	uint32_t retval = 0;
	addr += (uintptr_t) opaque;
	uae_ppc_io_mem_read(addr, &retval, 1);
	// printf("%s: 0x%08x <= %08" PRIx32 "\n", __func__, (uint32_t) addr, retval);
	return retval;
}

static uint32_t indirect_readw (void *opaque, hwaddr addr)
{
	uint32_t retval = 0;
	addr += (uintptr_t) opaque;
	uae_ppc_io_mem_read(addr, &retval, 2);
	printf("%s: 0x%08x <= %08" PRIx32 "\n", __func__, (uint32_t) addr, retval);
	return retval;
}

static uint32_t indirect_readl (void *opaque, hwaddr addr)
{
	uint32_t retval = 0;
	addr += (uintptr_t) opaque;
	uae_ppc_io_mem_read(addr, &retval, 4);
	printf("%s: 0x%08x <= %08" PRIx32 "\n", __func__, (uint32_t) addr, retval);
	return retval;
}

static const MemoryRegionOps indirect_ops = {
	.old_mmio = {
		.read = { indirect_readb, indirect_readw, indirect_readl, },
		.write = { indirect_writeb, indirect_writew, indirect_writel, },
	},
	.endianness = DEVICE_BIG_ENDIAN,
};

MemoryRegion *ram;
MemoryRegion uae_mem;

static bool initialize(uint32_t pvr)
{
	static bool initialized = false;
	if (initialized) {
		return;
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
	cpu = cpu_ppc_init(cpu_model);
	env = &cpu->env;

	// needed to initialize system_memory variable
	printf("cpu_exec_init_all\n");
	cpu_exec_init_all();

	// set time-base frequency to XX Mhz (??)
	// needed to initialize the translation engine
	cpu_ppc_tb_init(env, 66UL * 1000UL * 1000UL);

	// perhaps needed
	ppc_translate_init();

	hreg_store_msr(env, 1 << MSR_EP, 0);

	return true;
}

bool ppc_cpu_init(uint32_t pvr)
{
	printf("ppc_cpu_init pvr=0x%08x\n", pvr);
	if (!initialize(pvr)) {
		return false;
	}

	if (env->spr[SPR_PVR] != pvr) {
		printf("PVR (0x%08x) does not match requested PVR (0x%08x)\n", env->spr[SPR_PVR], pvr);;
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
	cpu_exit(ENV_GET_CPU(env));
}

void ppc_cpu_atomic_raise_ext_exception(void)
{
	printf("ppc_cpu_atomic_raise_ext_exception\n");
	ppc_set_irq(cpu, PPC_INTERRUPT_EXT, 1);
}

void ppc_cpu_atomic_cancel_ext_exception(void)
{
	printf("ppc_cpu_atomic_cancel_ext_exception\n");
	ppc_set_irq(cpu, PPC_INTERRUPT_EXT, 0);
}

void ppc_cpu_set_pc(int cpu, uint32_t value)
{
	printf("ppc_cpu_set_pc %x (cpu=%d)\n", value, cpu);

	// for now
	//assert(env->nip == 0);

	// set instruction pointer (hack? better way?)
	env->nip = value;
}

void ppc_cpu_run_continuous(void)
{
	printf("ppc_cpu_run_continuous\n");
	cpu_exec(env);
}

void ppc_cpu_run_single(int count)
{
	printf("ppc_cpu_run_single count=%d\n", count);
}

uint64_t ppc_cpu_get_dec(void)
{
	return cpu_ppc_load_decr(env);
}

void ppc_cpu_do_dec(int value)
{
	printf("ppc_cpu_do_dec %d\n", value);
	cpu_ppc_store_decr(env, value);
}
