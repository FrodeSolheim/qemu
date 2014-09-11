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
#include "sysemu/cpus.h"

#include "uae/log.h"
#include "uae/ppc.h"
#include "qemu-uae.h"

#ifdef UAE
#error UAE should not be defined here
#endif

/* Increase this when changes are not backwards compatible */
#define QEMU_UAE_VERSION_MAJOR 1

/* Increase this when important changes are made */
#define QEMU_UAE_VERSION_MINOR 2

/* Just increase this when the update is insignificant */
#define QEMU_UAE_VERSION_REVISION 3

#define BUSFREQ 66000000UL
#define TBFREQ 16600000UL
#define MAX_MEMORY_REGIONS 128

static struct {
    CPUPPCState *env;
    PowerPCCPU *cpu;
    bool started;
    bool exit_main_loop;
    bool main_loop_exited;
    int cpu_state;
    QemuThread pause_thread;

} state;

static uint64_t indirect_read(void *opaque, hwaddr addr, unsigned size)
{
    addr += (uintptr_t) opaque;
    if (size == 8) {
        uint64_t retval = 0;
        uae_ppc_io_mem_read64(addr, &retval);
        return retval;
    }
    else {
        uint32_t retval = 0;
        uae_ppc_io_mem_read(addr, &retval, size);
        return retval;
    }
}

static void indirect_write(void *opaque, hwaddr addr, uint64_t data,
                           unsigned size)
{
    addr += (uintptr_t) opaque;
    if (size == 8) {
        uae_ppc_io_mem_write64(addr, data);
    }
    else {
        uae_ppc_io_mem_write(addr, data, size);
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

void ppc_cpu_version(int *major, int *minor, int *revision)
{
    *major = QEMU_UAE_VERSION_MAJOR;
    *minor = QEMU_UAE_VERSION_MINOR;
    *revision = QEMU_UAE_VERSION_REVISION;
}

static void qemu_uae_machine_reset(void *opaque)
{
    PowerPCCPU *cpu = opaque;
    cpu_reset(CPU(cpu));
}

static void configure_accelerator(void)
{
    /* Allocate translation buffer (what is a suitable size?) */
    tcg_exec_init(1024 * 1024);
}

static bool qemu_uae_machine_init(const char *model)
{
    uae_log("QEMU: Initializing PPC CPU model %s\n", model);
    state.cpu = cpu_ppc_init(model);
    state.env = &state.cpu->env;

    /* needed to initialize the translation engine */
    cpu_ppc_tb_init(state.env, TBFREQ);

    qemu_register_reset(qemu_uae_machine_reset, state.cpu);
    return true;
}

static bool initialize(const char *model)
{
    static bool initialized = false;
    if (initialized) {
        return false;
    }
    int major, minor, revision;
    ppc_cpu_version(&major, &minor, &revision);
    uae_log("QEMU: Initialize PPC CPU (QEMU %s + API %d.%d.%d)\n",
            qemu_get_version(), major, minor, revision);
    initialized = true;

    /* Initialize the class system (and probably other stuff) */
    uae_log("QEMU: MODULE_INIT_QOM\n");
    module_call_init(MODULE_INIT_QOM);

    /* Initialize runstate transition structures */
    runstate_init();

#if 1
    /* qemu_init_main_loop -> qemu_signal_init installs signals */
    /* FIXME: could conflict with UAE */
    if (qemu_init_main_loop()) {
        fprintf(stderr, "qemu_init_main_loop failed\n");
        exit(1);
    }
#else
    /* Initialize clocks / timer lists */
    init_clocks();
#endif

    /* Initialize memory map structures, etc */
    cpu_exec_init_all();

    /* Calls tcg_exec_init */
    configure_accelerator();

    /* Initialize conditions and mutex needed by CPU emulation */
    qemu_init_cpu_loop();

    /* Lock qemu_global_mutex */
    qemu_mutex_lock_iothread();

    /* Configure timing method (using clock-based timing) */
    configure_icount(NULL);

    /*  */
    // qemu_add_globals();
    qemu_thread_naming(true);

    /* Create CPU */
    if (!qemu_uae_machine_init(model)) {
        return false;
    }

    /* Doesn't really do anything except in KVM mode */
    cpu_synchronize_all_post_init();

    /* Probably not needed */
    set_numa_modes();

    /* Exception vector base at 0xfff00000, instead of 0x00000000 */
    hreg_store_msr(state.env, 1 << MSR_EP, 0);

    /* Log CPU model identifier */
    uae_log("QEMU: CPU PVR 0x%08x\n", state.env->spr[SPR_PVR]);

    qemu_mutex_unlock_iothread();
    return true;
}

# if 0
bool ppc_cpu_init(uint32_t pvr)
{
    uae_log("QEMU: ppc_cpu_init pvr=0x%08x\n", pvr);
    const char *model = NULL;
    if (pvr == CPU_POWERPC_604E_v24) {
        model = "604e_v2.4";
    } else if (pvr == CPU_POWERPC_603E7v1) {
        model = "603e7v1";
    } else {
        uae_log("QEMU: Unknown CPU PVR, initialization failed\n");
        return false;
    }
    return initialize(model);
}
#endif

bool ppc_cpu_init(const char* model)
{
    const char *qemu_model = model;
    if (strcasecmp(model, "603ev") == 0) {
        qemu_model = "603e7v1";
    } else if (strcasecmp(model, "604e") == 0) {
        qemu_model = "604e_v2.4";
    }
    uae_log("QEMU: ppc_cpu_init_with_model %s => %s\n", model, qemu_model);
    return initialize(qemu_model);
}

void ppc_cpu_map_memory(PPCMemoryRegion *regions, int count)
{
    static MemoryRegion *added_regions[MAX_MEMORY_REGIONS + 1];
    int i;

    uae_log("QEMU: Map memory regions:\n");
    if (count >= MAX_MEMORY_REGIONS) {
        uae_log("QEMU: Too many memory regions!\n");
        return;
    }

    /* Remove all existing memory regions */
    for (i = 0; i < MAX_MEMORY_REGIONS; i++) {
        MemoryRegion *mem = added_regions[i];
        if (mem == NULL) {
            break;
        }
        memory_region_del_subregion(get_system_memory(), mem);
        memory_region_destroy(mem);
    }

    /* Create new memory subregions */
    /*
     * TODO:
     * Support aliased memory regions
     */
    for (i = 0; i < count; i++) {
        MemoryRegion *mem;
        PPCMemoryRegion *r = regions + i;
        uae_log("QEMU: %08x [+%8x]  =>  %p  \"%s\")\n",
                r->start, r->size, r->memory, r->name);
        if (r->memory) {
            mem = g_new(MemoryRegion, 1);
            memory_region_init_ram_ptr(mem, NULL, r->name, r->size, r->memory);
        } else {
            mem = g_new(MemoryRegion, 1);
            memory_region_init_io(
                        mem, NULL, &indirect_ops,
                        (void *) (uintptr_t) r->start, r->name, r->size);
        }
        memory_region_add_subregion(get_system_memory(), r->start, mem);
        added_regions[i] = mem;
    }
    added_regions[count] = NULL;
}

#if 0
void ppc_cpu_free(void)
{
    uae_log("QEMU: ppc_cpu_free (STUB)\n");
}
#endif

void ppc_cpu_atomic_raise_ext_exception(void)
{
    ppc_set_irq(state.cpu, PPC_INTERRUPT_EXT, 1);
}

void ppc_cpu_atomic_cancel_ext_exception(void)
{
    ppc_set_irq(state.cpu, PPC_INTERRUPT_EXT, 0);
}

#if 0
void ppc_cpu_set_pc(int cpu, uint32_t value)
{
    uae_log("QEMU: Set CPU%d program counter to 0x%08x \n", cpu, value);
    // set instruction pointer (hack? better way?)
    state.env->nip = value;
}
#endif

bool qemu_uae_main_loop_should_exit(void)
{
    return state.exit_main_loop;
}

void ppc_cpu_run_continuous(void)
{
    uae_log("QEMU: Running main loop\n");
    qemu_mutex_lock_iothread();

    cpu_enable_ticks();
    runstate_set(RUN_STATE_RUNNING);
    vm_state_notify(1, RUN_STATE_RUNNING);
    resume_all_vcpus();

    state.started = true;

    /* The main loop iteration unlocks and relocks the iothread lock */
    main_loop();
}

#if 0
void ppc_cpu_stop(void)
{
    uae_log("QEMU: Stopping CPU\n");
    ppc_cpu_pause(true);
}
#endif

void PPCCALL ppc_cpu_reset(void)
{
    uae_log("QEMU: Reset CPU\n");
    cpu_reset(ENV_GET_CPU(state.env));
    uae_log("QEMU: NIP = 0x%08x\n", state.env->nip);
}

bool PPCCALL ppc_cpu_check_state(int check_state)
{
    qemu_mutex_lock_iothread();
    bool result = state.cpu_state == check_state;
#if 0
    uae_log("%d vs %d\n", state.cpu_state, check_state);
#endif
    qemu_mutex_unlock_iothread();
    return result;
}

static void *pause_thread(void *arg)
{
    qemu_mutex_lock_iothread();

    /* We cannot safely pause before the emulation has properly started */
    while (!state.started) {
        qemu_mutex_unlock_iothread();
        g_usleep(10 * 1000);
        qemu_mutex_lock_iothread();
    }

    pause_all_vcpus();
    uae_log("QEMU: Paused!\n");
    state.cpu_state = PPC_CPU_STATE_PAUSED;

    qemu_mutex_unlock_iothread();
    return NULL;
}

void PPCCALL ppc_cpu_set_state(int set_state)
{
    if (set_state == PPC_CPU_STATE_PAUSED) {
        uae_log("QEMU: Pausing...\n");
        qemu_thread_create(&state.pause_thread, "QEMU pause", pause_thread,
                           NULL, QEMU_THREAD_DETACHED);
    } else if (set_state == PPC_CPU_STATE_RUNNING) {
        uae_log("QEMU: Resuming...\n");
        qemu_mutex_lock_iothread();
        resume_all_vcpus();
        state.cpu_state = PPC_CPU_STATE_RUNNING;
        uae_log("QEMU: Resumed!\n");
        qemu_mutex_unlock_iothread();
    }
}

/* Storage for callback functions set by UAE */

uae_log_function uae_log = NULL;
uae_ppc_io_mem_read_function uae_ppc_io_mem_read = NULL;
uae_ppc_io_mem_write_function uae_ppc_io_mem_write = NULL;
uae_ppc_io_mem_read64_function uae_ppc_io_mem_read64 = NULL;
uae_ppc_io_mem_write64_function uae_ppc_io_mem_write64 = NULL;
