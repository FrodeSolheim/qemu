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

//PPCAPI uae_ppc_io_mem_read_function g_uae_ppc_io_mem_read;
//PPCAPI uae_ppc_io_mem_write_function g_uae_ppc_io_mem_write;
//PPCAPI uae_ppc_io_mem_read64_function g_uae_ppc_io_mem_read64;
//PPCAPI uae_ppc_io_mem_write64_function g_uae_ppc_io_mem_write64;

#define BUSFREQ 66000000UL
#define TBFREQ 16600000UL

static struct {
    volatile int pause;
    CPUPPCState *env;
    PowerPCCPU *cpu;
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
    uae_log("PPC: Initializing CPU model %s\n", model);
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
    initialized = true;

    /* Initialize the class system (and probably other stuff) */
    uae_log("PPC: MODULE_INIT_QOM\n");
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

    /* Configure timing based on instruction counter */
    //configure_icount("auto");
    //configure_icount("10");
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
    uae_log("PPC: CPU PVR 0x%08x\n", state.env->spr[SPR_PVR]);

    return true;
}

bool ppc_cpu_init(uint32_t pvr)
{
    uae_log("PPC: ppc_cpu_init pvr=0x%08x\n", pvr);
    const char *model = NULL;
    if (pvr == CPU_POWERPC_604E_v24) {
        model = "604e_v2.4";
    } else if (pvr == CPU_POWERPC_603E7v1) {
        model = "603e7v1";
    } else {
        uae_log("PPC: Unknown CPU PVR, initialization failed\n");
        return false;
    }
    return initialize(model);
}

bool ppc_cpu_init_with_model(const char* model)
{
    const char *qemu_model = model;
    if (strcasecmp(model, "603ev") == 0) {
        qemu_model = "603e7v1";
    } else if (strcasecmp(model, "604e") == 0) {
        qemu_model = "604e_v2.4";
    }
    uae_log("PPC: ppc_cpu_init_with_model %s => %s\n", model, qemu_model);
    return initialize(qemu_model);
}

void ppc_cpu_map_memory(PPCMemoryRegion *regions, int count)
{
    /*
     * TODO:
     * Support aliased memory regions
     */
    MemoryRegion* mem;
    int i;
    uae_log("PPC: Map memory regions:\n");
    for (i = 0; i < count; i++) {
        PPCMemoryRegion *r = regions + i;
        uae_log("PPC: %08x [+%8x]  =>  %p  \"%s\")\n",
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
    }
}

void ppc_cpu_free(void)
{
    uae_log("PPC: ppc_cpu_free (STUB)\n");
}

void ppc_cpu_stop(void)
{
    uae_log("PPC: ppc_cpu_stop\n");
    cpu_exit(ENV_GET_CPU(state.env));
}

void ppc_cpu_atomic_raise_ext_exception(void)
{
    // uae_log("PPC: ppc_cpu_atomic_raise_ext_exception\n");
    ppc_set_irq(state.cpu, PPC_INTERRUPT_EXT, 1);
}

void ppc_cpu_atomic_cancel_ext_exception(void)
{
    // uae_log("PPC: ppc_cpu_atomic_cancel_ext_exception\n");
    ppc_set_irq(state.cpu, PPC_INTERRUPT_EXT, 0);
}

void ppc_cpu_set_pc(int cpu, uint32_t value)
{
    uae_log("PPC: ppc_cpu_set_pc %x (cpu=%d)\n", value, cpu);
    // set instruction pointer (hack? better way?)
    state.env->nip = value;
}

#if 0
static void main_loop(void)
{
    bool nonblocking;
    int last_io = 0;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif
    do {
        //nonblocking = !kvm_enabled() && !xen_enabled() && last_io > 0;
        nonblocking = last_io > 0;
#ifdef CONFIG_PROFILER
        ti = profile_getclock();
#endif
        last_io = main_loop_wait(nonblocking);
#ifdef CONFIG_PROFILER
        dev_time += profile_getclock() - ti;
#endif
    } while (!main_loop_should_exit());
}
#endif

void ppc_cpu_run_continuous(void)
{
    uae_log("PPC: ppc_cpu_run_continuous\n");

    cpu_enable_ticks();
    runstate_set(RUN_STATE_RUNNING);
    vm_state_notify(1, RUN_STATE_RUNNING);
    resume_all_vcpus();

    //cpu_exec(state.env);
#if 0
    //CPUState *cpu = arg;
    CPUState *cpu = ENV_GET_CPU(state.env);

    //qemu_tcg_init_cpu_signals();
    qemu_thread_get_self(cpu->thread);
#endif
#if 0
    qemu_mutex_lock(&qemu_global_mutex);
    CPU_FOREACH(cpu) {
        cpu->thread_id = qemu_get_thread_id();
        cpu->created = true;
    }
    qemu_cond_signal(&qemu_cpu_cond);
#endif
#if 0
    /* wait for initial kick-off after machine start */
    while (QTAILQ_FIRST(&cpus)->stopped) {
        //qemu_cond_wait(tcg_halt_cond, &qemu_global_mutex);

        /* process any pending work */
        CPU_FOREACH(cpu) {
            qemu_wait_io_event_common(cpu);
        }
    }
#endif
    main_loop();
    //while (1) {
    //    g_usleep(1000000);
    //    resume_all_vcpus();
#if 0
        tcg_exec_all();

        if (use_icount) {
            int64_t deadline = qemu_clock_deadline_ns_all(QEMU_CLOCK_VIRTUAL);

            if (deadline == 0) {
                qemu_clock_notify(QEMU_CLOCK_VIRTUAL);
                qemu_clock_run_timers(QEMU_CLOCK_VIRTUAL);
                //qemu_clock_run_all_timers();
            }
        }

        while (state.pause) {
            /* very basic pause function, just sleeping 1ms in a loop */
            g_usleep(1000);
        }

        qemu_tcg_wait_io_event();
#endif
    //}
}

void ppc_cpu_run_single(int count)
{
    uae_log("PPC: ppc_cpu_run_single count=%d (STUB)\n", count);
}

uint64_t ppc_cpu_get_dec(void)
{
    return cpu_ppc_load_decr(state.env);
}

void ppc_cpu_do_dec(int value)
{
    uae_log("PPC: ppc_cpu_do_dec %d\n", value);
    cpu_ppc_store_decr(state.env, value);
}

void ppc_cpu_pause(int pause)
{
    uae_log("PPC: ppc_cpu_pause %d\n", pause);
#if 1
    qemu_mutex_lock_iothread();
    if (pause) {
        pause_all_vcpus();
        uae_log("PPC: paused!\n");
    } else {
        resume_all_vcpus();
        uae_log("PPC: resumed!\n");
    }
    qemu_mutex_unlock_iothread();
#else
    state.pause = pause;
    if (pause) {
        // FIXME: can raise an interrupt/exception here to make the CPU
        // execution end sooner
    }
#endif
}

/* Storage for callback functions set by UAE */

uae_log_function uae_log = NULL;
uae_ppc_io_mem_read_function uae_ppc_io_mem_read = NULL;
uae_ppc_io_mem_write_function uae_ppc_io_mem_write = NULL;
uae_ppc_io_mem_read64_function uae_ppc_io_mem_read64 = NULL;
uae_ppc_io_mem_write64_function uae_ppc_io_mem_write64 = NULL;
