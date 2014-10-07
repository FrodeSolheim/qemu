/*
 * QEMU integration code for use with UAE
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
#include "net/net.h"
#include "sysemu/sysemu.h"
#include "qemu/log.h"
#include "cpu-models.h"
#include "helper_regs.h"
#include "qemu/module.h"
#include "sysemu/cpus.h"
#include "qemu-uae.h"

#include "uae/log.h"
#include "uae/ppc.h"
#include "uae/qemu.h"

#ifdef UAE
#error UAE should not be defined here
#endif

/* Increase this when changes are not backwards compatible */
#define VERSION_MAJOR 3

/* Increase this when important changes are made */
#define VERSION_MINOR 2

/* Just increase this when the update is insignificant */
#define VERSION_REVISION 0

#if QEMU_UAE_VERSION_MAJOR != VERSION_MAJOR
#error Major version mismatch between UAE and QEMU-UAE
#endif

#if QEMU_UAE_VERSION_MINOR != VERSION_MINOR
#warning Minor version mismatch between UAE and QEMU-UAE
#endif

static struct {
    volatile bool started;
    bool exit_main_loop;
} state;

void qemu_uae_set_started(void)
{
    state.started = true;
}

void qemu_uae_wait_until_started(void)
{
    while (!state.started) {
        qemu_mutex_unlock_iothread();
        g_usleep(10);
        qemu_mutex_lock_iothread();
    }
}

void qemu_uae_version(int *major, int *minor, int *revision)
{
    *major = VERSION_MAJOR;
    *minor = VERSION_MINOR;
    *revision = VERSION_REVISION;
}

static void configure_accelerator(void)
{
    /* Allocate translation buffer (what is a suitable size?) */
    tcg_exec_init(32 * 1024 * 1024);
}

static bool initialize(void)
{
    int major, minor, revision;
    qemu_uae_version(&major, &minor, &revision);
    uae_log("QEMU: Initialize QEMU-UAE (QEMU %s + API %d.%d.%d)\n",
            qemu_get_version(), major, minor, revision);

    /* Initialize the class system (and probably other stuff) */
    uae_log("QEMU: MODULE_INIT_QOM\n");
    module_call_init(MODULE_INIT_QOM);

    /* Initialize runstate transition structures */
    runstate_init();

    /* qemu_init_main_loop -> qemu_signal_init installs signals */
    /* FIXME: could conflict with UAE */
    if (qemu_init_main_loop()) {
        fprintf(stderr, "qemu_init_main_loop failed\n");
        exit(1);
    }

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
#if 0
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
#endif
    qemu_mutex_unlock_iothread();
    return true;
}

static void qemu_uae_main(void)
{
    uae_log("QEMU: Running main loop\n");
    qemu_mutex_lock_iothread();
//#if 0
    cpu_enable_ticks();
    runstate_set(RUN_STATE_RUNNING);
    vm_state_notify(1, RUN_STATE_RUNNING);
#if 0
    resume_all_vcpus();
#endif
    qemu_uae_set_started();

    /* The main loop iteration unlocks and relocks the iothread lock */
    main_loop();
}

static void *main_thread_function(void *arg)
{
    uae_log("QEMU: Main thread running\n");
    qemu_uae_main();
    return NULL;
}

static QemuThread main_thread;

void qemu_uae_init(void)
{
    static bool initialized = false;
    if (initialized) {
        return;
    }
    uae_log("QEMU: Initializing\n");
    initialize();
#if 0
    /* Now we fire away a main thread right away. We could wait until
     * we are sure we need it, but since qemu_uae_init was called in the
     * first place, we are probably going to need it really soon anyway. */
    qemu_thread_create(&main_thread, "QEMU Main", main_thread_function,
                       NULL, QEMU_THREAD_DETACHED);
#endif
    initialized = true;
}

void qemu_uae_start(void)
{
    static bool initialized = false;
    if (initialized) {
        return;
    }
    initialized = true;
    uae_log("QEMU: Starting main loop\n");
    qemu_thread_create(&main_thread, "QEMU Main", main_thread_function,
                       NULL, QEMU_THREAD_DETACHED);
}

bool qemu_uae_main_loop_should_exit(void)
{
    return state.exit_main_loop;
}
