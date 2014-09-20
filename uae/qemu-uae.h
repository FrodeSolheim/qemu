#ifndef QEMU_UAE_H
#define QEMU_UAE_H

void runstate_init(void);
// void tcg_exec_all(void);
void qemu_tcg_wait_io_event(void);
void qemu_wait_io_event_common(CPUState *cpu);

/* vl.c */
void main_loop(void);
bool main_loop_should_exit(void);

/* qemu-uae-cpu.c */

bool qemu_uae_main_loop_should_exit(void);

/* qemu-uae-main.c */

void qemu_uae_wait_until_started(void);

#endif /* QEMU_UAE_H */
