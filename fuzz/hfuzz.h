#ifndef FUZZ_HONGGFUZZ_H
#define FUZZ_HONGGFUZZ_H

#include "fuzz/config.h"

extern abi_ulong hfuzz_qemu_entry_point;
extern abi_ulong hfuzz_qemu_start_code[20];
extern abi_ulong hfuzz_qemu_end_code[20];
extern abi_ulong  hfuzz_qemu_img_cnt;

extern void hfuzz_qemu_setup(void);

extern void hfuzz_trace_pc(uintptr_t pc);
extern int hfuzz_pc_trace_fd;
static inline void hfuzz_qemu_trace_pc(abi_ulong pc) {
  int trace = 0;
  for (abi_ulong i = 0; i < hfuzz_qemu_img_cnt; i++) {
      if (pc < hfuzz_qemu_end_code[i] && pc >= hfuzz_qemu_start_code[i]) {
          trace = 1;
          break;
      }
  }
  if (!trace) {
    return;
  }
  if (hfuzz_pc_trace_fd != -1) {
    if (-1 == write(hfuzz_pc_trace_fd, &pc, sizeof(pc))) {
      fputs("trace write error\n", stderr);
      exit(1);
    }
  }
  hfuzz_trace_pc(pc);
}

#ifdef HFUZZ_FORKSERVER
extern void hfuzz_qemu_handle_argv(char **argv);
#endif // HFUZZ_FORKSERVER

#endif
