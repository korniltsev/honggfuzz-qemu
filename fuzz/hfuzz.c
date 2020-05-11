#include <stdio.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "tcg-op.h"

#include "fuzz/hfuzz.h"


#ifdef HFUZZ_FORKSERVER

extern void HonggfuzzFetchData(const uint8_t** buf_ptr, size_t* len_ptr);

static void fork_server(void) {
  size_t len;
  const uint8_t *buf = 0;

  while (2) {
    HonggfuzzFetchData(&buf, &len);

    if (lseek(1021, 0, SEEK_SET) == -1) {
      perror("lseek(1021, 0, SEEK_SET");
      exit(1);
    }

    pid_t pid = fork();
    if (pid < 0) {
      fputs("fork error\n", stderr);
      exit(1);
    }

    // Child
    if (!pid) {
      return;
    }

    // Parent
    int status;
    if (waitpid(pid, &status, 0) <= 0) {
      fputs("waitpid error\n", stderr);
      exit(1);
    }
  }
}
#endif // HFUZZ_FORKSERVER

extern void hfuzzInstrumentInit(void);

int hfuzz_pc_trace_fd = -1;

void hfuzz_qemu_setup(void) {
  rcu_disable_atfork();
  hfuzzInstrumentInit();

  if (getenv("HFUZZ_INST_LIBS")) {
    hfuzz_qemu_start_code[0] = 0;
    hfuzz_qemu_end_code[0]   = (abi_ulong)-1;
  } else if (getenv("HFUZZ_TRACE_RANGES")) {
    const char *it = getenv("HFUZZ_TRACE_RANGES");
    while (*it) {
      abi_ulong from, to, nr = 0;
      int nc;
      nr = sscanf(it, "0x" TARGET_FMT_lx "-0x" TARGET_FMT_lx "%n", &from, &to, &nc);
      if (nc >= 7 && nr == 2) {
        printf("add lib map %x " TARGET_FMT_lx " : " TARGET_FMT_lx " - " TARGET_FMT_lx " \n", nc, nr, from, to);
        hfuzz_qemu_start_code[hfuzz_qemu_img_cnt] = from;
        hfuzz_qemu_end_code[hfuzz_qemu_img_cnt]   = to;
        hfuzz_qemu_img_cnt+=1;
        if (hfuzz_qemu_img_cnt == 20) break;
      } else {
        break;
      }
      it += nc;
      if (*it == ',') it++;
      else break;
    }

  }

  if (getenv("HFUZZ_PC_TRACE_FILE")) {
      hfuzz_pc_trace_fd = open(getenv("HFUZZ_PC_TRACE_FILE"), O_CREAT | O_EXCL | O_WRONLY, 0600);
      if (hfuzz_pc_trace_fd == -1) {
          perror("open HFUZZ_PC_TRACE_FILE");
          exit(1);
      }
  }

#ifdef HFUZZ_FORKSERVER
  fork_server();
#endif // HFUZZ_FORKSERVER
}

extern void hfuzz_trace_cmp4(uintptr_t pc, uint64_t Arg1, uint64_t Arg2);
extern void hfuzz_trace_cmp8(uintptr_t pc, uint64_t Arg1, uint64_t Arg2);

void HELPER(hfuzz_qemu_trace_cmp_i64)(
        uint64_t cur_loc, uint64_t arg1, uint64_t arg2
    ) {
  hfuzz_trace_cmp8(cur_loc, arg1, arg2);
}

void HELPER(hfuzz_qemu_trace_cmp_i32)(
        uint32_t cur_loc, uint32_t arg1, uint32_t arg2
    ) {
  hfuzz_trace_cmp4(cur_loc, arg1, arg2);
}

