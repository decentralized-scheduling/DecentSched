/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#define _GNU_SOURCE

// headers {{{
#include "lib.h"
#include "ctypes.h"
#include <assert.h>
#include <execinfo.h>
#include <math.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <time.h>
#include <stdarg.h> // va_start

#if defined(__linux__)
#include <linux/fs.h>
#include <malloc.h>  // malloc_usable_size
#elif defined(__APPLE__) && defined(__MACH__)
#include <sys/disk.h>
#include <malloc/malloc.h>
#elif defined(__FreeBSD__)
#include <sys/disk.h>
#include <malloc_np.h>
#endif // OS

#if defined(__FreeBSD__)
#include <pthread_np.h>
#endif
// }}} headers

// math {{{
  inline u64
mhash64(const u64 v)
{
  return v * 11400714819323198485lu;
}

  inline u32
mhash32(const u32 v)
{
  return v * 2654435761u;
}

// From Daniel Lemire's blog (2013, lemire.me)
  u64
gcd64(u64 a, u64 b)
{
  if (a == 0)
    return b;
  if (b == 0)
    return a;

  const u32 shift = (u32)__builtin_ctzl(a | b);
  a >>= __builtin_ctzl(a);
  do {
    b >>= __builtin_ctzl(b);
    if (a > b) {
      const u64 t = b;
      b = a;
      a = t;
    }
    b = b - a;
  } while (b);
  return a << shift;
}
// }}} math

// random {{{
// Lehmer's generator is 2x faster than xorshift
/**
 * D. H. Lehmer, Mathematical methods in large-scale computing units.
 * Proceedings of a Second Symposium on Large Scale Digital Calculating
 * Machinery;
 * Annals of the Computation Laboratory, Harvard Univ. 26 (1951), pp. 141-146.
 *
 * P L'Ecuyer,  Tables of linear congruential generators of different sizes and
 * good lattice structure. Mathematics of Computation of the American
 * Mathematical
 * Society 68.225 (1999): 249-260.
 */
struct lehmer_u64 {
  union {
    u128 v128;
    u64 v64[2];
  };
};

static __thread struct lehmer_u64 rseed_u128 = {.v64 = {4294967291, 1549556881}};

  static inline u64
lehmer_u64_next(struct lehmer_u64 * const s)
{
  const u64 r = s->v64[1];
  s->v128 *= 0xda942042e4dd58b5lu;
  return r;
}

  static inline void
lehmer_u64_seed(struct lehmer_u64 * const s, const u64 seed)
{
  s->v128 = (((u128)(~seed)) << 64) | (seed | 1);
  (void)lehmer_u64_next(s);
}

  inline u64
random_u64(void)
{
  return lehmer_u64_next(&rseed_u128);
}

  inline void
srandom_u64(const u64 seed)
{
  lehmer_u64_seed(&rseed_u128, seed);
}

  inline double
random_double(void)
{
  // random between [0.0 - 1.0]
  const u64 r = random_u64();
  return ((double)r) * (1.0 / ((double)(~0lu)));
}
// }}} random

// timing {{{
  inline u64
time_nsec(void)
{
  struct timespec ts;
  // MONO_RAW is 5x to 10x slower than MONO
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((u64)ts.tv_sec) * 1000000000lu + ((u64)ts.tv_nsec);
}

  inline double
time_sec(void)
{
  const u64 nsec = time_nsec();
  return ((double)nsec) * 1.0e-9;
}

  inline u64
time_diff_nsec(const u64 last)
{
  return time_nsec() - last;
}

  inline double
time_diff_sec(const double last)
{
  return time_sec() - last;
}

// need char str[64]
  void
time_stamp(char * str, const size_t size)
{
  time_t now;
  struct tm nowtm;
  time(&now);
  localtime_r(&now, &nowtm);
  strftime(str, size, "%F %T %z", &nowtm);
}

  void
time_stamp2(char * str, const size_t size)
{
  time_t now;
  struct tm nowtm;
  time(&now);
  localtime_r(&now, &nowtm);
  strftime(str, size, "%F-%H-%M-%S%z", &nowtm);
}
// }}} timing

// cpucache {{{
  inline void
cpu_pause(void)
{
#if defined(__x86_64__)
  _mm_pause();
#elif defined(__aarch64__)
  // nop
#endif
}

  inline void
cpu_mfence(void)
{
  atomic_thread_fence(MO_SEQ_CST);
}

// compiler fence
  inline void
cpu_cfence(void)
{
  atomic_thread_fence(MO_ACQ_REL);
}

  inline void
cpu_prefetch0(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 0);
}

  inline void
cpu_prefetch1(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 1);
}

  inline void
cpu_prefetch2(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 2);
}

  inline void
cpu_prefetch3(const void * const ptr)
{
  __builtin_prefetch(ptr, 0, 3);
}

  inline void
cpu_prefetchw(const void * const ptr)
{
  __builtin_prefetch(ptr, 1, 0);
}
// }}} cpucache

// crc32c {{{
  inline u32
crc32c_u8(const u32 crc, const u8 v)
{
#if defined(__x86_64__)
  return _mm_crc32_u8(crc, v);
#elif defined(__aarch64__)
  return __crc32cb(crc, v);
#endif
}

  inline u32
crc32c_u16(const u32 crc, const u16 v)
{
#if defined(__x86_64__)
  return _mm_crc32_u16(crc, v);
#elif defined(__aarch64__)
  return __crc32ch(crc, v);
#endif
}

  inline u32
crc32c_u32(const u32 crc, const u32 v)
{
#if defined(__x86_64__)
  return _mm_crc32_u32(crc, v);
#elif defined(__aarch64__)
  return __crc32cw(crc, v);
#endif
}

  inline u32
crc32c_u64(const u32 crc, const u64 v)
{
#if defined(__x86_64__)
  return (u32)_mm_crc32_u64(crc, v);
#elif defined(__aarch64__)
  return (u32)__crc32cd(crc, v);
#endif
}

  inline u32
crc32c_inc_123(const u8 * buf, u32 nr, u32 crc)
{
  if (nr == 1)
    return crc32c_u8(crc, buf[0]);

  crc = crc32c_u16(crc, *(u16 *)buf);
  return (nr == 2) ? crc : crc32c_u8(crc, buf[2]);
}

  inline u32
crc32c_inc_x4(const u8 * buf, u32 nr, u32 crc)
{
  //debug_assert((nr & 3) == 0);
  const u32 nr8 = nr >> 3;
#pragma nounroll
  for (u32 i = 0; i < nr8; i++)
    crc = crc32c_u64(crc, ((u64*)buf)[i]);

  if (nr & 4u)
    crc = crc32c_u32(crc, ((u32*)buf)[nr8<<1]);
  return crc;
}

  u32
crc32c_inc(const u8 * buf, u32 nr, u32 crc)
{
  crc = crc32c_inc_x4(buf, nr, crc);
  const u32 nr123 = nr & 3u;
  return nr123 ? crc32c_inc_123(buf + nr - nr123, nr123, crc) : crc;
}
// }}} crc32c

// debug {{{
  void
debug_break(void)
{
  usleep(100);
}

static u64 * debug_watch_u64 = NULL;

  static void
watch_u64_handler(const int sig)
{
  (void)sig;
  const u64 v = debug_watch_u64 ? (*debug_watch_u64) : 0;
  fprintf(stderr, "[USR1] %lu (0x%lx)\n", v, v);
}

  void
watch_u64_usr1(u64 * const ptr)
{
  debug_watch_u64 = ptr;
  struct sigaction sa = {};
  sa.sa_handler = watch_u64_handler;
  sigemptyset(&(sa.sa_mask));
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGUSR1, &sa, NULL) == -1) {
    fprintf(stderr, "Failed to set signal handler for SIGUSR1\n");
  } else {
    fprintf(stderr, "to watch> kill -s SIGUSR1 %d\n", getpid());
  }
}

static void * debug_bt_state = NULL;
#if defined(BACKTRACE) && defined(__linux__)
// TODO: get exec path on MacOS and FreeBSD

#include <backtrace.h>
static char debug_filepath[1024] = {};

  static void
debug_bt_error_cb(void * const data, const char * const msg, const int errnum)
{
  (void)data;
  if (msg)
    dprintf(2, "libbacktrace: %s %s\n", msg, strerror(errnum));
}

  static int
debug_bt_print_cb(void * const data, const uintptr_t pc,
    const char * const file, const int lineno, const char * const func)
{
  u32 * const plevel = (typeof(plevel))data;
  if (file || func || lineno) {
    dprintf(2, "[%u]0x%012lx " TERMCLR(35) "%s" TERMCLR(31) ":" TERMCLR(34) "%d" TERMCLR(0)" %s\n",
        *plevel, pc, file ? file : "???", lineno, func ? func : "???");
  } else if (pc) {
    dprintf(2, "[%u]0x%012lx ??\n", *plevel, pc);
  }
  (*plevel)++;
  return 0;
}

__attribute__((constructor))
  static void
debug_backtrace_init(void)
{
  const ssize_t len = readlink("/proc/self/exe", debug_filepath, 1023);
  // disable backtrace
  if (len < 0 || len >= 1023)
    return;

  debug_filepath[len] = '\0';
  debug_bt_state = backtrace_create_state(debug_filepath, 1, debug_bt_error_cb, NULL);
}
#endif // BACKTRACE

  static void
debug_wait_gdb(void * const bt_state)
{
  if (bt_state) {
#if defined(BACKTRACE)
    dprintf(2, "Backtrace :\n");
    u32 level = 0;
    backtrace_full(debug_bt_state, 1, debug_bt_print_cb, debug_bt_error_cb, &level);
#endif // BACKTRACE
  } else { // fallback to execinfo if no backtrace or initialization failed
    void *array[64];
    const int size = backtrace(array, 64);
    dprintf(2, "Backtrace (%d):\n", size - 1);
    backtrace_symbols_fd(array + 1, size - 1, 2);
  }

  abool v = true;
  char timestamp[32];
  time_stamp(timestamp, 32);
  char threadname[32] = {};
  thread_get_name(pthread_self(), threadname, 32);
  strcat(threadname, "(!!)");
  thread_set_name(pthread_self(), threadname);
  char hostname[32];
  gethostname(hostname, 32);

  const char * const pattern = "[Waiting GDB] %1$s %2$s @ %3$s\n"
    "    Attach me: " TERMCLR(31) "sudo -Hi gdb -p %4$d" TERMCLR(0) "\n";
  char buf[256];
  sprintf(buf, pattern, timestamp, threadname, hostname, getpid());
  write(2, buf, strlen(buf));

  // to continue: gdb> set var v = 0
  // to kill from shell: $ kill %pid; kill -CONT %pid

  // uncomment this line to surrender the shell on error
  // kill(getpid(), SIGSTOP); // stop burning cpu, once

  static au32 nr_waiting = 0;
  const u32 seq = atomic_fetch_add_explicit(&nr_waiting, 1, MO_RELAXED);
  if (seq == 0) {
    sprintf(buf, "/run/user/%u/.debug_wait_gdb_pid", getuid());
    const int pidfd = open(buf, O_CREAT|O_TRUNC|O_WRONLY, 00644);
    if (pidfd >= 0) {
      dprintf(pidfd, "%u", getpid());
      close(pidfd);
    }
  }

#pragma nounroll
  while (atomic_load_explicit(&v, MO_CONSUME))
    sleep(1);
}

#ifndef NDEBUG
  void
debug_assert(const bool v)
{
  if (!v)
    debug_wait_gdb(debug_bt_state);
}
#endif

__attribute__((noreturn))
  void
debug_die(void)
{
  debug_wait_gdb(debug_bt_state);
  exit(0);
}

__attribute__((noreturn))
  void
debug_die_perror(void)
{
  perror(NULL);
  debug_die();
}

#if !defined(NOSIGNAL)
// signal handler for wait_gdb on fatal errors
  static void
wait_gdb_handler(const int sig, siginfo_t * const info, void * const context)
{
  (void)info;
  (void)context;
  char buf[64] = "[SIGNAL] ";
  strcat(buf, strsignal(sig));
  write(2, buf, strlen(buf));
  debug_wait_gdb(NULL);
}

// setup hooks for catching fatal errors
__attribute__((constructor))
  static void
debug_init(void)
{
  void * stack = pages_alloc_4kb(16);
  //fprintf(stderr, "altstack %p\n", stack);
  stack_t ss = {.ss_sp = stack, .ss_flags = 0, .ss_size = PGSZ*16};
  if (sigaltstack(&ss, NULL))
    fprintf(stderr, "sigaltstack failed\n");

  struct sigaction sa = {.sa_sigaction = wait_gdb_handler, .sa_flags = SA_SIGINFO | SA_ONSTACK};
  sigemptyset(&(sa.sa_mask));
  const int fatals[] = {SIGSEGV, SIGFPE, SIGILL, SIGBUS, 0};
  for (int i = 0; fatals[i]; i++) {
    if (sigaction(fatals[i], &sa, NULL) == -1) {
      fprintf(stderr, "Failed to set signal handler for %s\n", strsignal(fatals[i]));
      fflush(stderr);
    }
  }
}

__attribute__((destructor))
  static void
debug_exit(void)
{
  // to get rid of valgrind warnings
  stack_t ss = {.ss_flags = SS_DISABLE};
  stack_t oss = {};
  sigaltstack(&ss, &oss);
  if (oss.ss_sp)
    pages_unmap(oss.ss_sp, PGSZ * 16);
}
#endif // !defined(NOSIGNAL)

  void
debug_dump_maps(FILE * const out)
{
  FILE * const in = fopen("/proc/self/smaps", "r");
  char * line0 = yalloc(1024);
  size_t size0 = 1024;
  while (!feof(in)) {
    const ssize_t r1 = getline(&line0, &size0, in);
    if (r1 < 0) break;
    fprintf(out, "%s", line0);
  }
  free(line0);
  fflush(out);
  fclose(in);
}

static pid_t perf_pid = 0;

#if defined(__linux__)
__attribute__((constructor))
  static void
debug_perf_init(void)
{
  const pid_t ppid = getppid();
  char tmp[256] = {};
  sprintf(tmp, "/proc/%d/cmdline", ppid);
  FILE * const fc = fopen(tmp, "r");
  const size_t nr = fread(tmp, 1, sizeof(tmp) - 1, fc);
  fclose(fc);
  // look for "perf record"
  if (nr < 12)
    return;
  tmp[nr] = '\0';
  for (u64 i = 0; i < nr; i++)
    if (tmp[i] == 0)
      tmp[i] = ' ';

  char * const perf = strstr(tmp, "perf record");
  if (perf) {
    fprintf(stderr, "%s: perf detected\n", __func__);
    perf_pid = ppid;
  }
}
#endif // __linux__

  bool
debug_perf_switch(void)
{
  if (perf_pid > 0) {
    kill(perf_pid, SIGUSR2);
    return true;
  } else {
    return false;
  }
}
// }}} debug

// mm {{{
#ifdef ALLOCFAIL
  bool
alloc_fail(void)
{
#define ALLOCFAIL_RECP ((64lu))
#define ALLOCFAIL_MAGIC ((ALLOCFAIL_RECP / 3lu))
  return ((random_u64() % ALLOCFAIL_RECP) == ALLOCFAIL_MAGIC);
}

#ifdef MALLOCFAIL
extern void * __libc_malloc(size_t size);
  void *
malloc(size_t size)
{
  if (alloc_fail())
    return NULL;
  return __libc_malloc(size);
}

extern void * __libc_calloc(size_t nmemb, size_t size);
  void *
calloc(size_t nmemb, size_t size)
{
  if (alloc_fail())
    return NULL;
  return __libc_calloc(nmemb, size);
}

extern void *__libc_realloc(void *ptr, size_t size);

  void *
realloc(void *ptr, size_t size)
{
  if (alloc_fail())
    return NULL;
  return __libc_realloc(ptr, size);
}
#endif // MALLOC_FAIL
#endif // ALLOC_FAIL

  void *
xalloc(const size_t align, const size_t size)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  void * p;
  return (posix_memalign(&p, align, size) == 0) ? p : NULL;
}

// alloc cache-line aligned address
  void *
yalloc(const size_t size)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  void * p;
  return (posix_memalign(&p, 64, size) == 0) ? p : NULL;
}

  void **
malloc_2d(const size_t nr, const size_t size)
{
  const size_t size1 = nr * sizeof(void *);
  const size_t size2 = nr * size;
  void ** const mem = malloc(size1 + size2);
  u8 * const mem2 = ((u8 *)mem) + size1;
  for (size_t i = 0; i < nr; i++)
    mem[i] = mem2 + (i * size);
  return mem;
}

  inline void **
calloc_2d(const size_t nr, const size_t size)
{
  void ** const ret = malloc_2d(nr, size);
  memset(ret[0], 0, nr * size);
  return ret;
}

  inline void
pages_unmap(void * const ptr, const size_t size)
{
#ifndef HEAPCHECKING
  munmap(ptr, size);
#else
  (void)size;
  free(ptr);
#endif
}

  void
pages_lock(void * const ptr, const size_t size)
{
  static bool use_mlock = true;
  if (use_mlock) {
    const int ret = mlock(ptr, size);
    if (ret != 0) {
      use_mlock = false;
      fprintf(stderr, "%s: mlock disabled\n", __func__);
    }
  }
}

#ifndef HEAPCHECKING
  static void *
pages_do_alloc(const size_t size, const int flags)
{
  // vi /etc/security/limits.conf
  // * - memlock unlimited
  void * const p = mmap(NULL, size, PROT_READ | PROT_WRITE, flags, -1, 0);
  if (p == MAP_FAILED)
    return NULL;

  pages_lock(p, size);
  return p;
}

#if defined(__linux__) && defined(MAP_HUGETLB)

#if defined(MAP_HUGE_SHIFT)
#define PAGES_FLAGS_1G ((MAP_HUGETLB | (30 << MAP_HUGE_SHIFT)))
#define PAGES_FLAGS_2M ((MAP_HUGETLB | (21 << MAP_HUGE_SHIFT)))
#else // MAP_HUGE_SHIFT
#define PAGES_FLAGS_1G ((MAP_HUGETLB))
#define PAGES_FLAGS_2M ((MAP_HUGETLB))
#endif // MAP_HUGE_SHIFT

#else
#define PAGES_FLAGS_1G ((0))
#define PAGES_FLAGS_2M ((0))
#endif // __linux__

#endif // HEAPCHECKING

  inline void *
pages_alloc_1gb(const size_t nr_1gb)
{
  const u64 sz = nr_1gb << 30;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | PAGES_FLAGS_1G);
#else
  void * const p = xalloc(1lu << 21, sz); // Warning: valgrind fails with 30
  if (p)
    memset(p, 0, sz);
  return p;
#endif
}

  inline void *
pages_alloc_2mb(const size_t nr_2mb)
{
  const u64 sz = nr_2mb << 21;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS | PAGES_FLAGS_2M);
#else
  void * const p = xalloc(1lu << 21, sz);
  if (p)
    memset(p, 0, sz);
  return p;
#endif
}

  inline void *
pages_alloc_4kb(const size_t nr_4kb)
{
  const size_t sz = nr_4kb << 12;
#ifndef HEAPCHECKING
  return pages_do_alloc(sz, MAP_PRIVATE | MAP_ANONYMOUS);
#else
  void * const p = xalloc(1lu << 12, sz);
  if (p)
    memset(p, 0, sz);
  return p;
#endif
}

  void *
pages_alloc_best(const size_t size, const bool try_1gb, u64 * const size_out)
{
#ifdef ALLOCFAIL
  if (alloc_fail())
    return NULL;
#endif
  // 1gb huge page: at least 0.25GB
  if (try_1gb) {
    if (size >= (1lu << 28)) {
      const size_t nr_1gb = bits_round_up(size, 30) >> 30;
      void * const p1 = pages_alloc_1gb(nr_1gb);
      if (p1) {
        *size_out = nr_1gb << 30;
        return p1;
      }
    }
  }

  // 2mb huge page: at least 0.5MB
  if (size >= (1lu << 19)) {
    const size_t nr_2mb = bits_round_up(size, 21) >> 21;
    void * const p2 = pages_alloc_2mb(nr_2mb);
    if (p2) {
      *size_out = nr_2mb << 21;
      return p2;
    }
  }

  const size_t nr_4kb = bits_round_up(size, 12) >> 12;
  void * const p3 = pages_alloc_4kb(nr_4kb);
  if (p3)
    *size_out = nr_4kb << 12;
  return p3;
}
// }}} mm

// process/thread {{{
static u32 process_ncpu;
#if defined(__FreeBSD__)
typedef cpuset_t cpu_set_t;
#elif defined(__APPLE__) && defined(__MACH__)
typedef u64 cpu_set_t;
#define CPU_SETSIZE ((64))
#define CPU_COUNT(__cpu_ptr__) (__builtin_popcountl(*__cpu_ptr__))
#define CPU_ISSET(__cpu_idx__, __cpu_ptr__) (((*__cpu_ptr__) >> __cpu_idx__) & 1lu)
#define CPU_ZERO(__cpu_ptr__) ((*__cpu_ptr__) = 0)
#define CPU_SET(__cpu_idx__, __cpu_ptr__) ((*__cpu_ptr__) |= (1lu << __cpu_idx__))
#define CPU_CLR(__cpu_idx__, __cpu_ptr__) ((*__cpu_ptr__) &= ~(1lu << __cpu_idx__))
#define pthread_attr_setaffinity_np(...) ((void)0)
#endif

__attribute__((constructor))
  static void
process_init(void)
{
  // Linux's default is 1024 cpus
  process_ncpu = (u32)sysconf(_SC_NPROCESSORS_CONF);
  if (process_ncpu > CPU_SETSIZE) {
    fprintf(stderr, "%s: can use only %zu cores\n",
        __func__, (size_t)CPU_SETSIZE);
    process_ncpu = CPU_SETSIZE;
  }
  thread_set_name(pthread_self(), "main");
}

  static inline int
thread_getaffinity_set(cpu_set_t * const cpuset)
{
#if defined(__linux__)
  return sched_getaffinity(0, sizeof(*cpuset), cpuset);
#elif defined(__FreeBSD__)
  return cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(*cpuset), cpuset);
#elif defined(__APPLE__) && defined(__MACH__)
  *cpuset = (1lu << process_ncpu) - 1;
  return (int)process_ncpu; // TODO
#endif // OS
}

  static inline int
thread_setaffinity_set(const cpu_set_t * const cpuset)
{
#if defined(__linux__)
  return sched_setaffinity(0, sizeof(*cpuset), cpuset);
#elif defined(__FreeBSD__)
  return cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(*cpuset), cpuset);
#elif defined(__APPLE__) && defined(__MACH__)
  (void)cpuset; // TODO
  return 0;
#endif // OS
}

  void
thread_get_name(const pthread_t pt, char * const name, const size_t len)
{
#if defined(__linux__)
  pthread_getname_np(pt, name, len);
#elif defined(__FreeBSD__)
  pthread_get_name_np(pt, name, len);
#elif defined(__APPLE__) && defined(__MACH__)
  (void)pt;
  (void)len;
  strcpy(name, "unknown"); // TODO
#endif // OS
}

  void
thread_set_name(const pthread_t pt, const char * const name)
{
#if defined(__linux__)
  pthread_setname_np(pt, name);
#elif defined(__FreeBSD__)
  pthread_set_name_np(pt, name);
#elif defined(__APPLE__) && defined(__MACH__)
  (void)pt;
  (void)name; // TODO
#endif // OS
}

// kB
  long
process_get_rss(void)
{
  struct rusage rs;
  getrusage(RUSAGE_SELF, &rs);
  return rs.ru_maxrss;
}

  u32
process_affinity_count(void)
{
  cpu_set_t set;
  if (thread_getaffinity_set(&set) != 0)
    return process_ncpu;

  const u32 nr = (u32)CPU_COUNT(&set);
  return nr ? nr : process_ncpu;
}

  u32
process_getaffinity_list(const u32 max, u32 * const cores)
{
  memset(cores, 0, max * sizeof(cores[0]));
  cpu_set_t set;
  if (thread_getaffinity_set(&set) != 0)
    return 0;

  const u32 nr_affinity = (u32)CPU_COUNT(&set);
  const u32 nr = nr_affinity < max ? nr_affinity : max;
  u32 j = 0;
  for (u32 i = 0; i < process_ncpu; i++) {
    if (CPU_ISSET(i, &set))
      cores[j++] = i;

    if (j >= nr)
      break;
  }
  return j;
}

  void
thread_setaffinity_list(const u32 nr, const u32 * const list)
{
  cpu_set_t set;
  CPU_ZERO(&set);
  for (u32 i = 0; i < nr; i++)
    if (list[i] < process_ncpu)
      CPU_SET(list[i], &set);
  thread_setaffinity_set(&set);
}

  void
thread_pin(const u32 cpu)
{
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(cpu % process_ncpu, &set);
  thread_setaffinity_set(&set);
}

  u64
process_cpu_time_usec(void)
{
  struct rusage rs;
  getrusage(RUSAGE_SELF, &rs);
  const u64 usr = (((u64)rs.ru_utime.tv_sec) * 1000000lu) + ((u64)rs.ru_utime.tv_usec);
  const u64 sys = (((u64)rs.ru_stime.tv_sec) * 1000000lu) + ((u64)rs.ru_stime.tv_usec);
  return usr + sys;
}

struct fork_join_info {
  u32 total;
  u32 ncores;
  u32 * cores;
  void *(*func)(void *);
  bool args;
  union {
    void * arg1;
    void ** argn;
  };
  union {
    struct { au32 ferr, jerr; };
    au64 xerr;
  };
};

// DON'T CHANGE!
#define FORK_JOIN_RANK_BITS ((16)) // 16
#define FORK_JOIN_MAX ((1u << FORK_JOIN_RANK_BITS))

/*
 * fj(6):     T0
 *         /      \
 *       T0        T4
 *     /   \      /
 *    T0   T2    T4
 *   / \   / \   / \
 *  t0 t1 t2 t3 t4 t5
 */

// recursive tree fork-join
  static void *
thread_do_fork_join_worker(void * const ptr)
{
  struct entry13 fjp = {.ptr = ptr};
  // GCC: Without explicitly casting from fjp.fji (a 45-bit u64 value),
  // the high bits will get truncated, which is always CORRECT in gcc.
  // Don't use gcc.
  struct fork_join_info * const fji = u64_to_ptr(fjp.e3);
  const u32 rank = (u32)fjp.e1;

  const u32 nchild = (u32)__builtin_ctz(rank ? rank : bits_p2_up_u32(fji->total));
  debug_assert(nchild <= FORK_JOIN_RANK_BITS);
  pthread_t tids[FORK_JOIN_RANK_BITS];
  if (nchild) {
    cpu_set_t set;
    CPU_ZERO(&set);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE); // Joinable by default
    // fork top-down
    for (u32 i = nchild - 1; i < nchild; i--) {
      const u32 cr = rank + (1u << i); // child's rank
      if (cr >= fji->total)
        continue; // should not break
      const u32 core = fji->cores[(cr < fji->ncores) ? cr : (cr % fji->ncores)];
      CPU_SET(core, &set);
      pthread_attr_setaffinity_np(&attr, sizeof(set), &set);
      fjp.e1 = (u16)cr;
      const int r = pthread_create(&tids[i], &attr, thread_do_fork_join_worker, fjp.ptr);
      CPU_CLR(core, &set);
      if (unlikely(r)) { // fork failed
        memset(&tids[0], 0, sizeof(tids[0]) * (i+1));
        u32 nmiss = (1u << (i + 1)) - 1;
        if ((rank + nmiss) >= fji->total)
          nmiss = fji->total - 1 - rank;
        (void)atomic_fetch_add_explicit(&fji->ferr, nmiss, MO_RELAXED);
        break;
      }
    }
    pthread_attr_destroy(&attr);
  }

  char thname0[16];
  char thname1[16];
  thread_get_name(pthread_self(), thname0, 16);
  snprintf(thname1, 16, "%.8s_%u", thname0, rank);
  thread_set_name(pthread_self(), thname1);

  void * const ret = fji->func(fji->args ? fji->argn[rank] : fji->arg1);

  thread_set_name(pthread_self(), thname0);
  // join bottom-up
  for (u32 i = 0; i < nchild; i++) {
    const u32 cr = rank + (1u << i); // child rank
    if (cr >= fji->total)
      break; // safe to break
    if (tids[i]) {
      const int r = pthread_join(tids[i], NULL);
      if (unlikely(r)) { // error
        //fprintf(stderr, "pthread_join %u..%u = %d: %s\n", rank, cr, r, strerror(r));
        (void)atomic_fetch_add_explicit(&fji->jerr, 1, MO_RELAXED);
      }
    }
  }
  return ret;
}

  u64
thread_fork_join(u32 nr, void *(*func) (void *), const bool args, void * const argx)
{
  if (unlikely(nr > FORK_JOIN_MAX)) {
    fprintf(stderr, "%s reduce nr to %u\n", __func__, FORK_JOIN_MAX);
    nr = FORK_JOIN_MAX;
  }

  u32 cores[CPU_SETSIZE];
  u32 ncores = process_getaffinity_list(process_ncpu, cores);
  if (unlikely(ncores == 0)) { // force to use all cores
    ncores = process_ncpu;
    for (u32 i = 0; i < process_ncpu; i++)
      cores[i] = i;
  }
  if (unlikely(nr == 0))
    nr = ncores;

  // the compiler does not know fji can change since we cast &fji into fjp
  struct fork_join_info fji = {.total = nr, .cores = cores, .ncores = ncores,
      .func = func, .args = args, .arg1 = argx};
  const struct entry13 fjp = entry13(0, (u64)(&fji));

  // save current affinity
  cpu_set_t set0;
  thread_getaffinity_set(&set0);

  // master thread shares thread0's core
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET(fji.cores[0], &set);
  thread_setaffinity_set(&set);

  const u64 t0 = time_nsec();
  (void)thread_do_fork_join_worker(fjp.ptr);
  const u64 dt = time_diff_nsec(t0);

  // restore original affinity
  thread_setaffinity_set(&set0);

  // check and report errors (unlikely)
  if (atomic_load_explicit(&fji.xerr, MO_CONSUME))
    fprintf(stderr, "%s errors: fork %u join %u\n", __func__, fji.ferr, fji.jerr);
  return dt;
}

  int
thread_create_at(const u32 cpu, pthread_t * const thread,
    void *(*start_routine) (void *), void * const arg)
{
  const u32 cpu_id = (cpu < process_ncpu) ? cpu : (cpu % process_ncpu);
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  cpu_set_t set;

  CPU_ZERO(&set);
  CPU_SET(cpu_id, &set);
  pthread_attr_setaffinity_np(&attr, sizeof(set), &set);
  const int r = pthread_create(thread, &attr, start_routine, arg);
  pthread_attr_destroy(&attr);
  return r;
}
// }}} process/thread

// bits {{{
  inline u32
bits_reverse_u32(const u32 v)
{
  const u32 v2 = __builtin_bswap32(v);
  const u32 v3 = ((v2 & 0xf0f0f0f0u) >> 4) | ((v2 & 0x0f0f0f0fu) << 4);
  const u32 v4 = ((v3 & 0xccccccccu) >> 2) | ((v3 & 0x33333333u) << 2);
  const u32 v5 = ((v4 & 0xaaaaaaaau) >> 1) | ((v4 & 0x55555555u) << 1);
  return v5;
}

  inline u64
bits_reverse_u64(const u64 v)
{
  const u64 v2 = __builtin_bswap64(v);
  const u64 v3 = ((v2 & 0xf0f0f0f0f0f0f0f0lu) >>  4) | ((v2 & 0x0f0f0f0f0f0f0f0flu) <<  4);
  const u64 v4 = ((v3 & 0xcccccccccccccccclu) >>  2) | ((v3 & 0x3333333333333333lu) <<  2);
  const u64 v5 = ((v4 & 0xaaaaaaaaaaaaaaaalu) >>  1) | ((v4 & 0x5555555555555555lu) <<  1);
  return v5;
}

  inline u64
bits_rotl_u64(const u64 v, const u8 n)
{
  const u8 sh = n & 0x3f;
  return (v << sh) | (v >> (64 - sh));
}

  inline u64
bits_rotr_u64(const u64 v, const u8 n)
{
  const u8 sh = n & 0x3f;
  return (v >> sh) | (v << (64 - sh));
}

  inline u32
bits_rotl_u32(const u32 v, const u8 n)
{
  const u8 sh = n & 0x1f;
  return (v << sh) | (v >> (32 - sh));
}

  inline u32
bits_rotr_u32(const u32 v, const u8 n)
{
  const u8 sh = n & 0x1f;
  return (v >> sh) | (v << (32 - sh));
}

  inline u64
bits_p2_up_u64(const u64 v)
{
  // clz(0) is undefined
  return (v > 1) ? (1lu << (64 - __builtin_clzl(v - 1lu))) : v;
}

  inline u32
bits_p2_up_u32(const u32 v)
{
  // clz(0) is undefined
  return (v > 1) ? (1u << (32 - __builtin_clz(v - 1u))) : v;
}

  inline u64
bits_p2_down_u64(const u64 v)
{
  return v ? (1lu << (63 - __builtin_clzl(v))) : v;
}

  inline u32
bits_p2_down_u32(const u32 v)
{
  return v ? (1u << (31 - __builtin_clz(v))) : v;
}

  inline u64
bits_round_up(const u64 v, const u8 power)
{
  return (v + (1lu << power) - 1lu) >> power << power;
}

  inline u64
bits_round_up_a(const u64 v, const u64 a)
{
  return (v + a - 1) / a * a;
}

  inline u64
bits_round_down(const u64 v, const u8 power)
{
  return v >> power << power;
}

  inline u64
bits_round_down_a(const u64 v, const u64 a)
{
  return v / a * a;
}
// }}} bits

// misc {{{
  inline struct entry13
entry13(const u16 e1, const u64 e3)
{
  debug_assert((e3 >> 48) == 0);
  return (struct entry13){.v64 = (e3 << 16) | e1};
}

  inline void
entry13_update_e3(struct entry13 * const e, const u64 e3)
{
  debug_assert((e3 >> 48) == 0);
  *e = entry13(e->e1, e3);
}

  inline void *
u64_to_ptr(const u64 v)
{
  return (void *)v;
}

  inline u64
ptr_to_u64(const void * const ptr)
{
  return (u64)ptr;
}

// portable malloc_usable_size
  inline size_t
m_usable_size(void * const ptr)
{
#if defined(__linux__) || defined(__FreeBSD__)
  const size_t sz = malloc_usable_size(ptr);
#elif defined(__APPLE__) && defined(__MACH__)
  const size_t sz = malloc_size(ptr);
#endif // OS

#ifndef HEAPCHECKING
  // valgrind and asan may return unaligned usable size
  debug_assert((sz & 0x7lu) == 0);
#endif // HEAPCHECKING

  return sz;
}

  inline size_t
fdsize(const int fd)
{
  struct stat st;
  st.st_size = 0;
  if (fstat(fd, &st) != 0)
    return 0;

  if (S_ISBLK(st.st_mode)) {
#if defined(__linux__)
    ioctl(fd, BLKGETSIZE64, &st.st_size);
#elif defined(__APPLE__) && defined(__MACH__)
    u64 blksz = 0;
    u64 nblks = 0;
    ioctl(fd, DKIOCGETBLOCKSIZE, &blksz);
    ioctl(fd, DKIOCGETBLOCKCOUNT, &nblks);
    st.st_size = (ssize_t)(blksz * nblks);
#elif defined(__FreeBSD__)
    ioctl(fd, DIOCGMEDIASIZE, &st.st_size);
#endif // OS
  }

  return (size_t)st.st_size;
}

  u32
memlcp(const u8 * const p1, const u8 * const p2, const u32 max)
{
  const u32 max64 = max & (~7u);
  u32 clen = 0;
  while (clen < max64) {
    const u64 v1 = *(const u64 *)(p1+clen);
    const u64 v2 = *(const u64 *)(p2+clen);
    const u64 x = v1 ^ v2;
    if (x)
      return clen + (u32)(__builtin_ctzl(x) >> 3);

    clen += sizeof(u64);
  }

  if ((clen + sizeof(u32)) <= max) {
    const u32 v1 = *(const u32 *)(p1+clen);
    const u32 v2 = *(const u32 *)(p2+clen);
    const u32 x = v1 ^ v2;
    if (x)
      return clen + (u32)(__builtin_ctz(x) >> 3);

    clen += sizeof(u32);
  }

  while ((clen < max) && (p1[clen] == p2[clen]))
    clen++;
  return clen;
}

static double logger_t0 = 0.0;

__attribute__((constructor))
  static void
logger_init(void)
{
  logger_t0 = time_sec();
}

__attribute__ ((format (printf, 2, 3)))
  void
logger_printf(const int fd, const char * const fmt, ...)
{
  char buf[4096];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  dprintf(fd, "%010.3lf %08x %s", time_diff_sec(logger_t0), crc32c_u64(0x12345678, (u64)pthread_self()), buf);
}
// }}} misc

// bitmap {{{
// Partially thread-safe bitmap; call it Eventual Consistency?
struct bitmap {
  u64 nbits;
  u64 nbytes; // must be a multiple of 8
  union {
    u64 ones;
    au64 ones_a;
  };
  u64 bm[0];
};

  inline void
bitmap_init(struct bitmap * const bm, const u64 nbits)
{
  bm->nbits = nbits;
  bm->nbytes = bits_round_up(nbits, 6) >> 3;
  bm->ones = 0;
  bitmap_set_all0(bm);
}

  inline struct bitmap *
bitmap_create(const u64 nbits)
{
  const u64 nbytes = bits_round_up(nbits, 6) >> 3;
  struct bitmap * const bm = malloc(sizeof(*bm) + nbytes);
  bitmap_init(bm, nbits);
  return bm;
}

  static inline bool
bitmap_test_internal(const struct bitmap * const bm, const u64 idx)
{
  return (bm->bm[idx >> 6] & (1lu << (idx & 0x3flu))) != 0;
}

  inline bool
bitmap_test(const struct bitmap * const bm, const u64 idx)
{
  return (idx < bm->nbits) && bitmap_test_internal(bm, idx);
}

  inline bool
bitmap_test_all1(struct bitmap * const bm)
{
  return bm->ones == bm->nbits;
}

  inline bool
bitmap_test_all0(struct bitmap * const bm)
{
  return bm->ones == 0;
}

  inline void
bitmap_set1(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->nbits) && !bitmap_test_internal(bm, idx)) {
    debug_assert(bm->ones < bm->nbits);
    bm->bm[idx >> 6] |= (1lu << (idx & 0x3flu));
    bm->ones++;
  }
}

  inline void
bitmap_set0(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->nbits) && bitmap_test_internal(bm, idx)) {
    debug_assert(bm->ones && (bm->ones <= bm->nbits));
    bm->bm[idx >> 6] &= ~(1lu << (idx & 0x3flu));
    bm->ones--;
  }
}

// for ht: each thread has exclusive access to a 64-bit range but updates concurrently
// use atomic +/- to update bm->ones_a
  inline void
bitmap_set1_safe64(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->nbits) && !bitmap_test_internal(bm, idx)) {
    debug_assert(bm->ones < bm->nbits);
    bm->bm[idx >> 6] |= (1lu << (idx & 0x3flu));
    (void)atomic_fetch_add_explicit(&bm->ones_a, 1, MO_RELAXED);
  }
}

  inline void
bitmap_set0_safe64(struct bitmap * const bm, const u64 idx)
{
  if ((idx < bm->nbits) && bitmap_test_internal(bm, idx)) {
    debug_assert(bm->ones && (bm->ones <= bm->nbits));
    bm->bm[idx >> 6] &= ~(1lu << (idx & 0x3flu));
    (void)atomic_fetch_sub_explicit(&bm->ones_a, 1, MO_RELAXED);
  }
}

  inline u64
bitmap_count(struct bitmap * const bm)
{
  return bm->ones;
}

  inline u64
bitmap_first(struct bitmap * const bm)
{
  for (u64 i = 0; (i << 6) < bm->nbits; i++) {
    if (bm->bm[i])
      return (i << 6) + (u32)__builtin_ctzl(bm->bm[i]);
  }
  debug_die();
}

  inline void
bitmap_set_all1(struct bitmap * const bm)
{
  memset(bm->bm, 0xff, bm->nbytes);
  bm->ones = bm->nbits;
}

  inline void
bitmap_set_all0(struct bitmap * const bm)
{
  memset(bm->bm, 0, bm->nbytes);
  bm->ones = 0;
}
// }}} bitmap

// oalloc {{{
struct oalloc {
  union {
    void * mem;
    void ** ptr;
  };
  size_t blksz;
  size_t curr;
};

  struct oalloc *
oalloc_create(const size_t blksz)
{
  struct oalloc * const o = malloc(sizeof(*o));
  o->mem = malloc(blksz);
  o->blksz = blksz;
  *(o->ptr) = NULL;
  o->curr = sizeof(void *);
  return o;
}

  void *
oalloc_alloc(struct oalloc * const o, const size_t size)
{
  if ((o->curr + size) <= o->blksz) {
    void * ret = ((u8 *)o->mem) + o->curr;
    o->curr += size;
    return ret;
  }

  // too large
  if ((size + sizeof(void *)) > o->blksz)
    return NULL;

  // need more core
  void ** const newmem = malloc(o->blksz);
  *newmem = o->mem;
  o->ptr = newmem;
  o->curr = sizeof(void *);
  return oalloc_alloc(o, size);
}

  void
oalloc_clean(struct oalloc * const o)
{
  void * iter = *(o->ptr);
  *(o->ptr) = NULL;

  while (iter) {
    void * const next = *(void **)iter;
    free(iter);
    iter = next;
  }
}

  void
oalloc_destroy(struct oalloc * const o)
{
  while (o->mem) {
    void * const next = *(o->ptr);
    free(o->mem);
    o->mem = next;
  }
  free(o);
}
// }}} oalloc

// string {{{
  inline u64
a2u64(const void * const str)
{
  return strtoull(str, NULL, 10);
}

  inline u32
a2u32(const void * const str)
{
  return (u32)strtoull(str, NULL, 10);
}
// }}} string

// vim:fdm=marker

