#ifdef __cplusplus
#ifndef _QCC_LIB_CPP_H
#define _QCC_LIB_CPP_H

#include <atomic>

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <immintrin.h>
#include <execinfo.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <errno.h>

#define PGSZ ((4096lu))

// {{{ types
#define typeof __typeof__

typedef char            s8;
typedef short           s16;
typedef int             s32;
typedef long            s64;
typedef unsigned char   u8;
typedef unsigned short  u16;
typedef unsigned int    u32;
typedef unsigned long   u64;

typedef std::atomic<bool> abool;
typedef std::atomic<uint8_t>  au8;
typedef std::atomic<uint16_t> au16;
typedef std::atomic<uint32_t> au32;
typedef std::atomic<uint64_t> au64;
typedef std::atomic<int8_t>   as8;
typedef std::atomic<int16_t>  as16;
typedef std::atomic<int32_t>  as32;
typedef std::atomic<int64_t>  as64;

#define MO_RELAXED std::memory_order_relaxed
#define MO_CONSUME std::memory_order_consume
#define MO_ACQUIRE std::memory_order_acquire
#define MO_RELEASE std::memory_order_release
#define MO_ACQ_REL std::memory_order_acq_rel
#define MO_SEQ_CST std::memory_order_seq_cst
// }}} types

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

  extern void
time_stamp(char * str, const size_t size);

  extern void
time_stamp2(char * str, const size_t size);
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

  extern void
cpu_mfence(void);

  extern void
cpu_cfence(void);

  extern void
cpu_prefetch0(const void * const ptr);

  extern void
cpu_prefetch1(const void * const ptr);

  extern void
cpu_prefetch2(const void * const ptr);

  extern void
cpu_prefetch3(const void * const ptr);

  extern void
cpu_prefetchw(const void * const ptr);
// }}} cpucache

// bits {{{
  extern u32
bits_reverse_u32(const u32 v);

  extern u64
bits_reverse_u64(const u64 v);

  extern u64
bits_rotl_u64(const u64 v, const u8 n);

  extern u64
bits_rotr_u64(const u64 v, const u8 n);

  extern u32
bits_rotl_u32(const u32 v, const u8 n);

  extern u32
bits_rotr_u32(const u32 v, const u8 n);

  extern u64
bits_p2_up_u64(const u64 v);

  extern u32
bits_p2_up_u32(const u32 v);

  extern u64
bits_p2_down_u64(const u64 v);

  extern u32
bits_p2_down_u32(const u32 v);

  extern u64
bits_round_up(const u64 v, const u8 power);

  extern u64
bits_round_up_a(const u64 v, const u64 a);

  extern u64
bits_round_down(const u64 v, const u8 power);

  extern u64
bits_round_down_a(const u64 v, const u64 a);
// }}} bits

// oalloc {{{
struct oalloc;

  extern struct oalloc *
oalloc_create(const size_t blksz);

  extern void *
oalloc_alloc(struct oalloc * const o, const size_t size);

  extern void
oalloc_clean(struct oalloc * const o);

  extern void
oalloc_destroy(struct oalloc * const o);
// }}} oalloc

// mm {{{
#ifdef ALLOCFAIL
  extern bool
alloc_fail(void);
#endif

  extern void *
xalloc(const size_t align, const size_t size);

  extern void *
yalloc(const size_t size);

  extern void **
malloc_2d(const size_t nr, const size_t size);

  extern void **
calloc_2d(const size_t nr, const size_t size);

  extern void
pages_unmap(void * const ptr, const size_t size);

  extern void
pages_lock(void * const ptr, const size_t size);

/* hugepages */
// force posix allocators: -DVALGRIND_MEMCHECK
  extern void *
pages_alloc_4kb(const size_t nr_4kb);

  extern void *
pages_alloc_2mb(const size_t nr_2mb);

  extern void *
pages_alloc_1gb(const size_t nr_1gb);

  extern void *
pages_alloc_best(const size_t size, const bool try_1gb, u64 * const size_out);
// }}} mm

// locking {{{
typedef union {
  u32 opaque;
} spinlock;

  extern void
spinlock_init(spinlock * const lock);

  extern void
spinlock_lock(spinlock * const lock);

  extern bool
spinlock_trylock(spinlock * const lock);

  extern void
spinlock_unlock(spinlock * const lock);

typedef union {
  u32 opaque;
} rwlock;

  extern void
rwlock_init(rwlock * const lock);

  extern bool
rwlock_trylock_read(rwlock * const lock);

// low-priority reader-lock; use with trylock_write_hp
  extern bool
rwlock_trylock_read_lp(rwlock * const lock);

  extern bool
rwlock_trylock_read_nr(rwlock * const lock, u16 nr);

  extern void
rwlock_lock_read(rwlock * const lock);

  extern void
rwlock_unlock_read(rwlock * const lock);

  extern bool
rwlock_trylock_write(rwlock * const lock);

  extern bool
rwlock_trylock_write_nr(rwlock * const lock, u16 nr);

  extern void
rwlock_lock_write(rwlock * const lock);

// writer has higher priority; new readers are blocked
  extern bool
rwlock_trylock_write_hp(rwlock * const lock);

  extern bool
rwlock_trylock_write_hp_nr(rwlock * const lock, u16 nr);

  extern void
rwlock_lock_write_hp(rwlock * const lock);

  extern void
rwlock_unlock_write(rwlock * const lock);

  extern void
rwlock_write_to_read(rwlock * const lock);

typedef union {
  u64 opqaue[8];
} mutex;

  extern void
mutex_init(mutex * const lock);

  extern void
mutex_lock(mutex * const lock);

  extern bool
mutex_trylock(mutex * const lock);

  extern void
mutex_unlock(mutex * const lock);

  extern void
mutex_deinit(mutex * const lock);
// }}} locking

#define debug_assert(expr) ((void)0)

#endif
#endif
