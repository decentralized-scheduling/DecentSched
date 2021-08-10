/*
 * Copyright (c) 2016--2021  Wu, Xingbo <wuxb45@gmail.com>
 *
 * All rights reserved. No warranty, explicit or implicit, provided.
 */
#pragma once

// includes {{{
// C headers
#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// POSIX headers
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

// Linux headers
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

// SIMD
#if defined(__x86_64__)
#include <x86intrin.h>
#elif defined(__aarch64__)
#include <arm_acle.h>
#include <arm_neon.h>
#endif
// }}} includes

#ifdef __cplusplus
extern "C" {
#endif

// types {{{
#ifndef typeof
#define typeof __typeof__
#endif
#ifndef asm
#define asm __asm__
#endif
typedef char            s8;
typedef short           s16;
typedef int             s32;
typedef long            s64;
typedef __int128_t      s128;
static_assert(sizeof(s8) == 1, "sizeof(s8)");
static_assert(sizeof(s16) == 2, "sizeof(s16)");
static_assert(sizeof(s32) == 4, "sizeof(s32)");
static_assert(sizeof(s64) == 8, "sizeof(s64)");
static_assert(sizeof(s128) == 16, "sizeof(s128)");

typedef unsigned char   u8;
typedef unsigned short  u16;
typedef unsigned int    u32;
typedef unsigned long   u64;
typedef __uint128_t     u128;
static_assert(sizeof(u8) == 1, "sizeof(u8)");
static_assert(sizeof(u16) == 2, "sizeof(u16)");
static_assert(sizeof(u32) == 4, "sizeof(u32)");
static_assert(sizeof(u64) == 8, "sizeof(u64)");
static_assert(sizeof(u128) == 16, "sizeof(u128)");

#if defined(__x86_64__)
typedef __m128i m128;
#if defined(__AVX2__)
typedef __m256i m256;
#endif // __AVX2__
#if defined(__AVX512F__)
typedef __m512i m512;
#endif // __AVX512F__
#elif defined(__aarch64__)
typedef uint8x16_t m128;
#else
#error Need x86_64 or AArch64.
#endif
// }}} types

// defs {{{
#define likely(____x____)   __builtin_expect(____x____, 1)
#define unlikely(____x____) __builtin_expect(____x____, 0)

// ansi colors
// 3X:fg; 4X:bg; 9X:light fg; 10X:light bg;
// X can be one of the following colors:
// 0:black;   1:red;     2:green;  3:yellow;
// 4:blue;    5:magenta; 6:cyan;   7:white;
#define TERMCLR(____code____) "\x1b[" #____code____ "m"
// }}} defs

// const {{{
#define PGBITS ((12))
#define PGSZ ((1lu << PGBITS))
// }}} const

// math {{{
  extern u64
mhash64(const u64 v);

  extern u32
mhash32(const u32 v);

  extern u64
gcd64(u64 a, u64 b);
// }}} math

// random {{{
  extern u64
random_u64(void);

  extern void
srandom_u64(const u64 seed);

  extern double
random_double(void);
// }}} random

// timing {{{
  extern u64
time_nsec(void);

  extern double
time_sec(void);

  extern u64
time_diff_nsec(const u64 last);

  extern double
time_diff_sec(const double last);

  extern void
time_stamp(char * str, const size_t size);

  extern void
time_stamp2(char * str, const size_t size);
// }}} timing

// cpucache {{{
  extern void
cpu_pause(void);

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

// crc32c {{{
  extern u32
crc32c_u8(const u32 crc, const u8 v);

  extern u32
crc32c_u16(const u32 crc, const u16 v);

  extern u32
crc32c_u32(const u32 crc, const u32 v);

  extern u32
crc32c_u64(const u32 crc, const u64 v);

// 1 <= nr <= 3
  extern u32
crc32c_inc_123(const u8 * buf, u32 nr, u32 crc);

// nr % 4 == 0
  extern u32
crc32c_inc_x4(const u8 * buf, u32 nr, u32 crc);

  extern u32
crc32c_inc(const u8 * buf, u32 nr, u32 crc);
// }}} crc32c

// debug {{{
  extern void
debug_break(void);

  extern void
debug_backtrace(void);

  extern void
watch_u64_usr1(u64 * const ptr);

#ifndef NDEBUG
  extern void
debug_assert(const bool v);
#else
#define debug_assert(expr) ((void)0)
#endif

__attribute__((noreturn))
  extern void
debug_die(void);

__attribute__((noreturn))
  extern void
debug_die_perror(void);

  extern void
debug_dump_maps(FILE * const out);

  extern bool
debug_perf_switch(void);
// }}} debug

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

// process/thread {{{
  extern void
thread_get_name(const pthread_t pt, char * const name, const size_t len);

  extern void
thread_set_name(const pthread_t pt, const char * const name);

  extern long
process_get_rss(void);

  extern u32
process_affinity_count(void);

  extern u32
process_getaffinity_list(const u32 max, u32 * const cores);

  extern void
thread_setaffinity_list(const u32 nr, const u32 * const list);

  extern void
thread_pin(const u32 cpu);

  extern u64
process_cpu_time_usec(void);

// if args == true, argx is void **
// if args == false, argx is void *
  extern u64
thread_fork_join(u32 nr, void *(*func) (void *), const bool args, void * const argx);

  extern int
thread_create_at(const u32 cpu, pthread_t * const thread, void *(*start_routine) (void *), void * const arg);
// }}} process/thread

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

// misc {{{
// TODO: only works on little endian?
struct entry13 { // what a beautiful name
  union {
    u16 e1;
    struct { // easy for debugging
      u64 e1_64:16;
      u64 e3:48;
    };
    u64 v64;
    void * ptr;
  };
};

static_assert(sizeof(struct entry13) == 8, "sizeof(entry13) != 8");

// directly access read .e1 and .e3
// directly write .e1
// use entry13_update() to update the entire entry

  extern struct entry13
entry13(const u16 e1, const u64 e3);

  extern void
entry13_update_e3(struct entry13 * const e, const u64 e3);

  extern void *
u64_to_ptr(const u64 v);

  extern u64
ptr_to_u64(const void * const ptr);

  extern size_t
m_usable_size(void * const ptr);

  extern size_t
fdsize(const int fd);

  extern u32
memlcp(const u8 * const p1, const u8 * const p2, const u32 max);

__attribute__ ((format (printf, 2, 3)))
  extern void
logger_printf(const int fd, const char * const fmt, ...);
// }}} misc

// bitmap {{{
struct bitmap;

  extern struct bitmap *
bitmap_create(const u64 nbits);

  extern void
bitmap_init(struct bitmap * const bm, const u64 nbits);

  extern bool
bitmap_test(const struct bitmap * const bm, const u64 idx);

  extern bool
bitmap_test_all1(struct bitmap * const bm);

  extern bool
bitmap_test_all0(struct bitmap * const bm);

  extern void
bitmap_set1(struct bitmap * const bm, const u64 idx);

  extern void
bitmap_set0(struct bitmap * const bm, const u64 idx);

  extern void
bitmap_set1_safe64(struct bitmap * const bm, const u64 idx);

  extern void
bitmap_set0_safe64(struct bitmap * const bm, const u64 idx);

  extern u64
bitmap_count(struct bitmap * const bm);

  extern u64
bitmap_first(struct bitmap * const bm);

  extern void
bitmap_set_all1(struct bitmap * const bm);

  extern void
bitmap_set_all0(struct bitmap * const bm);
// }}} bitmap

// string {{{
  extern u64
a2u64(const void * const str);

  extern u32
a2u32(const void * const str);
// }}} string

#ifdef __cplusplus
}
#endif
// vim:fdm=marker

