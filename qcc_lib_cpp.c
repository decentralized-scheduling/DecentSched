#ifdef __cplusplus

#include "qcc_lib_cpp.h"

// timing {{{
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

  void
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
  struct oalloc * const o = (typeof(o))aligned_alloc(64, sizeof(*o));
  o->mem = aligned_alloc(64, blksz);
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
  void ** const newmem = (typeof(newmem))aligned_alloc(64, o->blksz);
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
  void ** const mem = (typeof(mem))malloc(size1 + size2);
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

// locking {{{

// spinlock {{{
#if defined(__linux__)
#define SPINLOCK_PTHREAD
#endif // __linux__

#if defined(SPINLOCK_PTHREAD)
static_assert(sizeof(pthread_spinlock_t) <= sizeof(spinlock), "spinlock size");
#else // SPINLOCK_PTHREAD
static_assert(sizeof(au32) <= sizeof(spinlock), "spinlock size");
#endif // SPINLOCK_PTHREAD

  void
spinlock_init(spinlock * const lock)
{
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_init(p, PTHREAD_PROCESS_PRIVATE);
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  atomic_store_explicit(p, 0, MO_RELEASE);
#endif // SPINLOCK_PTHREAD
}

  inline void
spinlock_lock(spinlock * const lock)
{
#if defined(CORR)
  while (!spinlock_trylock(lock))
    corr_yield();
#else // CORR
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_lock(p); // return value ignored
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  do {
    if (atomic_fetch_sub_explicit(p, 1, MO_ACQUIRE) == 0)
      return;
    do {
      cpu_pause();
    } while (atomic_load_explicit(p, MO_CONSUME));
  } while (true);
#endif // SPINLOCK_PTHREAD
#endif // CORR
}

  inline bool
spinlock_trylock(spinlock * const lock)
{
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  return !pthread_spin_trylock(p);
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  return atomic_fetch_sub_explicit(p, 1, MO_ACQUIRE) == 0;
#endif // SPINLOCK_PTHREAD
}

  inline void
spinlock_unlock(spinlock * const lock)
{
#if defined(SPINLOCK_PTHREAD)
  pthread_spinlock_t * const p = (typeof(p))lock;
  pthread_spin_unlock(p); // return value ignored
#else // SPINLOCK_PTHREAD
  au32 * const p = (typeof(p))lock;
  atomic_store_explicit(p, 0, MO_RELEASE);
#endif // SPINLOCK_PTHREAD
}
// }}} spinlock

// pthread mutex {{{
static_assert(sizeof(pthread_mutex_t) <= sizeof(mutex), "mutexlock size");
  inline void
mutex_init(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_init(p, NULL);
}

  inline void
mutex_lock(mutex * const lock)
{
#if defined(CORR)
  while (!mutex_trylock(lock))
    corr_yield();
#else
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_lock(p); // return value ignored
#endif
}

  inline bool
mutex_trylock(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  return !pthread_mutex_trylock(p); // return value ignored
}

  inline void
mutex_unlock(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_unlock(p); // return value ignored
}

  inline void
mutex_deinit(mutex * const lock)
{
  pthread_mutex_t * const p = (typeof(p))lock;
  pthread_mutex_destroy(p);
}
// }}} pthread mutex

// rwdep {{{
// poor man's lockdep for rwlock
// per-thread lock list
// it calls debug_die() when local double-(un)locking is detected
// cyclic dependencies can be manually identified by looking at the two lists below in gdb
#ifdef RWDEP
#define RWDEP_NR ((16))
__thread const rwlock * rwdep_readers[RWDEP_NR] = {};
__thread const rwlock * rwdep_writers[RWDEP_NR] = {};

  static void
rwdep_check(const rwlock * const lock)
{
  debug_assert(lock);
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_readers[i] == lock)
      debug_die();
    if (rwdep_writers[i] == lock)
      debug_die();
  }
}
#endif // RWDEP

  static void
rwdep_lock_read(const rwlock * const lock)
{
#ifdef RWDEP
  rwdep_check(lock);
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_readers[i] == NULL) {
      rwdep_readers[i] = lock;
      return;
    }
  }
#else
  (void)lock;
#endif // RWDEP
}

  static void
rwdep_unlock_read(const rwlock * const lock)
{
#ifdef RWDEP
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_readers[i] == lock) {
      rwdep_readers[i] = NULL;
      return;
    }
  }
  debug_die();
#else
  (void)lock;
#endif // RWDEP
}

  static void
rwdep_lock_write(const rwlock * const lock)
{
#ifdef RWDEP
  rwdep_check(lock);
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_writers[i] == NULL) {
      rwdep_writers[i] = lock;
      return;
    }
  }
#else
  (void)lock;
#endif // RWDEP
}

  static void
rwdep_unlock_write(const rwlock * const lock)
{
#ifdef RWDEP
  for (u64 i = 0; i < RWDEP_NR; i++) {
    if (rwdep_writers[i] == lock) {
      rwdep_writers[i] = NULL;
      return;
    }
  }
  debug_die();
#else
  (void)lock;
#endif // RWDEP
}
// }}} rwlockdep

// rwlock {{{
typedef au32 lock_t;
typedef u32 lock_v;
static_assert(sizeof(lock_t) == sizeof(lock_v), "lock size");
static_assert(sizeof(lock_t) <= sizeof(rwlock), "lock size");

#define RWLOCK_WSHIFT ((sizeof(lock_t) * 8 - 1))
#define RWLOCK_WBIT ((((lock_v)1) << RWLOCK_WSHIFT))

  void
rwlock_init(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_store_explicit(pvar, 0, MO_RELEASE);
}

  inline bool
rwlock_trylock_read(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if ((atomic_fetch_add_explicit(pvar, 1, MO_ACQUIRE) >> RWLOCK_WSHIFT) == 0) {
    rwdep_lock_read(lock);
    return true;
  } else {
    atomic_fetch_sub_explicit(pvar, 1, MO_RELAXED);
    return false;
  }
}

  inline bool
rwlock_trylock_read_lp(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if (atomic_load_explicit(pvar, MO_CONSUME) >> RWLOCK_WSHIFT) {
    cpu_pause();
    return false;
  }
  return rwlock_trylock_read(lock);
}

// actually nr + 1
  inline bool
rwlock_trylock_read_nr(rwlock * const lock, u16 nr)
{
  lock_t * const pvar = (typeof(pvar))lock;
  if ((atomic_fetch_add_explicit(pvar, 1, MO_ACQUIRE) >> RWLOCK_WSHIFT) == 0) {
    rwdep_lock_read(lock);
    return true;
  }

  do { // someone already locked; wait for a little while
    cpu_pause();
    if ((atomic_load_explicit(pvar, MO_CONSUME) >> RWLOCK_WSHIFT) == 0) {
      rwdep_lock_read(lock);
      return true;
    }
  } while (nr--);

  atomic_fetch_sub_explicit(pvar, 1, MO_RELAXED);
  return false;
}

  void
rwlock_lock_read(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  do {
    if (rwlock_trylock_read(lock))
      return;
    do {
#if defined(CORR)
      corr_yield();
#else
      cpu_pause();
#endif
    } while (atomic_load_explicit(pvar, MO_CONSUME) >> RWLOCK_WSHIFT);
  } while (true);
}

  void
rwlock_unlock_read(rwlock * const lock)
{
  rwdep_unlock_read(lock);
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_fetch_sub_explicit(pvar, 1, MO_RELEASE);
}

  inline bool
rwlock_trylock_write(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  lock_v v0 = atomic_load_explicit(pvar, MO_CONSUME);
  if ((v0 == 0) && atomic_compare_exchange_weak_explicit(pvar, &v0, RWLOCK_WBIT, MO_ACQUIRE, MO_RELAXED)) {
    rwdep_lock_write(lock);
    return true;
  } else {
    return false;
  }
}

// actually nr + 1
  inline bool
rwlock_trylock_write_nr(rwlock * const lock, u16 nr)
{
  do {
    if (rwlock_trylock_write(lock))
      return true;
    cpu_pause();
  } while (nr--);
  return false;
}

  inline void
rwlock_lock_write(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  do {
    if (rwlock_trylock_write(lock))
      return;
    do {
#if defined(CORR)
      corr_yield();
#else
      cpu_pause();
#endif
    } while (atomic_load_explicit(pvar, MO_CONSUME));
  } while (true);
}

  inline bool
rwlock_trylock_write_hp(rwlock * const lock)
{
  lock_t * const pvar = (typeof(pvar))lock;
  lock_v v0 = atomic_load_explicit(pvar, MO_CONSUME);
  if (v0 >> RWLOCK_WSHIFT)
    return false;

  if (atomic_compare_exchange_weak_explicit(pvar, &v0, v0|RWLOCK_WBIT, MO_ACQUIRE, MO_RELAXED)) {
    rwdep_lock_write(lock);
    // WBIT successfully marked; must wait for readers to leave
    if (v0) { // saw active readers
      while (atomic_load_explicit(pvar, MO_CONSUME) != RWLOCK_WBIT) {
#if defined(CORR)
        corr_yield();
#else
        cpu_pause();
#endif
      }
    }
    return true;
  } else {
    return false;
  }
}

  inline bool
rwlock_trylock_write_hp_nr(rwlock * const lock, u16 nr)
{
  do {
    if (rwlock_trylock_write_hp(lock))
      return true;
    cpu_pause();
  } while (nr--);
  return false;
}

  void
rwlock_lock_write_hp(rwlock * const lock)
{
  while (!rwlock_trylock_write_hp(lock)) {
#if defined(CORR)
    corr_yield();
#else
    cpu_pause();
#endif
  }
}

  void
rwlock_unlock_write(rwlock * const lock)
{
  rwdep_unlock_write(lock);
  lock_t * const pvar = (typeof(pvar))lock;
  atomic_fetch_sub_explicit(pvar, RWLOCK_WBIT, MO_RELEASE);
}

  inline void
rwlock_write_to_read(rwlock * const lock)
{
  rwdep_unlock_write(lock);
  rwdep_lock_read(lock);
  lock_t * const pvar = (typeof(pvar))lock;
  // +R -W
  atomic_fetch_add_explicit(pvar, ((lock_v)1) - RWLOCK_WBIT, MO_ACQ_REL);
}

#undef RWLOCK_WSHIFT
#undef RWLOCK_WBIT
// }}} rwlock

// }}} locking

#endif
