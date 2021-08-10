#ifndef _QCC_H
#define _QCC_H

#include <sys/param.h>

#ifndef __cplusplus
#include "c/lib.h"
#include "c/ctypes.h"
#else
#include "qcc_lib_cpp.h"
#endif

#define qcc_likely(____x____)   __builtin_expect(____x____, 1)
#define qcc_unlikely(____x____) __builtin_expect(____x____, 0)

#ifdef QCC_MAX_WORKERS_OVERRIDE
#define QCC_MAX_WORKERS ((QCC_MAX_WORKERS_OVERRIDE + 7) / 8 * 8)
#else
#define QCC_MAX_WORKERS (32u)
#endif

// comment to disable verify
// #define QCC_VERIFY

static_assert(QCC_MAX_WORKERS < (UINT32_MAX >> 1), "don't tease max_workers..");

// epoch
#define QCC_EPOCH_MS (1lu)
#define QCC_EPOCH_NS (QCC_EPOCH_MS * 1000000lu)
#define QCC_EPOCH_SYNC_STEP (10u)

// struct
#define QCC_NR_TXN_PER_EPOCH_BITS (10u) // 1024u txns per epoch per worker
#define QCC_NR_TXN_PER_EPOCH (1u << QCC_NR_TXN_PER_EPOCH_BITS)
#define QCC_NR_QUEUES_BITS (14u) // 16384u queues to map to
#define QCC_NR_QUEUES (1u << QCC_NR_QUEUES_BITS)
#define QCC_NR_QUEUES_MASK (QCC_NR_QUEUES - 1)

static_assert(QCC_NR_TXN_PER_EPOCH * QCC_MAX_WORKERS < (UINT32_MAX), "u32 for txn indexing");
static_assert(QCC_NR_QUEUES < (UINT32_MAX), "u32 for queue indexing");

#ifdef QCC_MAX_ACCESSES_OVERRIDE
#define QCC_MAX_ACCESSES QCC_MAX_ACCESSES_OVERRIDE
#else
#define QCC_MAX_ACCESSES QCC_NR_QUEUES
#endif

// access type
#define QCC_TYPE_RD (0)
#define QCC_TYPE_WR (1)

struct qcc_txn {
    //
    u32 id;
    u32 worker_id;
    u64 padding0[7];
    // the following two arrays are both indexed by worker_id of the corresponding txn
    struct {
        u16 type:16;
        u64 txn: 48;
    } rhs[QCC_MAX_WORKERS];
    // waitlist, volatile because of potential spin-wait
    struct qcc_txn *volatile waitlist[QCC_MAX_WORKERS];
    //
    u32 last_wait;
    u32 padding1[15];
    //
    volatile u8 status; // can be updated by others, but only once
    u8 padding2[63];
    //
    u32 retired_check;
    u32 padding3[15];
};

static_assert(sizeof(struct qcc_txn) % 64 == 0, "cache line aligned qcc_txn struct");

struct qcc_rvec {
    u64 rid; // row id
    u16 type; // access type
    // --- filled by _converge
    u32 qid; // assigned queue id
    u8 qv; // queue version
};

struct qcc_qvec {
    u32 qid; // queue id
    u16 type; // access type
};

struct qcc {
    //
    u32 nr_workers;
    au32 nr_finished;
    u64 padding0[7];
    //
    au64 epoch;
    u64 padding1[7];
    //
    struct qcc_mqueue *mq;
    u64 padding2[7];
    //
    struct qcc_txn *txns;
    u64 padding3[7];
    //
    struct {
        u64 ts;
        u32 try_cnt;
        u32 seq;
        u32 *footprint;
    } __attribute__((aligned(64))) worker_privs[QCC_MAX_WORKERS];
    //
    struct {
        u8 v;
#ifdef QCC_VERIFY
        pthread_spinlock_t spinlock;
#endif
    } __attribute__((aligned(64))) qvs[QCC_NR_QUEUES];
}__attribute__((aligned(64)));

extern struct qcc *qcc_create(const u32 nr_workers);

extern void qcc_ready(struct qcc *const q, const u32 worker_id);

extern void qcc_destroy(struct qcc *const q);

extern struct qcc_txn *qcc_txn_acquire(struct qcc *const q, const u32 worker_id);

extern void qcc_txn_enqueue(
        const struct qcc *const q, struct qcc_txn *const txn,
        struct qcc_rvec *const rows, const u64 nr_rows, struct qcc_qvec *const queues, u32 *const nr_queues);

extern void qcc_txn_snapshot(
        const struct qcc *const q, struct qcc_txn *const txn, struct qcc_rvec *const rows, const u64 nr_rows);

extern u8 qcc_txn_snapshot_consistent(
        const struct qcc *const q, struct qcc_txn *const txn, struct qcc_rvec *const rows, const u64 nr_rows,
        const u64 nr_finished);

extern u8 qcc_txn_snapshot_update(
        const struct qcc *const q, struct qcc_txn *const txn, struct qcc_rvec *const rows, const u64 nr_rows,
        const u64 nr_finished);

extern u8 qcc_txn_try_wait(const struct qcc *const q, struct qcc_txn *const txn);

extern void qcc_txn_wait(const struct qcc *const q, struct qcc_txn *const txn);

extern void qcc_txn_finish(
        struct qcc *const q, struct qcc_txn *const txn, struct qcc_qvec *const queues, const u32 nr_queues);

extern void qcc_sync(struct qcc *const q, const u32 worker_id);

extern void qcc_sync_force(struct qcc *const q, const u32 worker_id);

extern void qcc_finish(struct qcc *const q, const u32 worker_id);

#endif
