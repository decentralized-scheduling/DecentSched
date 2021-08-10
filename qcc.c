#include "qcc.h"

#define CLSZ (64u)

static inline void *clalloc(size_t size) {
    size_t sz = (size / CLSZ + 1) * CLSZ;
    void *const ret = aligned_alloc(CLSZ, sz);
    memset(ret, 0, sz);
    return ret;
}

// {{{ queue

struct qcc_mqueue_entry {
    struct {
        u16 type:16;
        u64 next:48; // ptr
    };
    struct qcc_txn *txn;
};

#define QCC_MQUEUE_ALLOC_SIZE (QCC_MAX_ACCESSES * QCC_NR_TXN_PER_EPOCH * sizeof(struct qcc_mqueue_entry))

static_assert(sizeof(struct qcc_mqueue_entry) == 16, "sizeof(struct qcc_mqueue_entry)");

// head.ptr -> entry -> entry -> ...
struct qcc_mqueue_head {
    au64 ptr;
} __attribute__((aligned(64)));

// { head, head, head, ... } each queue head takes one cacheline
struct qcc_mqueue {
    //
    u32 nr_workers;
    u64 padding0[7];
    //
    au64 epoch;
    u64 padding1[7];
    //
    struct {
        u8 mem[QCC_MQUEUE_ALLOC_SIZE];
        u8 *ptr;
    } __attribute__((aligned(64))) mp[QCC_MAX_WORKERS];
    //
    struct qcc_mqueue_head heads[QCC_NR_QUEUES];
} __attribute__((aligned(64)));

// mqueue does not manage the alloc and free of individual entries
static struct qcc_mqueue *qcc_mqueue_create(const u32 nr_workers)
{
    if (nr_workers > QCC_MAX_WORKERS) {
        return NULL;
    }
    struct qcc_mqueue *const mq = (struct qcc_mqueue *)clalloc(sizeof(*mq));
    debug_assert(mq);
    memset(mq, 0, sizeof(*mq));
    mq->nr_workers = nr_workers;
    for (u32 i=0; i<nr_workers; i++) {
        mq->mp[i].ptr = &mq->mp[i].mem[0];
    }
    return mq;
}

// only call this when all the entries are freed
static void qcc_mqueue_destroy(struct qcc_mqueue *const mq)
{
    free(mq);
}

static inline struct qcc_mqueue_entry *qcc_mqueue_alloc(
        struct qcc_mqueue *const mq, const u32 worker_id, const u32 nr_entries)
{
    const u64 sz = nr_entries * sizeof(struct qcc_mqueue_entry);
    struct qcc_mqueue_entry *const ret = (struct qcc_mqueue_entry *)(mq->mp[worker_id].ptr);
    mq->mp[worker_id].ptr = (u8 *)(mq->mp[worker_id].ptr) + sz;
    return ret;
}

static void qcc_mqueue_enqueue(
        struct qcc_mqueue *const mq, struct qcc_mqueue_entry *const entry, const u32 qid)
{
    struct qcc_mqueue_head *const head = &mq->heads[qid];
    do {
        u64 ptr = atomic_load_explicit(&head->ptr, MO_CONSUME);
        entry->next = 0xffffffffffff & (u64)ptr;
        if (atomic_compare_exchange_weak_explicit(&head->ptr, &ptr, (u64)entry, MO_ACQUIRE, MO_RELAXED)) {
            return;
        }
    } while (true);
}

// reset the header of each queue to NULL, then clean local alloc
// note that this function is maintained by epochs.. so every worker should call this function concurrently to
// make progress (or _reset_all?)
static void qcc_mqueue_reset(struct qcc_mqueue *const mq, const u32 worker_id)
{
    const u32 len = QCC_NR_QUEUES / mq->nr_workers;
    const u32 start = worker_id * len;
    const u32 end = (worker_id == mq->nr_workers - 1) ? (QCC_NR_QUEUES) : (start + len);

    memset(&mq->heads[start], 0, (end - start) * sizeof(mq->heads[0]));

    mq->mp[worker_id].ptr = &mq->mp[worker_id].mem[0];
    mq->epoch++;
    while (mq->epoch % mq->nr_workers != 0) {
        // cpu_pause();
    }
}

// }}} queue

// {{{ txn

// txn status
#define QCC_STATUS_NULL      (0)
#define QCC_STATUS_PREPARING (1)
#define QCC_STATUS_QUEUING   (2)
#define QCC_STATUS_FINISHED  (UINT8_MAX >> 1)
#define QCC_STATUS_RETIRED   (UINT8_MAX)

// dep level
#define QCC_RHS_NULL (0)
#define QCC_RHS_SOFT (1)
#define QCC_RHS_HARD (UINT16_MAX)

struct qcc *qcc_create(const u32 nr_workers)
{
    if (nr_workers > QCC_MAX_WORKERS || nr_workers == 0) {
        return NULL;
    }
    struct qcc *const q = (struct qcc *)clalloc(sizeof(*q));
    debug_assert(q);
    memset(q, 0, sizeof(*q));
    q->nr_workers = nr_workers;
    q->nr_finished = 0;
    q->epoch = 0;
    for (u32 i=0; i<QCC_MAX_WORKERS; i++) {
        q->worker_privs[i].ts = 0;
        q->worker_privs[i].try_cnt = 0;
        q->worker_privs[i].seq = 0;
        const u64 fpsize = sizeof(q->worker_privs[0].footprint[0]) * QCC_MAX_WORKERS * QCC_NR_TXN_PER_EPOCH;
        q->worker_privs[i].footprint = (u32 *)clalloc(fpsize);
        debug_assert(q->worker_privs[i].footprint);
        memset(q->worker_privs[i].footprint, 0, fpsize);
    }
    q->mq = qcc_mqueue_create(q->nr_workers);
    q->txns = (struct qcc_txn *)clalloc(sizeof(q->txns[0]) * QCC_NR_TXN_PER_EPOCH * QCC_MAX_WORKERS);
    debug_assert(q->mq && q->txns);
    // these inits are unnecessary because workers can init each txn when acquiring them
    // but this loop will pre-fault all the allocated pages, if nr_txn is large
    for (u32 i=0; i<q->nr_workers*QCC_NR_TXN_PER_EPOCH; i++) {
        struct qcc_txn *const txn = &q->txns[i];
        // some invalid stuff..
        txn->id = UINT32_MAX;
        txn->worker_id = QCC_MAX_WORKERS;
        txn->last_wait = 0;
        txn->retired_check = 0; // xxx..
        txn->status = QCC_STATUS_NULL;
        for (u32 j=0; j<QCC_MAX_WORKERS; j++) {
            txn->rhs[j].type = 0;
            txn->rhs[j].txn = 0;
            txn->waitlist[j] = NULL;
        }
    }
#ifdef QCC_VERIFY
    for (u32 i=0; i<QCC_NR_QUEUES; i++) {
        pthread_spin_init(&q->qvs[i].spinlock, PTHREAD_PROCESS_SHARED);
    }
#endif
    return q;
}

void qcc_ready(struct qcc *const q, const u32 worker_id)
{
    // to do some useless warmup
    // 1. claim the local mp
    volatile u8 buf8;
    for (u64 i=0; i<QCC_MQUEUE_ALLOC_SIZE; i++) {
        buf8 = q->mq->mp[worker_id].mem[i];
    }
    // 2. claim txn structures
    struct qcc_txn buftxn;
    const u64 base = QCC_NR_TXN_PER_EPOCH * worker_id;
    for (u64 i=0; i<QCC_NR_TXN_PER_EPOCH; i++) {
        memcpy(&buftxn, &q->txns[base+i], sizeof(buftxn));
    }
    // 3. claim the local footprint
    volatile u64 buf64;
    for (u64 i=0; i<QCC_MAX_WORKERS*QCC_NR_TXN_PER_EPOCH; i++) {
        buf64 = q->worker_privs[worker_id].footprint[i];
    }
    qcc_sync_force(q, worker_id);
    (void)buf8;
    (void)buf64;
    (void)buftxn;
}

void qcc_destroy(struct qcc *const q)
{
    free(q->txns);
    qcc_mqueue_destroy(q->mq);
    for (u32 i=0; i<QCC_MAX_WORKERS; i++) {
        free(q->worker_privs[i].footprint);
    }
    free(q);
}

// acquire txn by id
struct qcc_txn *qcc_txn_acquire(struct qcc *const q, const u32 worker_id)
{
    if (qcc_unlikely(q->worker_privs[worker_id].seq == QCC_NR_TXN_PER_EPOCH)) {
        // this worker runs too fast and all the slots are used up..
        // so force a barrier here for housekeeping
        qcc_sync_force(q, worker_id);
    } else {
        qcc_sync(q, worker_id);
    }

    const u32 id = worker_id + q->nr_workers * q->worker_privs[worker_id].seq; // scattered id for fairness
    const u32 slot = QCC_NR_TXN_PER_EPOCH * worker_id + q->worker_privs[worker_id].seq; // contiguous slots
    struct qcc_txn *const txn = &q->txns[slot];
    txn->id = id;
    // acquired the txn
    txn->worker_id = worker_id;
    txn->status = QCC_STATUS_PREPARING;
    q->worker_privs[worker_id].seq++;
    return txn;
}

static inline u8 qcc_txn_in_rhs(const struct qcc_txn *const txn, const struct qcc_txn *const txn2, const u32 worker_id)
{
    return (void *)(0xffffffffffff & txn->rhs[worker_id].txn) == (void *)txn2 ? 1 : 0;
}

static inline u8 qcc_txn_in_rhs_hard(
        const struct qcc_txn *const txn, const struct qcc_txn *const txn2, const u32 worker_id)
{
    return (txn->rhs[worker_id].type == QCC_RHS_HARD &&
            (void *)(0xffffffffffff & txn->rhs[worker_id].txn) == (void *)txn2) ? 1 : 0;
}

static inline u8 qcc_txn_waiting(const struct qcc_txn *const txn, const struct qcc_txn *const txn2, const u32 worker_id)
{
    return txn->waitlist[worker_id] == txn2 ? 1 : 0;
}

static u8 qcc_txn_retired(struct qcc_txn *const txn)
{
    const u8 status = txn->status;
    if (qcc_likely(status > QCC_STATUS_FINISHED)) {
        return 1;
    }
    else if (status != QCC_STATUS_FINISHED) {
        return 0;
    }
    u8 retired = 1;
    u32 chk = txn->retired_check;

    while (chk < QCC_MAX_WORKERS) {
        const struct qcc_txn *const txn2 = txn->waitlist[chk];
        if (txn2) {
            if (txn2->status < QCC_STATUS_FINISHED) {
                retired = 0;
                break;
            }
        }
        chk++;
    }
    if (retired) {
        while (chk < 2 * QCC_MAX_WORKERS) {
            const struct qcc_txn *const txn2 =
                (const struct qcc_txn *)(0xffffffffffff & txn->rhs[chk - QCC_MAX_WORKERS].txn);
            if (txn->rhs[chk - QCC_MAX_WORKERS].type == QCC_RHS_SOFT && txn2) {
                if (txn2->status < QCC_STATUS_FINISHED) {
                    retired = 0;
                    break;
                }
            }
            chk++;
        }
    }
    if (retired) {
        txn->status = QCC_STATUS_RETIRED;
    } else if (txn->retired_check < chk) {
        txn->retired_check = chk;
    }
    return retired;
}

static void qcc_txn_rhs_add(struct qcc_txn *const txn, struct qcc_txn *const txn2, const u32 worker_id)
{
    debug_assert(txn->id != txn2->id);
    if (qcc_txn_in_rhs_hard(txn, txn2, worker_id) || txn2->status >= QCC_STATUS_FINISHED) {
        return;
    }
    txn->rhs[worker_id].txn = 0xffffffffffff & (u64)txn2;
    txn->rhs[worker_id].type = QCC_RHS_HARD;
}

static void qcc_txn_rhs_add_soft(struct qcc_txn *const txn, struct qcc_txn *const txn2, const u32 worker_id)
{
    debug_assert(txn->id != txn2->id);
    if (qcc_txn_in_rhs(txn, txn2, worker_id) || txn2->status >= QCC_STATUS_FINISHED) {
        return;
    }
    txn->rhs[worker_id].txn = (u64)txn2;
    txn->rhs[worker_id].txn = 0xffffffffffff & (u64)txn2;
    txn->rhs[worker_id].type = QCC_RHS_SOFT;
}

static inline u8 qcc_txn_test_preparation(const struct qcc_txn *const txn)
{
    if (txn->status > QCC_STATUS_PREPARING) {
        return 1;
    }
    return 0;
}

// static inline void qcc_txn_spin_preparation(const struct qcc_txn *const txn)
// {
//     while (!qcc_txn_test_preparation(txn)) {
//         // cpu_pause();
//     }
// }

static void qcc_txn_collect_rhs(
        struct qcc_txn *const txn, const struct qcc_mqueue_entry *const es, const u32 nr_queues)
{
    for (u32 i=0; i<nr_queues; i++) {
        const struct qcc_mqueue_entry *e = &es[i];
        u8 rd = 0;
        if (e->type == QCC_TYPE_RD) {
            rd = 1;
        }
        while (0xffffffffffff & e->next) {
            e = (const struct qcc_mqueue_entry *)(0xffffffffffff & e->next);
            struct qcc_txn *const txn2 = e->txn;
            debug_assert(txn2->status != QCC_STATUS_NULL);
            if (qcc_txn_retired(txn2)) {
                break;
            }
            const u32 worker_id = txn2->worker_id;
            if (rd && e->type == QCC_TYPE_RD) {
                qcc_txn_rhs_add_soft(txn, txn2, worker_id);
            } else {
                qcc_txn_rhs_add(txn, txn2, worker_id);
            }
        }
    }
}

static u8 qcc_txn_waitlist_add(struct qcc_txn *const txn, struct qcc_txn *const txn2, u32 *const footprint)
{
    const u32 id = txn->id;
    const u32 id2 = txn2->id;
    const u32 worker_id = txn->worker_id;
    const u32 worker_id2 = txn2->worker_id;

    if (qcc_unlikely(footprint[id2] == id + 1)) {
        return 0;
    } else if (qcc_txn_waiting(txn, txn2, worker_id2) || qcc_txn_retired(txn2)) {
        footprint[id2] = id + 1;
        return 0;
    }

    footprint[id2] = id + 1;

    // the second condition seems not necessary because wait_waitlist tests it
    if (txn2->status < QCC_STATUS_FINISHED && qcc_txn_in_rhs_hard(txn2, txn, worker_id)) {
        txn->waitlist[worker_id2] = txn2;
    }

    return 1;
}

static void qcc_txn_waitlist_search_r(struct qcc_txn *const txn, struct qcc_txn *const txn2, u32 *const footprint)
{
    // note: when this function is called, it is guaranteed that `id` txn has complete scanning of its RHS
    if (qcc_txn_waitlist_add(txn, txn2, footprint)) {
        u8 checked[QCC_MAX_WORKERS] = { 0 };
        u32 nr_checked = 0;
        while (nr_checked < QCC_MAX_WORKERS) {
            for (u32 i=0; i<QCC_MAX_WORKERS; i++) {
                if (!checked[i]) {
                    struct qcc_txn *const i_txn = (struct qcc_txn *)(0xffffffffffff & txn2->rhs[i].txn);
                    if (txn2->rhs[i].type == QCC_RHS_HARD && i_txn) {
                        if (qcc_txn_test_preparation(i_txn)) {
                            qcc_txn_waitlist_search_r(txn, i_txn, footprint);
                            checked[i] = 1;
                            nr_checked++;
                        }
                    } else {
                        checked[i] = 1;
                        nr_checked++;
                    }
                }
            }
        }
    }
}

static void qcc_txn_waitlist_search(struct qcc_txn *const txn, u32 *const footprint)
{
    const u32 id = txn->id;

    footprint[id] = id + 1;
    for (u32 i=0; i<QCC_MAX_WORKERS; i++) {
        struct qcc_txn *const rh_txn = (struct qcc_txn *)(0xffffffffffff & txn->rhs[i].txn);
        if (txn->rhs[i].type == QCC_RHS_HARD) {
            txn->waitlist[i] = rh_txn;
            footprint[rh_txn->id] = id + 1;
        }
    }

    u8 checked[QCC_MAX_WORKERS] = { 0 };
    u32 nr_checked = 0;
    while (nr_checked < QCC_MAX_WORKERS) {
        for (u32 i=0; i<QCC_MAX_WORKERS; i++) {
            if (!checked[i]) {
                struct qcc_txn *const rh_txn = (struct qcc_txn *)(0xffffffffffff & txn->rhs[i].txn);
                if (txn->rhs[i].type == QCC_RHS_HARD && rh_txn) { // rhs item exists
                    if (qcc_txn_test_preparation(rh_txn)) {
                        // check all indirect items
                        u8 checked2[QCC_MAX_WORKERS] = { 0 };
                        u32 nr_checked2 = 0;
                        while (nr_checked2 < QCC_MAX_WORKERS) {
                            for (u32 j=0; j<QCC_MAX_WORKERS; j++) {
                                if (!checked2[j]) {
                                    struct qcc_txn *const i_txn =
                                        (struct qcc_txn *)(0xffffffffffff & rh_txn->rhs[j].txn);
                                    if (rh_txn->rhs[j].type == QCC_RHS_HARD && i_txn) {
                                        if (qcc_txn_test_preparation(i_txn)) {
                                            // recursive search
                                            qcc_txn_waitlist_search_r(txn, i_txn, footprint);
                                            checked2[j] = 1;
                                            nr_checked2++;
                                        }
                                    } else {
                                        checked2[j] = 1;
                                        nr_checked2++;
                                    }
                                }
                            }
                        }
                        checked[i] = 1;
                        nr_checked++;
                    }
                } else {
                    checked[i] = 1;
                    nr_checked++;
                }
            }
        }
    }
}

static u8 qcc_txn_wait_waitlist(struct qcc_txn *const txn, const u8 sync)
{
    const u32 start = txn->last_wait;
    const u32 worker_id = txn->worker_id;
    for (u32 i=start; i<QCC_MAX_WORKERS; i++) {
        const struct qcc_txn *const w_txn = txn->waitlist[i];
        if (!w_txn) {
            continue;
        }
        debug_assert(w_txn->status != QCC_STATUS_PREPARING);
        // no intersection
        if (!qcc_txn_in_rhs_hard(txn, w_txn, i) && !qcc_txn_in_rhs_hard(w_txn, txn, worker_id)) {
            // no circular waiting
            continue;
        }

        if (w_txn->id < txn->id) { // wait until commit
            while (w_txn->status < QCC_STATUS_FINISHED) {
                if (sync) {
                    // cpu_pause();
                } else {
                    txn->last_wait = i;
                    return 0;
                }
            }
        } else { // wait until yields.. or commit
            while (w_txn->status < QCC_STATUS_FINISHED && !qcc_txn_waiting(w_txn, txn, worker_id)) {
                if (sync) {
                    // cpu_pause();
                } else {
                    txn->last_wait = i;
                    return 0;
                }
            }
        }
    }
    return 1;
}

static int qcc_compare_qvec(const void *rv1, const void *rv2)
{
    const struct qcc_qvec *const v1 = (const struct qcc_qvec *const)rv1;
    const struct qcc_qvec *const v2 = (const struct qcc_qvec *const)rv2;
    return memcmp(&(v1->qid), &(v2->qid), sizeof(v1->qid));
}

static void qcc_rvec_converge(
        const struct qcc *const q,
        struct qcc_rvec *const rows, const u64 nr_rows, struct qcc_qvec *const queues, u32 *const nr_queues)
{
    // copy rvec to qvec, also hashing
    for (u64 i=0; i<nr_rows; i++) {
        const u32 qid = _mm_crc32_u64(0, rows[i].rid) & QCC_NR_QUEUES_MASK; // h..
        // only touch row's qid and qv, no more (rid and type is filled by user), qv is invalid for now
        rows[i].qid = qid;
        rows[i].qv = UINT8_MAX;
        // then fill the queue entry
        queues[i].qid = qid;
        queues[i].type = rows[i].type;
    }

    // sort queues by qid
    qsort((void *)queues, nr_rows, sizeof(queues[0]), qcc_compare_qvec);

    // dedup, converge..
    u32 idx = 0; // slower
    u32 sidx = 1; // faster

    while (sidx < nr_rows) {
        if (queues[idx].qid == queues[sidx].qid) {
            if (queues[idx].type != queues[sidx].type) {
                queues[idx].type = QCC_TYPE_WR;
            }
        } else {
            idx++;
            queues[idx] = queues[sidx]; // move sidx to the next slot
        }
        sidx++;
    }

    *nr_queues = idx + 1;
    (void)q;
}

 void qcc_txn_enqueue(
        const struct qcc *const q, struct qcc_txn *const txn,
        struct qcc_rvec *const rows, const u64 nr_rows, struct qcc_qvec *const queues, u32 *const nr_queues)
{
    const u32 worker_id = txn->worker_id;
    // rows are ready, generate queues
    qcc_rvec_converge(q, rows, nr_rows, queues, nr_queues);

    // queues are ready, get something..
    const u32 nr_q = *nr_queues;
    struct qcc_mqueue_entry *const es = qcc_mqueue_alloc(q->mq, worker_id, nr_q);
    debug_assert(es);
    for (u32 i=0; i<nr_q; i++) {
        es[i].txn = txn;
        es[i].type = queues[i].type;
        qcc_mqueue_enqueue(q->mq, &es[i], queues[i].qid);
    }
    qcc_txn_collect_rhs(txn, es, nr_q);

    txn->status = QCC_STATUS_QUEUING;
    // discover waitlist
    u32 *const footprint = q->worker_privs[worker_id].footprint;
    qcc_txn_waitlist_search(txn, footprint);
    // done!
}

void qcc_txn_snapshot(
        const struct qcc *const q, struct qcc_txn *const txn, struct qcc_rvec *const rows, const u64 nr_rows)
{
    // set and check version.. return 1 if the new snapshot is the same as the previous one
    for (u64 i=0; i<nr_rows; i++) {
        rows[i].qv = q->qvs[rows[i].qid].v;
    }
    (void)txn;
}

u8 qcc_txn_snapshot_consistent(
        const struct qcc *const q, struct qcc_txn *const txn, struct qcc_rvec *const rows, const u64 nr_rows,
        const u64 nr_finished)
{
    u8 correct = 1;
    const u64 nr = (nr_rows > nr_finished) ? nr_finished : nr_rows;
    for (u64 i=0; i<nr; i++) {
        if (rows[i].qv != q->qvs[rows[i].qid].v) {
            correct = 0;
            break;
        }
    }
    return correct;
    (void)txn;
}

u8 qcc_txn_snapshot_update(
        const struct qcc *const q, struct qcc_txn *const txn, struct qcc_rvec *const rows, const u64 nr_rows,
        const u64 nr_finished)
{
    if (!qcc_txn_snapshot_consistent(q, txn, rows, nr_rows, nr_finished)) {
        return 0;
    }
    for (u64 i=nr_finished; i<nr_rows; i++) {
        rows[i].qv = q->qvs[rows[i].qid].v;
    }
    return 1;
}

u8 qcc_txn_try_wait(const struct qcc *const q, struct qcc_txn *const txn)
{
    // finally wait on the waitlist
    return qcc_txn_wait_waitlist(txn, 0);
    (void)q;
}

void qcc_txn_wait(const struct qcc *const q, struct qcc_txn *const txn)
{
    // finally wait on the waitlist
    u8 r = qcc_txn_wait_waitlist(txn, 1);
    debug_assert(r == 1);
    (void)r;
    (void)q;
}

void qcc_txn_finish(
        struct qcc *const q, struct qcc_txn *const txn, struct qcc_qvec *const queues, const u32 nr_queues)
{
    // increase version by 1:
    for (u32 i=0; i<nr_queues; i++) {
        if (queues[i].type == QCC_TYPE_WR) {
#ifdef QCC_VERIFY
            // a 2PL-like growing phase
            int ret = pthread_spin_trylock(&q->qvs[queues[i].qid].spinlock);
            if (ret == EBUSY) {
                printf("QCC verification fails at growing phase\n");
                fflush(stdout);
                usleep(10000);
            }
#endif
            q->qvs[queues[i].qid].v++;
        }
    }

#ifdef QCC_VERIFY
    for (u32 i=0; i<nr_queues; i++) {
        if (queues[i].type == QCC_TYPE_WR) {
            // a 2PL-like shrinking phase
            pthread_spin_unlock(&q->qvs[queues[i].qid].spinlock);
        }
    }
#endif



    txn->status = QCC_STATUS_FINISHED;

    qcc_txn_retired(txn); // self-eval.. when the cache is warm
}

static void qcc_sync_r(struct qcc *const q, const u32 worker_id, const u8 force)
{
    if (!force && q->worker_privs[worker_id].try_cnt < QCC_EPOCH_SYNC_STEP) {
        q->worker_privs[worker_id].try_cnt++;
        return;
    } else if (!force) {
        q->worker_privs[worker_id].try_cnt = 0;
    }
    if (force || time_diff_nsec(q->worker_privs[worker_id].ts) > QCC_EPOCH_NS) {
        q->epoch++;
        while (q->epoch % q->nr_workers != 0) {
            // cpu_pause();
        }

        // reset visited node map
        const u64 fpsize = sizeof(q->worker_privs[0].footprint[0]) * q->nr_workers * QCC_NR_TXN_PER_EPOCH;
        memset(q->worker_privs[worker_id].footprint, 0, fpsize);

        // reset global txn table
        const u32 start = worker_id * QCC_NR_TXN_PER_EPOCH;
        memset(&q->txns[start], 0, q->worker_privs[worker_id].seq * sizeof(q->txns[0]));

        // barrier, cleanup the mq. internally there is another epoch
        qcc_mqueue_reset(q->mq, worker_id);

        // update the epoch info
        q->worker_privs[worker_id].ts = time_nsec();
        q->worker_privs[worker_id].seq = 0;
    }
}

void qcc_sync(struct qcc *const q, const u32 worker_id)
{
    return qcc_sync_r(q, worker_id, 0);
}

void qcc_sync_force(struct qcc *const q, const u32 worker_id)
{
    return qcc_sync_r(q, worker_id, 1);
}

void qcc_finish(struct qcc *const q, const u32 worker_id)
{
    qcc_sync_force(q, worker_id); // force a barrier.. before report finished

    q->nr_finished++;

    while (q->nr_finished != q->nr_workers) {
        qcc_sync(q, worker_id);
    }

    qcc_sync_force(q, worker_id);
}

// }}} txn
