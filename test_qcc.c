#include "qcc.h"

#define TIMES (100000lu)
#define MAX_OPS (100lu)

// #define TEST_ENHANCED_CONCURRENCY

#ifdef TEST_ENHANCED_CONCURRENCY
static au64 total_discard = 0;
#endif

#define TEST_MAX_NR_QUEUES (100000)

static au64 committed = 0;

pthread_barrier_t start_barrier;

struct test_worker_ctx {
    u32 worker_id;
    struct qcc *q;
    u64 nr_rows;
    u64  *rows;
    au64 *arows; // for correctness
};

static void *test_worker(void *const octx)
{
    const struct test_worker_ctx *const ctx = octx;

    const u32 worker_id = ctx->worker_id;

    thread_pin(worker_id);

    struct qcc *const q = ctx->q;
    qcc_ready(q, worker_id);

    const u64 nr_rows = ctx->nr_rows;
    u64 *const rows = ctx->rows;
    au64 *const arows = ctx->arows;

    u64 *const local_rows = calloc(nr_rows, sizeof(local_rows[0]));

    const u64 seed = (u64)time(NULL);
    srandom_u64(seed);

    u64 nr_txns = 0;

#ifdef TEST_ENHANCED_CONCURRENCY
    u64 discard = 0;
#endif

    pthread_barrier_wait(&start_barrier);

    for (u64 i=0; i<TIMES; i++) {
        // step 0: init and allocation
        struct qcc_txn *const txn = qcc_txn_acquire(q, worker_id);
        debug_assert(txn);

        struct qcc_rvec t_rows[MAX_OPS];
        struct qcc_qvec t_queues[MAX_OPS];

        u64 copy[MAX_OPS];

        const u64 rand_nr_ops = random_u64() % (nr_rows - 1) + 1;
        const u64 nr_ops = rand_nr_ops > MAX_OPS ? MAX_OPS : rand_nr_ops; // [1, nr_rows - 1], at most 100
        const u64 start = random_u64() % (nr_rows - nr_ops + 1);
        for (u64 j=0; j<nr_ops; j++) {
            const u64 update = random_u64() & 0x1;
            const u64 rid = start + nr_ops - j - 1;
            debug_assert(rid < nr_rows);
            t_rows[j].rid = rid;
            if (update) {
                t_rows[j].type = QCC_TYPE_WR;
                local_rows[rid]++;
            } else {
                t_rows[j].type = QCC_TYPE_RD;
            }
        } // all rids are unique.. but continuous

        u32 nr_queues = 0;
        qcc_txn_enqueue(q, txn, &t_rows[0], nr_ops, &t_queues[0], &nr_queues);

#ifdef TEST_ENHANCED_CONCURRENCY
        u8 try_once = 0;
        while (!try_once || !qcc_txn_try_wait(q, txn)) {
            if (try_once && qcc_txn_snapshot_consistent(q, txn, &t_rows[0], nr_ops, nr_ops)) {
                continue;
            }
            qcc_txn_snapshot(q, txn, &t_rows[0], nr_ops);
            for (u64 j=0; j<nr_ops; j++) {
                copy[j] = rows[t_rows[j].rid];
                if (t_rows[j].type == QCC_TYPE_WR) {
                    copy[j]++;
                }
            }
            try_once = 1;
        }

        qcc_txn_wait(q, txn);

        // if inconsistent, redo again locally.
        if (!qcc_txn_snapshot_consistent(q, txn, &t_rows[0], nr_ops, nr_ops) || !try_once) {
            discard++;
            for (u64 j=0; j<nr_ops; j++) {
                copy[j] = rows[t_rows[j].rid];
                if (t_rows[j].type == QCC_TYPE_WR) {
                    copy[j]++;
                }
            }
        }

#else
        // the real barrier
        qcc_txn_wait(q, txn);

        // run!
        // first read to local
        for (u64 j=0; j<nr_ops; j++) {
            copy[j] = rows[t_rows[j].rid];
            if (t_rows[j].type == QCC_TYPE_WR) {
                copy[j]++;
            }
        }
#endif
        // write back
        for (u64 j=0; j<nr_ops; j++) {
            // for each in writeset..
            if (t_rows[j].type == QCC_TYPE_WR) {
                rows[t_rows[j].rid] = copy[j];
            }
        }

        qcc_txn_finish(q, txn, &t_queues[0], nr_queues);
        committed++;
        nr_txns++;
    }

    qcc_finish(q, worker_id);

    // add local ops to verify correctness
    for (u64 i=0; i<nr_rows; i++) {
        arows[i] += local_rows[i];
    }

    free(local_rows);

#ifdef TEST_ENHANCED_CONCURRENCY
    total_discard += discard;
#endif

    return NULL;
    (void)nr_txns;
}

static void test_verify(const u64 *const rows, const au64 *const arows, const u64 nr_rows)
{
    u8 correct = 1;
    for (u64 i=0; i<nr_rows; i++) {
        if (rows[i] != arows[i]) {
            printf("row %lu value %lu wrong, should be %lu\n", i, rows[i], arows[i]);
            correct = 0;
        }
    }

    if (correct) {
        printf("\033[0;32m[results correct]\033[0m ");
    } else {
        printf("\033[0;31m[results wrong]\033[0m   ");
        debug_die();
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        printf("usage: ./test_qcc.out <nr_workers> <nr_rows>\n");
        return -1;
    }

    const u32 nr_workers = a2u32(argv[1]);
    const u64 nr_rows = a2u64(argv[2]);

    if (nr_workers > QCC_MAX_WORKERS) {
        return -1;
    }

    // init rows
    u64 *const rows = calloc(nr_rows, sizeof(rows[0]));
    au64 *const arows = calloc(nr_rows, sizeof(arows[0]));

    // init qcc
    struct qcc *const q = qcc_create(nr_workers);
    debug_assert(q);

    // init barrier
    pthread_barrier_init(&start_barrier, NULL, nr_workers + 1);

    // exec
    pthread_t *const threads = calloc(nr_workers, sizeof(*threads));
    struct test_worker_ctx *const ctxs = calloc(nr_workers, sizeof(*ctxs));
    for (u32 i=0; i<nr_workers; i++) {
        ctxs[i] = (struct test_worker_ctx)
                  {.worker_id = i, .q = q, .nr_rows = nr_rows, .rows = rows, .arows = arows};
        pthread_create(&threads[i], NULL, test_worker, (void *)(&ctxs[i]));
    }

    pthread_barrier_wait(&start_barrier);
    u64 t = time_nsec();

    // end
    for (u32 i=0; i<nr_workers; i++) {
        pthread_join(threads[i], NULL);
    }
    t = time_diff_nsec(t);

    test_verify(rows, arows, nr_rows);

#ifdef TEST_ENHANCED_CONCURRENCY
    printf("%lf mops/sec (nr_workers %u total txns %lu total_discard %lu)\n",
            (double)1e3*committed/(double)t, nr_workers, committed, total_discard);
#else
    printf("%lf mops/sec (nr_workers %u total txns %lu)\n", (double)1e3*committed/(double)t, nr_workers, committed);
#endif

    qcc_destroy(q);
    free(rows);
    free(arows);

    free(threads);
    free(ctxs);

    return 0;
}

