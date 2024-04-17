# DecentSched

This repository contains the implementation of DecentSched as a ready-to-use user-level library.
The detailed design is introduced in our paper, "Fast Abort-Freedom for Deterministic Transactions"
on IPDPS '24.

[[Paper PDF](https://www.roychan.org/assets/publications/ipdps24chen.pdf)]

DecentSched is a concurrency control protocol for deterministic transactions (i.e., transactions
with known read/write key set before execution). It utilizes queue-based ordering and decentralized
scheduling to let transactions execute efficiently. It provides serializable isolation between
concurrent transactions.

In the implementation, `qcc` is the name of the protocol across all repositories.

## Example

In the repository, `test_qcc.c` demonstrates the basic usage of DecentSched. To compile it,
the repository already contains a `Makefile` so you can just run `make` to compile it.

The compiled `test_qcc.out` program simulates a single-table database where each row is a number.
It spawns multiple worker threads. Each thread randomly reads or writes multiple numbers and all
accesses are wrapped in a transaction. The thread will execute multiple such transactions, and
finally the results are validated against the correct ones.

The program accepts two arguments:

```
./test_qcc.out <nr_workers> <nr_rows>
```

where `nr_workers` specifies the total number of threads and `nr_rows` is the total number of
rows (numbers) in the data store.

The test program also supports a `TEST_ENHANCED_CONCURRENCY` flag, which enables opportunistic
execution of transactions. It can be set to test its functionality.

## API

For complete API and function signatures, you can refer to `qcc.h` file. Here we document the usage
of core functions in the library.

| Function | Usage |
| --- | --- |
| `qcc_create` | Create a `struct qcc` which records all the metadata of the concurrency control. The struct is useful for core function calls. |
| `qcc_ready` | Called by a worker thread to synchronize after all thread-local preparation works are done. |
| `qcc_acquire` | Called by a worker thread to acquire a new empty transaction. |
| `qcc_txn_enqueue` | Called by a worker thread to enqueue the queuing entries for all accesses. |
| `qcc_txn_wait` | Blocking the worker thread until its current transaction can execute according to the global schedule. |
| `qcc_txn_finish` | Marking the current transaction as finished after execution (commit). |
| `qcc_sync` | Synchronizing all worker threads on a global barrier. Used interally for epoch-based memory management. |
| `qcc_snapshot_*` | Taking a version number snapshot of all accessed items (for opportunistic execution). |
