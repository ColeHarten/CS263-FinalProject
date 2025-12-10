# Testing

Using `hyperfine` to compare runtime / memory overhead for baseline vs instrumented versions of different test files.

I first installed `wget` in the container with `apg-get`, then installed `hyperfine`.

Currently, we run 2 tests:

## Test 1: Basic Execution Time and Memory Overhead

## Test 2: Runtime Overhead as we scale number of tainted variables

The test file is `test_scaling.c`. We run the following command to generate the statistics:

```
hyperfine --parameter-scan n 20 100 -D 20 "./test_scaling_baseline {n}" "./test_scaling_instrumented {n}" --export-json scaling_results_2.json --export-csv scaling_results_2.csv
```

This runs each version of the test binaries (baseline and instrumented) with n blocks, for n in {20, 40, 60, 80, 100}. Each block is a function of the form:

```
void taint_block_##i(void) {                             \
        sensitive int secret_##i = 0xfeed0000 ^ (i);         \
        int copy_##i       = secret_##i;                     \
        int arithmetic_##i = secret_##i + 100;               \
        int multi_##i      = (secret_##i * 2) - 50;          \
        int boolean_##i    = (secret_##i > 1000) ? 1 : 0;    \
        int result1_##i    = add_one(secret_##i);            \
        int result2_##i    = add_one(copy_##i);              \
        int result3_##i    = compute(secret_##i, 5);         \
        int result4_##i    = nested_compute(secret_##i);     \
        int mixed1_##i     = add_one(arithmetic_##i);        \
        int mixed2_##i     = mixed1_##i * 3;                 \
        int mixed3_##i     = compute(mixed2_##i, result1_##i); \
        volatile int sink = 0;                               \
        sink ^= copy_##i ^ arithmetic_##i ^ multi_##i;       \
        sink ^= boolean_##i ^ result1_##i ^ result2_##i;     \
        sink ^= result3_##i ^ result4_##i;                   \
        sink ^= mixed1_##i ^ mixed2_##i ^ mixed3_##i;        \
        (void)sink;                                          \
    }
```


### To-do:
- Generate graph for test 2 for runtime
- Generate graphs for the memory overhead of both tests

Note: `plot_benchmark_comparison.py` is a script from the `hyperfine` repo for processing a `json` file produced by a benchmark run. It was used to generate `plot_benchmark.png`, which shows the runtime comparison of test_baseline vs test_instrumented.