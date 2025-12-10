# Testing

Using `hyperfine` to compare runtime / memory overhead for baseline vs instrumented versions of different test files.

First, we installed `wget` in the container with `sudo apt install wget`, then installed `hyperfine` with the following:
```
wget https://github.com/sharkdp/hyperfine/releases/download/v1.20.0/hyperfine_1.20.0_amd64.deb
sudo dpkg -i hyperfine_1.20.0_amd64.deb
```

Currently, we run 1 test:

## Test 1: Runtime Overhead as we scale number of tainted variables

The test file is `test_scaling.c`. There are 2 binaries, one that is compiled with `gcc`, and one that is instrumented and compiled with `Sensitaint`.

The source code for `test_scaling.c` contains several function definitions, created using a define block:

```
#define TAINT_BLOCK(i)                                       \
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
followed by another definition that expands 100 of these blocks. Our main function takes in a command line `N`, which is the parameter for how many of those blocks we execute. The resulting binaries can thus be run with command-line arguments, and so we create the benchmark results using `hyperfine` as follows.

1. Generate runtime and memory usage for the baseline binary
```
hyperfine --parameter-scan n 20 100 -D 20 "./test_scaling_baseline {n}" --export-json scaling_baseline_results.json
```

2. Generate runtime and memory usage for the instrumented binary
```
hyperfine --parameter-scan n 20 100 -D 20 "./test_scaling_instrumented {n}" --export-json scaling_instrumented_results.json
```

Each of these commands runs the respective test binaries (baseline and instrumented) with n blocks, for n in {20, 40, 60, 80, 100}.

3. Generate graphs
We built off of `plot_benchmark_comparison.py`, a script from the `hyperfine` repo for processing a `json` file produced by a benchmark run. It was edited to generate `runtime_plot.png` and `memory_overhead_plot.png`, which shows the runtime comparison of test_baseline vs test_instrumented.

```
python3 plot_benchmark_runtime.py scaling_baseline_results.json  scaling_instrumented_results.json --benchmark-names "Baseline" "Instrumented" --title "Runtime Comparison Between Baseline and Instrumented Binaries" -o runtime_plot.png
```

NOTE: The relevant binaries, scripts and results are now stored in `testing_binaries`, `testing_scripts` and `testing_scripts/results` respectively. Future testing should appropriately update paths in scripts to take this change into account.