#!/usr/bin/env python
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "matplotlib",
#     "pyqt6",
#     "numpy",
# ]
# ///

# Usage:
# python plot_benchmark_runtime.py benchmark1.json benchmark2.json --benchmark-names "Test 1" "Test 2" --title "Runtime Benchmark" -o runtime_plot.png

"""
This script shows `hyperfine` benchmark results as a bar plot grouped by number of blocks.
Note all the input files must contain results for all commands.
"""

import argparse
import json
import pathlib

import matplotlib.pyplot as plt
import numpy as np

# Parse command-line arguments
# Usage:
# python plot_benchmark_runtime.py benchmark1.json benchmark2.json --benchmark-names "Test 1" "Test 2" --title "Runtime Benchmark" -o runtime_plot.png

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "files", nargs="+", type=pathlib.Path, help="JSON files with benchmark results"
)
parser.add_argument("--title", help="Plot Title", default="Benchmark Comparison")
parser.add_argument(
    "--benchmark-names", nargs="+", help="Names of the benchmark groups"
)
parser.add_argument("-o", "--output", help="Save image to the given filename", default="plot_benchmark.png")

args = parser.parse_args()

commands = None
datasets = []
inputs = []

if args.benchmark_names:
    assert len(args.files) == len(
        args.benchmark_names
    ), "Number of benchmark names must match the number of input files."

for i, filename in enumerate(args.files):
    datasets.append([])
    with open(filename) as f:
        results = json.load(f)["results"]

    print(f"Results from {filename}:")
    
    datasets[-1].extend([round(b["mean"], 6) for b in results])
    print(datasets[-1])
    # benchmark_commands = [b["command"] for b in results]
    # if commands is None:
    #     commands = benchmark_commands
    # else:
    #     assert (
    #         commands == benchmark_commands
    #     ), f"Unexpected commands in {filename}: {benchmark_commands}, expected: {commands}"

    # if args.benchmark_names:
    #     inputs.append(args.benchmark_names[i])
    # else:
    #     inputs.append(filename.stem)

# for i in range(len(datasets)):
#     datasets[i] = np.array(datasets[i])

categories= ['20', '40', '60', '80', '100']
width = 0.25
x = np.arange(len(categories))

# 3. Create the plot
fig, ax = plt.subplots(figsize=(10, 6), constrained_layout=True)

# Plot the first set of bars, shifted left by half the width
rects1 = ax.bar(x - width/2, datasets[0], width, label='Baseline')

# Plot the second set of bars, shifted right by half the width
rects2 = ax.bar(x + width/2, datasets[1], width, alpha=0.5, label='Instrumented')

# Add labels, title, and legend
ax.set_xticks(x, categories)
ax.grid(visible=True, axis="y")
# ax.set_ylim(0, max(max(datasets[0]), max(datasets[1])) * 1.1)  # Set y-axis limit for better visibility
ax.set_title('Runtime Comparison Between Baseline and Instrumented Binaries')
ax.set_xlabel('Number of Blocks')
ax.set_ylabel('Runtime [s]')
ax.legend(loc='lower right')

# Display the plot
ax.bar_label(rects1, padding=3)
ax.bar_label(rects2, padding=3)

if args.output:
    plt.savefig(args.output)
else:
    plt.show()