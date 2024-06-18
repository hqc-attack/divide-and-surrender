import logging

# Disable debug logs for matplotlib (very verbose)
rootlogger = logging.getLogger()
origlevel = rootlogger.level
rootlogger.setLevel(level="INFO")

# get new logger for this module only
logger = logging.getLogger(__name__)

# Create a console handler and set the level to DEBUG
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Create a formatter and attach it to the handler
formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler.setFormatter(formatter)

# Add the console handler to the logger
logger.addHandler(console_handler)

import matplotlib

matplotlib.use("pgf")
matplotlib.rcParams.update(
    {
        "pgf.texsystem": "lualatex",
        "font.family": "serif",
        "font.serif": ["Computer Modern Roman"],
        "font.sans-serif": ["Computer Modern Sans Serif"],
        "font.monospace": ["Computer Modern Typewriter"],
        "text.usetex": True,
        "pgf.rcfonts": False,
    }
)

import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import os.path
from collections import Counter, defaultdict

sns.set_theme(
    style="darkgrid",
    font="serif",
    rc={
        "legend.frameon": True,
    },
)


def load_data(csv_file):
    logger.info(f"Reading file: {csv_file}")
    df = pd.read_csv(csv_file)
    df["success"] = (
        df["key_bits"] <= df["recovered_zeros_x"] + df["recovered_zeros_y"]
    ) & (0 == df["wrong_zeros_x"] + df["wrong_zeros_y"])
    return df


names = list(
    reversed(
        [
            x
            for x in ["perfect", "ideal", "0.005", "0.05", "0.1", "0.485"]
            if os.path.isfile(f"data/{x}.csv")
        ]
    )
)


def load_all_data():
    dfs = [load_data(f"data/{n}.csv") for n in names]
    for n, df in zip(names, dfs):
        df["mode"] = cat_name(n)
    return pd.concat(dfs)


def cat_name(name):
    n = name
    try:
        n = str(1 - float(n))
    except ValueError:
        n = f"\\mathrm{{{n}}}"
    return f"$\\mathcal{{O}}_{{\\mathrm{{HQC}}}}^{{{n}}}$"


def oracle_calls_boxplots(df):
    cat_names = [cat_name(x) for x in names]
    sns.set(font_scale=2)
    g = sns.catplot(
        data=df[df.success],
        x="queries",
        y="mode",
        orient="h",
        kind="box",
        order=cat_names,
        palette="colorblind",
        aspect=9 / 3,
        hue="mode",
        linewidth=0.1,
        whis=(5, 95),
        fliersize=1,
        # facet_kws={'xlim': (0, max(df.queries))},
    )
    g.set(xscale="log")
    g.set_axis_labels("Oracle calls", "", fontsize=20)
    g.savefig("figures/oracle_calls.pdf", bbox_inches='tight')


def view_hqc_simulation_csv():
    df = load_all_data()
    oracle_calls_boxplots(df)


def timings_with_diff(timings, diff_min=None, diff_max=None):
    if diff_min is not None:
        timings = timings[timings["diff"] >= diff_min]
    if diff_max is not None:
        timings = timings[timings["diff"] <= diff_max]
    return timings


def sd(domain, x, y):
    return 1 / 2 * sum(abs(x[v] - y[v]) for v in domain)


def calculate_success_rate(df, additional_bits):
    return (((df.wrong_zeros_x + df.wrong_zeros_y) == 0) & ((df.recovered_zeros_x + df.recovered_zeros_y) >= (df.key_bits + additional_bits))).mean()

# def sortperm(xs):
#     xs = [(x, i) for (i, x) in enumerate(xs)]
#     xs.sort()
#     return [x[1] for x in xs]

# def applyperm(perm, xs):
#     return [xs[i] for i in perm]

def main():
    additional_bits = []
    additional_bits_dfs = []
    prefix = 'additional_bits_'
    for root, dirs, files in os.walk('data'):
        for file in files:
            if file.startswith(prefix):
                ab = int(file.removeprefix(prefix).removesuffix('.csv'))
                additional_bits.append(ab)
                additional_bits_dfs.append(pd.read_csv(os.path.join(root, file)))
    additional_bits_success_rate = [
        calculate_success_rate(df, additional_bits) for (additional_bits, df) in zip(additional_bits, additional_bits_dfs)
    ]
    queries = [
        df.queries.median() for df in additional_bits_dfs
    ]


    # p = sortperm(additional_bits)
    # additional_bits = applyperm(p, additional_bits)
    # additional_bits_success_rate = applyperm(p, additional_bits_success_rate)
    df = pd.DataFrame({
        'Additional Bits': additional_bits,
        'Success Rate': additional_bits_success_rate,
        "Queries": queries,
    })
    df.sort_values('Additional Bits', inplace=True)
    print(df)

    g = sns.lineplot(df, x="Additional Bits", y="Success Rate", marker='^', label="Success Rate")
    g.grid(False)
    ax2 = plt.twinx()
    ax2.grid(False)
    sns.lineplot(df, x="Additional Bits", y="Queries", color="r", marker='P', ax=ax2, label="Queries")

    lines, labels = g.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax2.legend(lines + lines2, labels + labels2, loc='right')
    g.get_legend().remove()

    # g.set_xscale('log')
    g.figure.savefig("figures/additional_bits_success_rate.pdf", bbox_inches='tight')

    plt.clf()
    # plt.margins(x=0,y=0)
    view_hqc_simulation_csv()
    aspect = 1 / (4 / 3)
    w = 10
    size = (w, w * aspect)

    # import re

    # pattern = r".*n_traces=(\d+)\s.*accuracy=([0-9.]+).*"
    # n_tracess = []
    # accuracies = []
    # with open("n_traces.log") as f:
    #     for line in f.readlines():
    #         match = re.search(pattern, line)
    #         if match is not None:
    #             n_traces = int(match.group(1))
    #             accuracy = float(match.group(2))
    #             n_tracess.append(n_traces)
    #             accuracies.append(accuracy)
    # df = pd.DataFrame(data={})
    df = pd.read_csv("accuracy.csv")
    fdf = df[(df["diff"] >= 55)]
    # fdf = df[(df["diff"] >= 55) & (df["n_traces"] % 2 == 1)]
    sdf = fdf.groupby("n_traces")["accuracy"].agg(
        ["median", lambda x: np.percentile(x, 5), lambda x: np.percentile(x, 95)]
    )
    sdf.columns = ["median", "lo", "hi"]
    # print(df)

    plt.clf()
    g = sns.lineplot(sdf, x="n_traces", y="median")
    g.set_xlabel("Number of Traces")
    g.set_ylabel("Accuracy")
    g.fill_between(
        sdf.index,
        sdf.lo,
        sdf.hi,
        color="blue",
        alpha=0.3,
        label="5th to 95th Percentile",
    )
    g.figure.savefig("figures/n_traces.pdf", bbox_inches='tight')

    plt.clf()
    g = sns.scatterplot(fdf, x="n_traces", y="accuracy")
    g.set_xlabel("Number of Traces")
    g.set_ylabel("Accuracy")
    g.figure.savefig("figures/n_traces_raw.pdf", bbox_inches='tight')

    timings = pd.read_csv("timings.csv")
    timings["ty"] = timings["ty"].map(
        {
            "fast": "Fast",
            "rand": "Random",
        }
    )
    ftimings = timings.rename(columns={"ty": "Ciphertext Timing"})
    # ftimings = timings[(timings['diff'] >= 55) & (12350 <= timings['time']) & (timings['time'] <= 12600)].copy()
    lo = 12350
    hi = 12600
    ftimings = ftimings[(lo <= ftimings["time"]) & (ftimings["time"] <= hi)]

    plt.clf()
    g = sns.histplot(
        timings_with_diff(ftimings, 55, 55),
        x="time",
        hue="Ciphertext Timing",
        multiple="layer",
        bins=50,
        hue_order=["Fast", "Random"],
    )
    g.set_xlabel("Side Channel Measurement (Cycles)")
    # g.set_ylabel("Frequency", rotation=270, color="k", labelpad=15)
    g.set_ylabel("Frequency", labelpad=15)
    # g.set_aspect(aspect)
    # g.figure.set_size_inches(size)
    g.figure.savefig("figures/timing_histogram.pdf", bbox_inches='tight')
    print("Done with hist")

    sds = []
    max_diff = 55
    timing_diffs = range(max_diff + 1)
    difference_of_means = []
    for i in timing_diffs:
        sub_ftimings = timings_with_diff(ftimings, i, i)
        print(sub_ftimings)

        def p_of(ty):
            c = Counter(sub_ftimings[sub_ftimings["Ciphertext Timing"] == ty]["time"])
            t = c.total()
            return defaultdict(lambda: 0, {k: v / t for (k, v) in c.items()})

        def mean_of(ty):
            return sub_ftimings[sub_ftimings["Ciphertext Timing"] == ty]["time"].mean()

        pf = p_of("Fast")
        pr = p_of("Random")
        sds.append(sd(range(lo, hi + 1), pf, pr))
        difference_of_means.append(mean_of("Random") - mean_of("Fast"))
        print(sds)
        print(difference_of_means)
    # ftimings = ftimings.groupby('ty')
    plt.clf()
    g = sns.lineplot(
        pd.DataFrame(
            {
                "Computed Timing Difference (Cycles)": timing_diffs,
                "Statistical Distance": sds,
            }
        ),
        x="Computed Timing Difference (Cycles)",
        y="Statistical Distance",
    )
    # g.set_box_aspect(1)
    # g.set_aspect(aspect)
    g.figure.set_size_inches(size)
    g.figure.savefig("figures/sd.pdf", bbox_inches='tight')

    plt.clf()
    g = sns.lineplot(
        pd.DataFrame(
            {
                "Computed Timing Difference (Cycles)": timing_diffs,
                "Mean Timing Deviation (Cycles)": difference_of_means,
            }
        ),
        x="Computed Timing Difference (Cycles)",
        y="Mean Timing Deviation (Cycles)",
    )
    g.figure.savefig("figures/difference_of_means.pdf", bbox_inches='tight')



if __name__ == "__main__":
    main()
