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
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
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

import sys
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import os.path

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
    df["success"] = (df["key_bits"] <= df["recovered_zeros_x"] + df["recovered_zeros_y"]) & (0 == df["wrong_zeros_x"] + df["wrong_zeros_y"])
    return df

names = list(reversed([x for x in ["perfect", "ideal", "0.005", "0.05", "0.1", "0.485"] if os.path.isfile(f"data/{x}.csv") ]))
def load_all_data():
    dfs = [load_data(f"data/{n}.csv") for n in names ]
    for (n, df) in zip(names, dfs):
        df['mode'] = cat_name(n)
    return pd.concat(dfs)

def cat_name(name):
    n = name
    try:
        n = str(1-float(n))
    except ValueError:
        n = f'\\mathrm{{{n}}}'
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
        aspect=9/3,
        hue="mode",
        linewidth=0.1,
        whis=(5, 95),
        fliersize=1,
        # facet_kws={'xlim': (0, max(df.queries))},
    )
    g.set(xscale = 'log')
    g.set_axis_labels("Oracle calls", "", fontsize=20)
    g.savefig('figures/oracle_calls.pdf')

def view_hqc_simulation_csv():
    df = load_all_data()
    oracle_calls_boxplots(df)


if __name__ == "__main__":
    view_hqc_simulation_csv()