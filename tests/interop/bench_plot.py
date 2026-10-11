#!/usr/bin/env python3
"""Summarise a bench.py JSONL (valid runs only) into summary.json and draw the SVGs.
Usage: bench_plot.py RESULTS.jsonl OUTDIR (host Python with matplotlib)."""
import json, statistics, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cpu import data_total  # noqa: E402

PROFILE = "netem: A 10 ms/300 Mbit/s, B 30 ms/80 Mbit/s, one-way"
CLIENTS = {"mptcp-rs": "#2a78d6", "kernel": "#eb6834"}  # dataviz reference palette, validated
INK, MUTED, GRID, SURFACE = "#0b0b0b", "#898781", "#e1e0d9", "#fcfcfb"
DIR_LABEL = {"c2s": "c2s (client sending)", "s2c": "s2c (client receiving)"}


def record_cpu(rec):
    """Per-run CPU of an m2-unshaped record over its window; GB = TCP payload in that window."""
    c = rec["cpu"]
    gb = data_total(c["payload"], rec["dir"]) / 1e9
    cli = c["client"]["user_s"] + c["client"]["sys_s"]
    srv = c["server"]["user_s"] + c["server"]["sys_s"]
    b = c["payload"]["b"]["received" if rec["dir"] == "c2s" else "acked"]
    r = {"host_cpu_s_per_gb": c["host_busy_cpus"] * c["window_s"] / gb, "client_cpu_s_per_gb": cli / gb,
         "client_core_share": cli / c["window_s"], "client_user_frac": c["client"]["user_s"] / cli if cli else 0.0,
         "server_core_share": srv / c["window_s"], "leg_b_share": b / (gb * 1e9)}
    # Only the Python programs can be a harness bottleneck: a saturated mptcp-rs is the stack itself.
    r["bottleneck"] = r["server_core_share"] >= 0.9 or (rec["client"] == "kernel" and r["client_core_share"] >= 0.9)
    return r


def leg_b_share(rec):
    legs = rec.get("leg_payload") or {}
    return legs.get("b", 0) / sum(legs.values()) if legs and sum(legs.values()) else None


def summarize(records):
    cells = {}
    for r in records:
        if r.get("error") is None:
            cells.setdefault(f"{r['scenario']}/{r['dir']}/{r['client']}", []).append(r)
    med = lambda xs: statistics.median(xs) if xs else None
    out = {}
    for key, rs in sorted(cells.items()):
        g = [r["goodput_mbps"] for r in rs]
        s = {"n": len(rs), "median_mbps": med(g), "min_mbps": min(g), "max_mbps": max(g),
             "ceiling_median_mbps": med([r["ceiling_mbps"] for r in rs if r.get("ceiling_mbps") is not None]),
             "host_cpu_s_per_gb": None, "client_cpu_s_per_gb": None, "client_user_frac": None,
             "server_core_share_max": None, "bottleneck": False, "bottleneck_runs": []}
        if rs[0]["scenario"] == "m2-unshaped":
            cpus = [(r, record_cpu(r)) for r in rs]
            for f in ("host_cpu_s_per_gb", "client_cpu_s_per_gb", "client_user_frac"):
                s[f] = med([c[f] for _, c in cpus])
            s["server_core_share_max"] = max(c["server_core_share"] for _, c in cpus)
            s["leg_b_share_median"] = med([c["leg_b_share"] for _, c in cpus])
            s["bottleneck_runs"] = [{"rep": r["rep"], "artifacts": r["artifacts"], **{f: c[f] for f in ("client_core_share", "client_user_frac", "server_core_share")}}
                                    for r, c in cpus if c["bottleneck"]]
            s["bottleneck"] = bool(s["bottleneck_runs"])
        else:
            s["leg_b_share_median"] = med([x for x in map(leg_b_share, rs) if x is not None])
        out[key] = s
    return out


def bars(ax, groups, summary, scale=1.0, ceiling=True):
    """Grouped bars: one group per (scenario, dir) label, one bar per client; median, min-max, ceiling tick."""
    import matplotlib.patches as mpatches
    w = 0.38
    for gi, (label, scen, d) in enumerate(groups):
        for ci, client in enumerate(CLIENTS):
            s = summary.get(f"{scen}/{d}/{client}")
            if not s:
                continue
            x = gi + (ci - 0.5) * (w + 0.02)  # 0.02: the surface gap between adjacent bars
            m = s["median_mbps"] / scale
            ax.bar(x, m, w, color=CLIENTS[client], zorder=2)
            ax.errorbar(x, m, yerr=[[m - s["min_mbps"] / scale], [s["max_mbps"] / scale - m]], color=INK, lw=1, capsize=3, zorder=3)
            ax.annotate(f"{m:.1f}", (x, s["max_mbps"] / scale), xytext=(0, 3),
                        textcoords="offset points", ha="center", va="bottom", fontsize=8, color=INK)
            if ceiling and s["ceiling_median_mbps"]:
                c = s["ceiling_median_mbps"] / scale
                ax.plot([x - w / 2, x + w / 2], [c, c], color=INK, lw=1.5, ls=(0, (2, 1.5)), zorder=4)
    ax.set_xticks(range(len(groups)), [g[0] for g in groups])
    handles = [mpatches.Patch(color=c, label=n) for n, c in CLIENTS.items()]
    if ceiling:
        from matplotlib.lines import Line2D
        handles.append(Line2D([], [], color=INK, lw=1.5, ls=(0, (2, 1.5)), label="ceiling (link rate x payload share)"))
    # Below the plot, clear of the bars.
    ax.legend(handles=handles, frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=len(handles))


def style(ax, ylabel):
    ax.set_facecolor(SURFACE)
    ax.set_ylabel(ylabel, color=INK)
    ax.grid(axis="y", color=GRID, lw=0.8, zorder=0)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelcolor=INK, length=0)


def plot(summary, outdir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    plt.rcParams.update({"font.size": 9, "svg.fonttype": "none", "figure.facecolor": SURFACE})
    note = "CUBIC; median of runs, bars min-max; one segment per packet at netem"

    def shaped(scen, name, title):
        fig, ax = plt.subplots(figsize=(6.4, 4.2))
        bars(ax, [(DIR_LABEL[d], scen, d) for d in ("c2s", "s2c")], summary)
        style(ax, "goodput (Mbit/s)")
        ax.set_title(f"{title}\n{PROFILE}\n{note}", fontsize=9, color=INK, loc="left")
        fig.tight_layout()
        fig.savefig(outdir / name)
        plt.close(fig)

    shaped("m2-goodput", "shaped-ab.svg", "mptcp-rs vs Linux kernel MPTCP client, paths A+B")
    shaped("m2-lossy", "lossy.svg", "mptcp-rs vs Linux kernel MPTCP client, paths A+B, 1 % loss")

    fig, axes = plt.subplots(1, 2, figsize=(9, 4.2), sharey=True)
    for ax, d in zip(axes, ("c2s", "s2c")):
        bars(ax, [("A only", "base-a", d), ("B only", "base-b", d), ("A+B", "m2-goodput", d)], summary)
        style(ax, "goodput (Mbit/s)" if d == "c2s" else "")
        ax.set_title(DIR_LABEL[d], fontsize=9, color=INK, loc="left")
    fig.suptitle(f"Single path vs multipath\n{PROFILE}\n{note}", fontsize=9, color=INK, x=0.01, ha="left")
    fig.tight_layout()
    fig.savefig(outdir / "shaped-paths.svg")
    plt.close(fig)

    # Two measures, two panels (never two y-scales on one axis).
    fig, (ag, ac) = plt.subplots(1, 2, figsize=(9, 4.2))
    groups = [(DIR_LABEL[d], "m2-unshaped", d) for d in ("c2s", "s2c")]
    bars(ag, groups, summary, scale=1000, ceiling=False)
    style(ag, "goodput (Gbit/s)")
    w = 0.38
    for gi, (_, scen, d) in enumerate(groups):
        for ci, client in enumerate(CLIENTS):
            s = summary.get(f"{scen}/{d}/{client}")
            if not s or s["host_cpu_s_per_gb"] is None:
                continue
            x = gi + (ci - 0.5) * (w + 0.02)
            ac.bar(x - w / 4 - 0.005, s["host_cpu_s_per_gb"], w / 2 - 0.01, color=CLIENTS[client], zorder=2)
            ac.bar(x + w / 4 + 0.005, s["client_cpu_s_per_gb"], w / 2 - 0.01, color=SURFACE, edgecolor=CLIENTS[client], hatch="////", lw=1, zorder=2)
    ac.set_xticks(range(len(groups)), [g[0] for g in groups])
    import matplotlib.patches as mpatches
    ac.legend(handles=[mpatches.Patch(color=MUTED, label="host busy CPU"),
                       mpatches.Patch(facecolor=SURFACE, edgecolor=MUTED, hatch="////", label="client process CPU")],
              frameon=False, fontsize=8, loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2)
    style(ac, "CPU seconds per GB of TCP payload")
    fig.suptitle("No netem (CPU-bound), paths A+B; veth, offloads default; CUBIC; median of runs", fontsize=9, color=INK, x=0.01, ha="left")
    fig.tight_layout()
    fig.savefig(outdir / "unshaped.svg")
    plt.close(fig)


def main():
    src, outdir = Path(sys.argv[1]), Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)
    summary = summarize([json.loads(line) for line in src.read_text().splitlines()])
    (outdir / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    plot(summary, outdir)
    for key, s in summary.items():
        if s["bottleneck"]:
            print(f"BOTTLENECK {key}: {s['bottleneck_runs']}")


if __name__ == "__main__":
    main()
