"""Draws docs/coldstart.svg: cold-start p50 per runtime, from the hyperfine
JSON in results/final and results/final-session-baseline.

usage: python3 -I chart.py results/final results/final-session-baseline ../docs/coldstart.svg
"""
import json
import os
import sys

final, before, out = sys.argv[1:4]


def p50(directory, name):
    with open(os.path.join(directory, name + ".json")) as f:
        times = sorted(json.load(f)["results"][0]["times"])
    mid = len(times) // 2
    median = times[mid] if len(times) % 2 else (times[mid - 1] + times[mid]) / 2
    return median * 1000


# (label, value, series) per panel. Series: 1 kiln now, 2 kiln before, 3 other.
panels = [
    ("No network", [
        ("kiln (now)", p50(final, "kiln-none"), 1),
        ("kiln (before)", p50(before, "kiln-none"), 2),
        ("crun", p50(final, "crun-none"), 3),
        ("runc", p50(final, "runc-none"), 3),
        ("docker run --rm", p50(final, "docker-none"), 3),
    ]),
    ("With network (kiln --net full, Docker bridge)", [
        ("kiln (now)", p50(final, "kiln-net"), 1),
        ("kiln (before)", p50(before, "kiln-net"), 2),
        ("docker run --rm", p50(final, "docker-net"), 3),
    ]),
]
legend = [(1, "kiln after this work"), (2, "kiln before"), (3, "other runtimes")]

W, LEFT, RIGHT = 760, 150, 70
ROW, BAR = 30, 20
plot_w = W - LEFT - RIGHT
x_max = 150
ticks = range(0, x_max + 1, 25)


def x(v):
    return LEFT + plot_w * min(v, x_max) / x_max


parts = []
y = 64
for title, rows in panels:
    parts.append(f'<text class="panel" x="{LEFT}" y="{y}">{title}</text>')
    top = y + 12
    bottom = top + ROW * len(rows)
    for t in ticks:
        parts.append(f'<line class="grid" x1="{x(t):.1f}" y1="{top}" x2="{x(t):.1f}" y2="{bottom}"/>')
        parts.append(f'<text class="tick" x="{x(t):.1f}" y="{bottom + 14}" text-anchor="middle">{t}</text>')
    for i, (label, value, series) in enumerate(rows):
        by = top + i * ROW + (ROW - BAR) / 2
        x0, x1, r = LEFT, x(value), 4
        # Square at the baseline, 4px rounded at the data end.
        path = (f"M{x0},{by} H{x1 - r:.1f} Q{x1:.1f},{by} {x1:.1f},{by + r} "
                f"V{by + BAR - r} Q{x1:.1f},{by + BAR} {x1 - r:.1f},{by + BAR} H{x0} Z")
        parts.append(f'<path class="s{series}" d="{path}"><title>{label}: {value:.1f} ms</title></path>')
        parts.append(f'<text class="label" x="{LEFT - 10}" y="{by + BAR / 2 + 4}" text-anchor="end">{label}</text>')
        parts.append(f'<text class="value" x="{x1 + 6:.1f}" y="{by + BAR / 2 + 4}">{value:.1f} ms</text>')
    y = bottom + 50

H = y - 2
lx = LEFT
legend_svg = []
for series, text in legend:
    legend_svg.append(f'<rect class="s{series}" x="{lx}" y="22" width="12" height="12" rx="3"/>')
    legend_svg.append(f'<text class="label" x="{lx + 18}" y="32">{text}</text>')
    lx += 30 + 7.2 * len(text)

svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img"
  aria-label="Cold-start time to run true, p50 in milliseconds, per runtime">
<style>
  svg {{ font: 13px -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; }}
  .bg {{ fill: #fcfcfb; }}
  .s1 {{ fill: #2a78d6; }} .s2 {{ fill: #eb6834; }} .s3 {{ fill: #1baf7a; }}
  .grid {{ stroke: #e6e5e1; stroke-width: 1; }}
  .tick {{ fill: #77766f; font-size: 11px; }}
  .label {{ fill: #52514e; }} .value {{ fill: #0b0b0b; font-weight: 600; }}
  .panel, .title {{ fill: #0b0b0b; font-weight: 600; }} .note {{ fill: #77766f; font-size: 11px; }}
  @media (prefers-color-scheme: dark) {{
    .bg {{ fill: #1a1a19; }}
    .s1 {{ fill: #3987e5; }} .s2 {{ fill: #d95926; }} .s3 {{ fill: #199e70; }}
    .grid {{ stroke: #2e2e2c; }} .tick, .note {{ fill: #9a998f; }}
    .label {{ fill: #c3c2b7; }} .value, .panel, .title {{ fill: #f0efec; }}
  }}
</style>
<rect class="bg" width="{W}" height="{H}" rx="8"/>
{"".join(legend_svg)}
{"".join(parts)}
<text class="note" x="{W - RIGHT}" y="{H - 10}" text-anchor="end">p50 of 100 runs, 100 ms idle between runs, ms (lower is better)</text>
</svg>
"""
with open(out, "w") as f:
    f.write(svg)
