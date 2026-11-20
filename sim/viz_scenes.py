"""
viz_scenes.py - Manim clips for the demo video, replaying real sim runs (traces from viz_trace.py).

    ~/manim-venv/bin/manim -qh sim/viz_scenes.py FloodClip      # one clip, 1080p
    ~/manim-venv/bin/manim -qh -a sim/viz_scenes.py             # all six
    GM_CAPTIONS=0 ~/manim-venv/bin/manim -qh -a sim/viz_scenes.py   # no captions (for a voiceover)

Videos land in media/videos/viz_scenes/1080p60/. Every timing is a run(t, seconds) call below:
change the seconds to make a clip longer or shorter. Captions also hold the frame long enough
to be read out loud (GM_WPS words/s, default 2.2; lower = slower).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np                                                       # noqa: E402
from manim import (BOLD, DOWN, LEFT, RIGHT, UP, Circle, Dot, FadeIn, FadeOut, Line, Scene, Text,  # noqa: E402
                   ValueTracker, VGroup, always_redraw, config, linear)

import viz_trace                                                         # noqa: E402
from viz_frames import COLORS, LEGEND, Timeline                          # noqa: E402

config.background_color = "#111318"
Text.set_default(font="DejaVu Sans")
CAPTIONS = os.environ.get("GM_CAPTIONS", "1") != "0"
# voiceover pacing: every caption stays up at least (words / WPS + BREATH) seconds, captions shown or not
WPS = float(os.environ.get("GM_WPS", "2.2"))
BREATH = 1.5
SUB = "#9aa1ad"


# ---- one mesh on screen -------------------------------------------------------------

class Panel:
    def __init__(self, data, center, size, node_r=0.075):
        self.data, self.tl = data, Timeline(data)
        self.c, self.s, self.node_r = np.array([center[0], center[1], 0.0]), size, node_r

    def P(self, xy):
        return self.c + np.array([xy[0] - 0.5, xy[1] - 0.5, 0.0]) * self.s

    def build(self, clock):
        d = self.data
        self.edges = VGroup(*[Line(self.P(d["pos"][a]), self.P(d["pos"][b]), stroke_width=1.3,
                                   color=COLORS["edge"]) for a, b in d["edges"]])
        states = self.tl.node_states(clock.get_value())
        self.nodes = VGroup(*[Dot(self.P(p), radius=self.node_r, color=COLORS[s]) for p, s in zip(d["pos"], states)])

        def recolor(group):
            for dot, s in zip(group, self.tl.node_states(clock.get_value())):
                dot.set_color(COLORS[s])
        self.nodes.add_updater(recolor)
        self.moving = always_redraw(lambda: self._moving(clock.get_value()))
        return VGroup(self.edges, self.moving, self.nodes)

    def _moving(self, T):
        g = VGroup()
        for c, r, col, al in self.tl.rings(T):
            if r * self.s > 0.03:
                g.add(Circle(radius=r * self.s, color=col, stroke_width=2).set_stroke(opacity=al).move_to(self.P(c)))
        for a, b, q, col, al in self.tl.packets(T):
            pa, pb = self.P(a), self.P(b)
            g.add(Dot(pa + (pb - pa) * q, radius=0.035, color=col, fill_opacity=al))
        for xy, al in self.tl.collisions(T):
            g.add(cross(self.P(xy), 0.09, al))
        return g

    def label(self, node, text, color="#ffffff"):
        p = self.P(self.data["pos"][node])
        out = p - self.c
        out = out / (np.linalg.norm(out) + 1e-9)
        return Text(text, font_size=24, weight=BOLD, color=color).move_to(p + out * 0.28)


def cross(p, d, opacity=1.0, width=3):
    return VGroup(Line(p + np.array([-d, -d, 0]), p + np.array([d, d, 0]), stroke_width=width),
                  Line(p + np.array([-d, d, 0]), p + np.array([d, -d, 0]), stroke_width=width)
                  ).set_stroke(color=COLORS["lost"], opacity=opacity)


def legend(keys, font=20, horizontal=False):
    rows = [VGroup(Dot(radius=0.08, color=COLORS[k]), Text(t, font_size=font)).arrange(RIGHT, buff=0.15)
            for t, k in LEGEND if k in keys]
    g = VGroup(*rows)
    return g.arrange(RIGHT, buff=0.45) if horizontal else g.arrange(DOWN, aligned_edge=LEFT, buff=0.2)


def source_line(p):
    s = p["source"]
    if not s["verified"]:
        return ""
    sets = ", ".join(f"{k} = {v}" for k, v in s["settings"].items())
    return f"{s['experiment']}: {sets}, seed {s['seed']} · run {s['run_id']} @ {s['commit']}"


# ---- shared clip helpers -------------------------------------------------------------

class Clip:
    cap = None
    _cap_t, _cap_need = 0.0, 0.0

    def start(self, t0):
        self.clock = ValueTracker(t0)

    def _say_time(self, text):
        # seconds to say this out loud at voiceover speed, plus a breath
        return len(text.split()) / WPS + BREATH

    def _settle(self):
        # hold the frame until the current caption has been on screen long enough to say
        left = self._cap_need - (self.renderer.time - self._cap_t)
        if left > 0.05:
            self.wait(left)

    def card(self, title, lines, secs=5.0):
        g = VGroup(Text(title, font_size=46, weight=BOLD),
                   *[Text(x, font_size=22, color=SUB) for x in lines if x]).arrange(DOWN, buff=0.3)
        if g.width > 13.4:
            g.scale_to_fit_width(13.4)
        secs = max(secs, self._say_time(title) + 1.5)
        self.play(FadeIn(g), run_time=0.6)
        self.wait(max(secs - 1.2, 0.1))
        self.play(FadeOut(g), run_time=0.6)

    def caption(self, text, hold=0.0):
        self._settle()
        if CAPTIONS:
            new = Text(text, font_size=26).to_edge(DOWN, buff=0.3)
            if new.width > 13.4:
                new.scale_to_fit_width(13.4)
            anims = [FadeIn(new)] + ([FadeOut(self.cap)] if self.cap else [])
            self.play(*anims, run_time=0.4)
            self.cap = new
        else:
            self.wait(0.4)
        self._cap_t, self._cap_need = self.renderer.time, self._say_time(text)
        if hold:
            self.wait(hold)

    def run(self, t, secs):
        self.play(self.clock.animate.set_value(t), run_time=secs, rate_func=linear)

    def jump(self, t):
        self.clock.set_value(t)

    def timer(self, ref, where):
        # ms since `ref()` (A's send), simulated time
        return always_redraw(lambda: Text(f"t = {max(self.clock.get_value() - ref(), 0):4.0f} ms",
                                          font_size=24).move_to(where))

    def end_card(self, lines, secs=5.0):
        self._settle()
        self.play(*[FadeOut(m) for m in self.mobjects], run_time=0.6)
        self.cap = None
        g = VGroup(*[Text(x, font_size=30 if i == 0 else 24, color="#ffffff" if i == 0 else SUB)
                     for i, x in enumerate(lines)]).arrange(DOWN, buff=0.35)
        if g.width > 13.4:
            g.scale_to_fit_width(13.4)
        secs = max(secs, self._say_time(" ".join(lines)) + 1.0)
        self.play(FadeIn(g), run_time=0.6)
        self.wait(max(secs - 1.2, 0.1))
        self.play(FadeOut(g), run_time=0.6)


def counts_at_end(panel):
    tl = panel.tl
    return tl.counts(panel.data["phases"]["end"] + 1)


def pct(x):
    return f"{100 * x:.1f}%"


# ---- 1. managed flooding ---------------------------------------------------------------

class FloodClip(Clip, Scene):
    def construct(self):
        clip = viz_trace.get("flood")
        d = clip["panels"][0]
        m, ph = d["messages"][d["focus"]], d["phases"]
        self.card("Managed flooding: one message across the mesh",
                  ["Replay of a real sim run (routing.c), slowed down", source_line(d),
                   "rerun matches the stored result exactly"])
        self.start(d["window"][0])
        pan = Panel(d, (-2.4, 0.1), 6.4)
        tl = pan.tl
        mesh = pan.build(self.clock)
        leg = legend({"src", "heard", "relayed", "cancelled", "delivered", "ack"}).to_edge(RIGHT, buff=0.5).shift(UP * 0.3)
        tmr = self.timer(lambda: m["sent"], np.array([4.6, 3.3, 0]))
        self.play(FadeIn(mesh), FadeIn(pan.label(m["src"], "A")), FadeIn(pan.label(m["dst"], "C")),
                  FadeIn(leg), FadeIn(tmr), run_time=1.0)
        self.caption(f"A sends one message to C, {m['hops']} hops away (30 nodes)", hold=1.5)

        self.run(m["sent"], 0.3)
        self.caption("Each node that hears it waits a random 10–50 ms, then passes it on")
        self.run(m["sent"] + 0.45 * (tl.delivered_at - m["sent"]), 6)
        self.caption("A node that already heard k = 2 copies stays quiet (grey): the 'managed' part")
        self.run(tl.delivered_at + 10, 7)
        self.caption(f"C got it {m['delivered'] - m['sent']:.0f} ms after A sent it, first try", hold=1.5)
        self.caption("C waits a random 0–400 ms, then sends an ACK")
        self.run(ph["ack_start"], 2)
        self.caption("The ACK floods back to A the same way")
        self.run(ph["acked"] + tl.shift + 10, 7)
        self.caption("A has its ACK: the message shows as delivered")
        self.run(ph["end"], 1.5)
        self.wait(1)

        c = counts_at_end(pan)
        h = d["headline"]
        self.end_card([f"This message: {c['transmissions']} transmissions, {c['relayed']} relays, "
                       f"{c['quiet']} nodes stayed quiet",
                       f"All 10 runs at 30 nodes: {pct(h['delivery'])} delivered, "
                       f"{h['tx_per_delivered']:.0f} transmissions per delivered message (DATA + ACK)"])


# ---- side-by-side helper ------------------------------------------------------------------

class PairClip(Clip):
    keys = {"src", "heard", "relayed", "cancelled", "delivered", "ack"}

    def pair(self, clip, titles, size=5.4, subs=None):
        L, R = clip["panels"]
        self.start(L["window"][0])
        pl, pr = Panel(L, (-3.5, -0.3), size, 0.06), Panel(R, (3.5, -0.3), size, 0.06)
        ml, mr = pl.build(self.clock), pr.build(self.clock)
        hl = Text(titles[0], font_size=28, weight=BOLD).move_to(np.array([-3.5, 2.95, 0]))
        hr = Text(titles[1], font_size=28, weight=BOLD).move_to(np.array([3.5, 2.95, 0]))
        leg = legend(self.keys, font=16, horizontal=True).move_to(np.array([0, 3.65, 0]))
        if leg.width > 13.6:
            leg.scale_to_fit_width(13.6)
        labels = []
        for p in (pl, pr):
            if p.data.get("focus") is not None:
                mm = p.data["messages"][p.data["focus"]]
                labels += [p.label(mm["src"], "A"), p.label(mm["dst"], "C")]
        if subs:
            labels += [Text(subs[0], font_size=18, color=SUB).next_to(hl, DOWN, buff=0.08),
                       Text(subs[1], font_size=18, color=SUB).next_to(hr, DOWN, buff=0.08)]
        self.play(FadeIn(ml), FadeIn(mr), FadeIn(hl), FadeIn(hr), FadeIn(leg), *[FadeIn(x) for x in labels],
                  run_time=1.0)
        return pl, pr


# ---- 2. TTL 5 vs 16 ------------------------------------------------------------------------

class TtlClip(PairClip, Scene):
    def construct(self):
        clip = viz_trace.get("ttl")
        bad, good = clip["panels"]
        m, mg = bad["messages"][bad["focus"]], good["messages"][good["focus"]]
        self.card("TTL: how far a message is allowed to travel",
                  ["Two real sim runs, same mesh and same message, only the TTL differs",
                   source_line(bad), source_line(good), "both reruns match their stored results exactly"])
        pl, pr = self.pair(clip, ["TTL 5", "TTL 16"])
        self.add(self.timer(lambda: m["sent"], np.array([0, 2.95, 0])))
        self.caption(f"50 nodes. A sends to C, {mg['hops']} hops away", hold=1.5)
        self.run(m["sent"], 0.3)
        self.caption("Every hop uses up 1 of the TTL (hop padding already spends up to 2)")
        self.run(m["sent"] + 0.5 * (pr.tl.delivered_at - m["sent"]), 6)
        self.caption("TTL 5: the last nodes hear it but have no hops left to pass it on")
        self.run(pr.tl.delivered_at + 10, 6)
        self.caption("TTL 16: C gets it on the first try", hold=1.5)
        tries = len(m["attempts"])
        tail = (f"With TTL 5, A tries {tries} times and C never gets it" if m["delivered"] is None
                else f"With TTL 5, C only gets it on try {tries}")
        self.caption(tail)
        self.run(good["phases"]["end"], 5)
        self.wait(1)
        hb, hg = bad["headline"], good["headline"]
        self.end_card([f"All 10 runs at 50 nodes: TTL 5 delivers {pct(hb['delivery'])}, TTL 16 delivers {pct(hg['delivery'])}",
                       "So the sim uses TTL 16 (the 4-board demo only needs about 2 hops)"])


# ---- 3. k = 1 vs k = 2 -------------------------------------------------------------------------

class KClip(PairClip, Scene):
    def construct(self):
        clip = viz_trace.get("k")
        bad, good = clip["panels"]
        m, mg = bad["messages"][bad["focus"]], good["messages"][good["focus"]]
        self.card("Suppression threshold k: when should a relay stay quiet?",
                  ["Two real sim runs, same mesh and same message, only k differs",
                   source_line(bad), source_line(good), "both reruns match their stored results exactly"])
        pl, pr = self.pair(clip, ["k = 1", "k = 2"])
        self.add(self.timer(lambda: m["sent"], np.array([0, 2.95, 0])))
        self.caption(f"50 nodes, 1000 kbps. A sends to C, {mg['hops']} hops away", hold=1.5)
        self.run(m["sent"], 0.3)
        ids = {f["id"] for f in bad["frames"] if f["msg"] == bad["focus"]}
        lost_at = [r["t"] + pl.tl.shift for r in bad["rx"] if not r["ok"] and r["id"] in ids]
        mid = m["sent"] + 0.5 * (pr.tl.delivered_at - m["sent"])
        self.caption("k = 1: a relay cancels as soon as it hears one other copy")
        if lost_at:
            # time the "lost copy" caption to k = 1's first destroyed reception, so the × is on screen
            t_x = min(lost_at)
            self.run(max(m["sent"] + 5, t_x - 12), 4)
            self.caption("So when a copy is lost (red × on the left), nobody covers for it")
            self.run(max(t_x + 25, mid), 4)
        else:
            self.run(m["sent"] + 0.25 * (pr.tl.delivered_at - m["sent"]), 3.5)
            self.caption("So far fewer relays carry it on")
            self.run(mid, 3.5)
        self.caption("k = 1: the flood dies out and C never hears this attempt (a coverage hole)")
        self.run(pr.tl.delivered_at + 10, 6)
        self.caption("k = 2: enough relays keep going, and C gets it on the first try", hold=1.5)
        tail = (f"With k = 1, A's retry 1 s later finally reaches C ({m['delivered'] - m['sent']:.0f} ms in total)"
                if m["delivered"] is not None else "With k = 1, C never gets this message")
        self.caption(tail)
        self.run(good["phases"]["end"], 4)
        self.wait(1)
        hb, hg = bad["headline"], good["headline"]
        self.end_card([f"All 10 runs (50 nodes, 1000 kbps): k = 1 delivers {pct(hb['delivery'])}, "
                       f"k = 2 delivers {pct(hg['delivery'])}",
                       "So k = 2 is the default: it closes coverage holes without flooding everything"])


# ---- 4. channel overload ---------------------------------------------------------------------

class LoadClip(PairClip, Scene):
    keys = {"tx", "lost"}

    def construct(self):
        clip = viz_trace.get("load")
        fast, slow = clip["panels"]
        t_a, t_b = fast["window"]
        self.card("Channel capacity: heavy load on a slow channel",
                  ["Two real sim runs, same mesh and same traffic (8 messages/s), only the bit rate differs",
                   source_line(fast), source_line(slow), "both reruns match their stored results exactly"])
        pl, pr = self.pair(clip, ["1000 kbps", "300 kbps"])

        def counter(p, x):
            return always_redraw(lambda: Text(
                "sent {sent}   delivered {delivered}   lost receptions {collisions}".format(**p.tl.counts(self.clock.get_value())),
                font_size=18, color=SUB).move_to(np.array([x, -3.15, 0])))
        self.add(counter(pl, -3.5), counter(pr, 3.5))
        self.caption("30 nodes, about 8 new messages per second, same messages on both sides", hold=1.5)
        self.caption("Each color is a different message. Red × = a reception destroyed by a collision")
        self.run(t_a + 0.35 * (t_b - t_a), 8)
        self.caption("At 300 kbps each frame is on the air over 3× longer, so floods overlap and collide")
        self.run(t_b, 13)
        self.wait(1)
        hf, hs = fast["headline"], slow["headline"]
        self.end_card([f"All 10 runs at 8 msg/s: 1000 kbps delivers {pct(hf['delivery'])}, 300 kbps delivers {pct(hs['delivery'])}",
                       "Below about 500 kbps, flooding can't keep up under heavy load"])


# ---- 5. v1 vs v2 ------------------------------------------------------------------------------

class V2Clip(PairClip, Scene):
    def construct(self):
        clip = viz_trace.get("v2")
        v1, v2 = clip["panels"]
        m1, m2 = v1["messages"][v1["focus"]], v2["messages"][v2["focus"]]
        ttl = lambda p, m: next(f["ttl"] + f["hop"] for f in p["frames"]
                                if f["msg"] == p["focus"] and f["node"] == m["src"] and f["kind"] == "data")
        self.card("Route learning (v2): what flooding costs, and why we kept it",
                  ["Two real sim runs, same mesh and same traffic, only route learning differs",
                   source_line(v1), source_line(v2), "both reruns match their stored results exactly"])
        pl, pr = self.pair(clip, ["v1: flooding", "v2: route learning"], subs=["deployed", "not deployed"])
        self.add(self.timer(lambda: m1["sent"], np.array([0, 2.95, 0])))
        self.caption(f"50 nodes, 5 ongoing conversations. A and C have talked before; C is {m1['hops']} hops away",
                     hold=1.5)
        self.run(m1["sent"], 0.3)
        self.caption(f"v1 sends with TTL {ttl(v1, m1)}: the whole mesh carries it")
        self.run(m1["sent"] + 40, 5)
        self.caption(f"v2 learned the distance, so it sends with TTL {ttl(v2, m2)}: just enough to reach C")
        self.run(max(v2["phases"]["end"], m1["sent"] + 90), 6)
        n1 = len({f["node"] for f in v1["frames"] if f["msg"] == v1["focus"]})
        n2 = len({f["node"] for f in v2["frames"] if f["msg"] == v2["focus"]})
        self.caption(f"This message: {n1} nodes transmitted in v1, {n2} in v2")
        self.run(v1["phases"]["end"], 6)
        self.caption("But a TTL that just reaches C tells anyone listening roughly how far away C is", hold=2.5)
        h1, h2 = v1["headline"], v2["headline"]
        cut = 100 * (1 - h2["tx_per_delivered"] / h1["tx_per_delivered"])
        self.end_card(["All 10 runs (50 nodes, 5 conversations):",
                       f"v2 needs {h2['tx_per_delivered']:.0f} transmissions per delivered message instead of "
                       f"{h1['tx_per_delivered']:.0f} (−{cut:.0f}%)",
                       f"delivery is the same: {pct(h1['delivery'])} vs {pct(h2['delivery'])}",
                       "We kept v1: hiding who is talking to whom matters more than the savings"])


# ---- 6. self-healing (scenario) -----------------------------------------------------------------

class SelfHealClip(Clip, Scene):
    def construct(self):
        clip = viz_trace.get("selfheal")
        d0, d1 = clip["panels"]
        x, t_down = clip["x"], clip["t_down"]
        m0, m1 = d0["messages"][d0["focus"]], d1["messages"][d1["focus"]]
        seed = d0["source"]["seed"]
        self.card("Self-healing: unplug a relay",
                  ["A scenario, not one of the experiment runs:",
                   f"same routing code, settings and mesh as the 30-node scaling runs (seed {seed}),",
                   "with one relay (X) unplugged on purpose"])
        self.start(d0["window"][0])
        pan = Panel(d0, (-2.4, 0.1), 6.4)
        mesh = pan.build(self.clock)
        leg = legend({"src", "heard", "relayed", "cancelled", "delivered", "ack"}).to_edge(RIGHT, buff=0.5).shift(UP * 0.3)
        ref = {"t": m0["sent"]}
        tmr = self.timer(lambda: ref["t"], np.array([4.6, 3.3, 0]))
        lx = pan.label(x, "X", color="#ffd166")
        self.play(FadeIn(mesh), FadeIn(pan.label(m0["src"], "A")), FadeIn(pan.label(m0["dst"], "C")),
                  FadeIn(lx), FadeIn(leg), FadeIn(tmr), run_time=1.0)
        self.caption(f"A sends C a message, {m0['hops']} hops away. X is one of the relays it goes through", hold=1.5)
        self.run(m0["sent"], 0.3)
        self.run(pan.tl.delivered_at + 10, 8)
        self.caption(f"C got it ({m0['delivered'] - m0['sent']:.0f} ms), and its ACK comes back to A")
        self.run(d0["phases"]["end"], 4)

        # unplug X
        pan.tl = Timeline(d1)
        self.jump(t_down - 1)
        self.caption("Now X is unplugged, like pulling a board's power")
        self.run(t_down + 1, 0.4)
        xmark = cross(pan.P(d1["pos"][x]), 0.16, 1.0, width=5)
        self.play(FadeIn(xmark), run_time=0.5)
        self.wait(1.2)

        ref["t"] = m1["sent"]
        self.jump(d1["window"][0])
        self.caption("A sends again. Nobody tells the mesh that X is gone")
        self.run(m1["sent"] + 0.5 * (pan.tl.delivered_at - m1["sent"]), 6)
        first_try = len(m1["attempts"]) == 1 and m1["delivered"] is not None and m1["delivered"] - m1["sent"] < 900
        self.caption("There is no route to repair: the flood simply takes the other paths" if first_try
                     else "The first attempt doesn't make it; A's retry floods around X")
        self.run(pan.tl.delivered_at + 10, 5)
        if m1["delivered"] is not None:
            self.caption(f"C got it {m1['delivered'] - m1['sent']:.0f} ms after A sent it"
                         + (", first try" if first_try else ""), hold=1.5)
        self.run(d1["phases"]["end"], 3)
        self.wait(1)
        self.end_card(["Flooding keeps no routes, so there is nothing to break:",
                       "the first message after the failure already went around X",
                       "On the boards, this is the reroute-time test: unplug B, time the next message (PROTOCOL.md §13)"])


# ---- 15 s cut for the 3-minute video: one message across 50 nodes, no captions ---------------

class ScaleClip(Clip, Scene):
    """Exactly 15 s, no captions or cards (the voiceover carries it). Replay of a 50-node scaling run."""

    def construct(self):
        d = viz_trace.get("scale50")["panels"][0]
        m, ph = d["messages"][d["focus"]], d["phases"]
        self.start(d["window"][0])
        pan = Panel(d, (-1.7, -0.05), 7.6, 0.065)
        mesh = pan.build(self.clock)
        leg = legend({"src", "heard", "relayed", "cancelled", "delivered", "ack"}, font=18) \
            .to_edge(RIGHT, buff=0.45).shift(DOWN * 0.4)
        tag = Text("Simulation: 50 nodes, real routing code", font_size=20, color=SUB).to_corner(UP + LEFT, buff=0.35)
        tmr = self.timer(lambda: m["sent"], np.array([5.0, 3.4, 0]))
        self.play(FadeIn(mesh), FadeIn(pan.label(m["src"], "A")), FadeIn(pan.label(m["dst"], "C")),
                  FadeIn(leg), FadeIn(tag), FadeIn(tmr), run_time=0.8)   # 0.8
        self.wait(0.7)                                                     # 1.5
        self.run(m["sent"], 0.2)                                           # 1.7
        self.run(pan.tl.delivered_at + 10, 7.0)                            # 8.7  DATA floods out, C gets it
        self.run(ph["acked"] + pan.tl.shift + 10, 4.8)                     # 13.5 ACK floods back
        self.run(ph["end"], 0.8)                                           # 14.3
        self.wait(0.7)                                                     # 15.0
