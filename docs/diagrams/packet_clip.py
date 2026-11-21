"""packet_clip.py - 25 s Manim clip: anatomy of a GhostMesh frame (header, then the encrypted part).

    ~/manim-venv/Scripts/manim -qh docs/diagrams/packet_clip.py PacketClip                    # 1080p60, captions
    GM_CAPTIONS=0 ~/manim-venv/Scripts/manim -qh docs/diagrams/packet_clip.py PacketClip      # no captions (voiceover)

Storyboard (Jose, Nov 20): 0-5 s the whole 240-byte frame; zoom to the 30-byte header and explain it
(~10 s); zoom out and into the encrypted part and explain it (~10 s). Same look as Rashad's clips in
sim/viz_scenes.py (dark background, SUB grey, caption line at the bottom). Field layout: PROTOCOL.md §9.4-9.5;
the still version with full text is docs/diagrams/packet-anatomy.svg.
"""
import os

from manim import (BOLD, DOWN, LEFT, UP, AnimationGroup, Brace, DashedVMobject, FadeIn, FadeOut, LaggedStart, Line,
                   Rectangle, Scene, SurroundingRectangle, Text, VGroup, config, smooth)

config.background_color = "#111318"
Text.set_default(font="DejaVu Sans")
CAPTIONS = os.environ.get("GM_CAPTIONS", "1") != "0"
SUB = "#9aa1ad"
BG = "#111318"
GREEN, BLUE, AMBER = "#22c06a", "#3b8bff", "#f2b134"

BAR_W, BAR_H, BAR_Y = 12.5, 0.78, 0.55


def bar(specs, y=BAR_Y, h=BAR_H, font=16):
    """specs: [(width, color, label)] laid out left to right, centred. -> VGroup of VGroup(rect, label)."""
    x = -sum(w for w, _, _ in specs) / 2
    cells = VGroup()
    for w, col, label in specs:
        r = Rectangle(width=w, height=h, fill_color=col, fill_opacity=1, stroke_color=BG, stroke_width=5)
        r.move_to([x + w / 2, y, 0])
        cell = VGroup(r)
        if label:
            t = Text(label, font_size=font, color="#ffffff", weight=BOLD)
            if t.width > w - 0.08:
                t.scale_to_fit_width(w - 0.08)
            cell.add(t.move_to(r))
        cells.add(cell)
        x += w
    return cells


class PacketClip(Scene):
    def caption(self, text):
        """Swap the bottom caption (kept for timing even when captions are off)."""
        anims = []
        if getattr(self, "_cap", None) is not None:
            anims.append(FadeOut(self._cap, run_time=0.25))
        self._cap = None
        if CAPTIONS and text:
            self._cap = Text(text, font_size=24, color="#ffffff").to_edge(DOWN, buff=0.45)
            anims.append(FadeIn(self._cap, run_time=0.35))
        return anims

    def title(self, text):
        anims = []
        if getattr(self, "_title", None) is not None:
            anims.append(FadeOut(self._title, run_time=0.3))
        self._title = Text(text, font_size=30, weight=BOLD).move_to([0, 2.75, 0])
        anims.append(FadeIn(self._title, run_time=0.4))
        return anims

    def beat(self, cells, idx, word, row, cap, hold, color, anchor=None):
        """Highlight cells[idx], drop a tick + short label under the anchor cells, swap the caption, hold."""
        group = VGroup(*[cells[i] for i in (anchor or idx)])
        x = group.get_center()[0]
        y = BAR_Y - BAR_H / 2 - (0.75 if row == 1 else 1.45)
        label = Text(word, font_size=21, color=color, weight=BOLD)
        lx = min(max(x, -6.9 + label.width / 2), 6.9 - label.width / 2)
        label.move_to([lx, y, 0])
        tick = Line([x, BAR_Y - BAR_H / 2 - 0.04, 0], [lx, y + 0.2, 0], color=color, stroke_width=2.5)
        dim = [cells[i].animate.set_opacity(0.28) for i in range(len(cells)) if i not in idx]
        lit = [cells[i].animate.set_opacity(1) for i in idx]
        self.play(*dim, *lit, FadeIn(tick), FadeIn(label, shift=UP * 0.1), *self.caption(cap), run_time=0.6)
        self.wait(hold)
        return VGroup(tick, label)

    def construct(self):
        tag = Text("GhostMesh frame, real layout (PROTOCOL §9.4)", font_size=20, color=SUB).to_corner(UP + LEFT, buff=0.35)
        self.add(tag)

        # ---- 1. the whole frame (0-5 s) ---------------------------------------------------
        px = BAR_W / 240
        full = bar([(30 * px, "#5b6b8a", "header"), (24 * px, "#6b7280", "nonce"),
                    (170 * px, "#2950b8", "ciphertext"), (16 * px, "#c98a12", "tag")], font=18)
        sizes = VGroup(*[Text(s, font_size=17, color=SUB).next_to(c, DOWN, buff=0.15)
                         for s, c in zip(("30 B", "24 B", "170 B", "16 B"), full)])
        b_head = Brace(full[0], DOWN, buff=0.5, color=GREEN)
        b_enc = Brace(VGroup(full[1], full[2], full[3]), DOWN, buff=0.5, color=BLUE)
        t_head = Text("readable by anyone", font_size=20, color=GREEN).next_to(b_head, DOWN, buff=0.12)
        t_head.align_to(b_head, LEFT)
        t_enc = Text("only sender and recipient", font_size=20, color=BLUE).next_to(b_enc, DOWN, buff=0.12)
        frame = VGroup(full, sizes, b_head, b_enc, t_head, t_enc)

        self.play(*self.title("One frame: 240 bytes, every time"),
                  LaggedStart(*[FadeIn(c, shift=UP * 0.15) for c in full], lag_ratio=0.25), run_time=1.4)
        self.play(FadeIn(sizes), *self.caption("Every frame is the same size, so length never gives anything away."),
                  run_time=0.7)
        self.play(FadeIn(b_head), FadeIn(t_head), FadeIn(b_enc), FadeIn(t_enc), run_time=0.8)
        self.remove(*frame.get_family())                 # FadeIn added the parts one by one: keep one group
        self.add(frame)
        self.wait(2.1)                                                                     # -> 5.0 s

        # ---- zoom to the header (5.0-7.1 s) -----------------------------------------------
        words = VGroup(sizes, b_head, b_enc, t_head, t_enc, *[cell[1] for cell in full])
        box = DashedVMobject(SurroundingRectangle(full[0], buff=0.12, color=GREEN, stroke_width=3), num_dashes=24)
        frame.save_state()
        self.play(FadeIn(box), *self.caption(""), run_time=0.4)
        self.play(words.animate.set_opacity(0), box.animate.set_opacity(0), run_time=0.3)
        self.remove(box)
        c = full[0].get_center()
        k = BAR_W / full[0].width
        self.play(frame.animate.stretch(k, 0, about_point=c).shift([0, BAR_Y, 0] - c), run_time=0.9, rate_func=smooth)

        hpx = BAR_W / 30
        head = bar([(1 * hpx, "#5a6b8c", "type"), (1 * hpx, "#7a5a8c", "flags"), (8 * hpx, "#3f8796", "msg_id"),
                    (1 * hpx, "#8c6a3f", "ttl"), (1 * hpx, "#a07845", "hop"), (4 * hpx, "#2f6fb5", "src_pseudo"),
                    (4 * hpx, "#4f8a5c", "next_hop"), (2 * hpx, "#8c4f6a", "epoch"), (8 * hpx, "#c98a12", "link_tag")])
        self.play(FadeIn(head), frame.animate.set_opacity(0), *self.title("Header: 30 bytes anyone can read"),
                  run_time=0.5)
        self.remove(frame)                                                                 # -> 7.1 s

        # ---- header points (7.1-15.0 s) ---------------------------------------------------
        h1 = self.beat(head, [5, 6], "who → whom: hidden", 1,
                       "No destination, and the sender field is a relay's 60 s pseudonym.", 1.25, GREEN)
        h2 = self.beat(head, [3, 4], "distance: padded", 2,
                       "Hop counts start at 0, 1 or 2, so hop 0 doesn't reveal the sender.", 1.25, AMBER)
        h3 = self.beat(head, [2, 7], "replays: expire", 1,
                       "Random IDs and 60 s epochs: replayed frames are dropped.", 1.25, "#7ec8d6", anchor=[2])
        h4 = self.beat(head, [8], "forgery: dropped", 2,
                       "Sealed with the network key: outsider frames die at the first hop.", 1.25, AMBER)
        self.play(*[c.animate.set_opacity(1) for c in head], run_time=0.3)
        self.wait(0.2)                                                                     # -> 15.0 s

        # ---- zoom out, then into the encrypted part (15.0-17.8 s) ------------------------
        self.play(FadeOut(VGroup(h1, h2, h3, h4)), *self.caption(""), run_time=0.3)
        self.add(frame)
        self.play(frame.animate.restore(), FadeOut(head), *self.title("Encrypted: only the two ends can read it"),
                  run_time=0.7)
        enc = VGroup(full[1], full[2], full[3])
        box2 = DashedVMobject(SurroundingRectangle(enc, buff=0.12, color=BLUE, stroke_width=3), num_dashes=60)
        self.play(FadeIn(box2), run_time=0.35)
        self.play(words.animate.set_opacity(0), full[0].animate.set_opacity(0), box2.animate.set_opacity(0), run_time=0.3)
        self.remove(box2)
        c2 = enc.get_center()
        k2 = BAR_W / enc.width
        self.play(frame.animate.stretch(k2, 0, about_point=c2).shift([0, BAR_Y, 0] - c2), run_time=0.75, rate_func=smooth)

        cip = bar([(1.35, "#6b7280", "nonce"), (0.95, "#1f3f99", "from"), (0.95, "#24479f", "to"),
                   (0.95, "#2a50a6", "time"), (0.8, "#3059ad", "seq"), (0.75, "#3662b4", "type"),
                   (0.65, "#3c6bbb", "len"), (5.0, BLUE, "message (padded)"), (1.1, "#c98a12", "tag")])
        brace_ct = Brace(VGroup(*cip[1:8]), UP, buff=0.12, color=SUB)
        brace_tx = Text("encrypted (XChaCha20)", font_size=18, color=SUB).next_to(brace_ct, UP, buff=0.08)
        self.play(FadeIn(cip), frame.animate.set_opacity(0), FadeIn(brace_ct), FadeIn(brace_tx), run_time=0.4)
        self.remove(frame)                                                                 # -> 17.8 s

        # ---- encrypted points (17.5-25 s) -------------------------------------------------
        e1 = self.beat(cip, [0], "fresh every frame", 1,
                       "A random 24-byte nonce on every frame: nothing repeats, nothing to track.", 1.05, "#c3c8d2")
        e2 = self.beat(cip, [1, 2, 3, 4, 5, 6], "real sender + recipient", 2,
                       "The real sender, recipient, time and order are only inside here.", 1.05, BLUE)
        e3 = self.beat(cip, [7], "padded, key changes every minute", 1,
                       "Padded to one size, under a pair key that changes every 60 s.", 1.05, "#7fb0ff")
        e4 = self.beat(cip, [8], "tamper seal", 2,
                       "The tag seals the message and the header: one changed bit, dropped.", 1.05, AMBER)
        self.play(*[c.animate.set_opacity(1) for c in cip], run_time=0.3)
        self.wait(0.3)                                                                     # -> 25.0 s
