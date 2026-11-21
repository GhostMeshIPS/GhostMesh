"""attack_clip.py - 20 s Manim clip: a replay attack on the testbed, stopped at the first hop and logged by the IPS.

    ~/manim-venv/Scripts/manim -qh docs/diagrams/attack_clip.py AttackClip                    # 1080p60, captions
    GM_CAPTIONS=0 ~/manim-venv/Scripts/manim -qh docs/diagrams/attack_clip.py AttackClip      # no captions (voiceover)

Storyboard (Jose, Nov 20), six frames, 3.5 s each and 2.5 s for the last:
  1. from the last frame of PacketClip, zoom out and pan to the testbed map
  2. a bubble shows the replayed frame and its copied fields (A's identity), zoom to the top half
  3. relay B checks the frame (expected vs real epoch), zoom to B
  4. B finds the attack and drops the frame
  5. zoom out to the whole system; an IPS log entry for the replay slides in
  6. checkmark
It starts on PacketClip's final frame, so the two clips join without a cut. The IPS panel is a stand-in for the
live dashboard (ips/dashboard): its shape matches, the rows are placeholders, and it claims no measured numbers.
What's shown is the real behaviour: a replayed frame keeps a valid link_tag (it's an exact copy), and nodes drop
it because its epoch is outside the +-1 window (PROTOCOL §9.6), so it is never relayed. Attack spec: security/attacks.
"""
import numpy as np
from manim import (BackgroundRectangle, BOLD, DOWN, LEFT, RIGHT, UP, Arrow, Circle, Create, DashedVMobject, FadeIn, FadeOut, Line,
                   Polygon, Rectangle, Transform, RoundedRectangle, Text, VGroup, VMobject, smooth)

from packet_clip import CAPTIONS, AMBER, BG, BLUE, GREEN, SUB, PacketClip

RED, CYAN, YELLOW = "#ef4444", "#7fb0ff", "#f5d142"
NODE_FILL, NODE_LINE = "#1a2233", "#5b7bb5"
NAVY, CARD = "#0f1a3d", "#16214a"
NW, NH = 2.5, 0.95                                     # node box size (world units)
POS = {"A": (-4.2, 0.3), "B": (0.0, 1.45), "C": (4.2, 0.3), "D": (0.0, -0.85), "X": (-4.2, -2.0), "W": (4.2, -2.0)}
ROLE = {"A": "sender", "B": "main relay", "C": "receiver", "D": "backup relay", "X": "insider attacker",
        "W": "watchtower"}


def node(name):
    x, y = POS[name]
    col = {"X": RED, "W": AMBER}.get(name, NODE_LINE)
    r = RoundedRectangle(width=NW, height=NH, corner_radius=0.12, fill_color=NODE_FILL, fill_opacity=1,
                         stroke_color=col, stroke_width=3)
    if name == "X":
        r = VGroup(RoundedRectangle(width=NW, height=NH, corner_radius=0.12, fill_color=NODE_FILL, fill_opacity=1,
                                    stroke_width=0),
                   DashedVMobject(r, num_dashes=30))
    r.move_to([x, y, 0])
    t1 = Text(f"{name} · {ROLE[name]}", font_size=20, weight=BOLD, color="#ffffff")
    t2 = Text("network key" if name != "W" else "signs CTRL · runs the IPS", font_size=14, color=SUB)
    if t1.width > NW - 0.25:
        t1.scale_to_fit_width(NW - 0.25)
    VGroup(t1, t2).arrange(DOWN, buff=0.1).move_to([x, y, 0])
    return VGroup(r, t1, t2)


def mini_packet(w=0.9, h=0.22):
    parts = [(30, "#5b6b8a"), (24, "#6b7280"), (170, "#2950b8"), (16, "#c98a12")]
    x = -w / 2
    g = VGroup()
    for n, col in parts:
        pw = w * n / 240
        g.add(Rectangle(width=pw, height=h, fill_color=col, fill_opacity=1, stroke_width=0).move_to([x + pw / 2, 0, 0]))
        x += pw
    return g


def bubble(content, color=CYAN, tail_to=None, pad=0.25):
    """Rounded box around content with a tail pointing at tail_to (a point)."""
    box = RoundedRectangle(width=content.width + 2 * pad, height=content.height + 2 * pad, corner_radius=0.18,
                           fill_color="#0d1524", fill_opacity=0.96, stroke_color=color, stroke_width=3)
    box.move_to(content)
    g = VGroup(box)
    if tail_to is not None:
        c = box.get_center()
        tail_to = np.array(tail_to)
        d = tail_to - c
        # attach the tail on the box edge nearest the target
        base = c + np.array([np.clip(d[0], -box.width / 2 + 0.4, box.width / 2 - 0.4),
                             -box.height / 2 if d[1] < 0 else box.height / 2, 0])
        g.add(Polygon(base + LEFT * 0.16, base + RIGHT * 0.16, tail_to, fill_color="#0d1524", fill_opacity=0.96,
                      stroke_color=color, stroke_width=3))
        box.set_z_index(1)
    g.add(content.set_z_index(2))
    return g


def field_row(specs, h=0.42, font=15):
    """specs: [(width, color, top text, bottom text, bottom color)] -> mini header bar with notes underneath."""
    g, x = VGroup(), 0
    for w, col, top, bot, bcol in specs:
        r = Rectangle(width=w, height=h, fill_color=col, fill_opacity=1, stroke_color="#0d1524", stroke_width=3)
        r.move_to([x + w / 2, 0, 0])
        t = Text(top, font_size=font, weight=BOLD, color="#ffffff").move_to(r)
        if t.width > w - 0.08:
            t.scale_to_fit_width(w - 0.08)
        b = Text(bot, font_size=font - 1, color=bcol, weight=BOLD).next_to(r, DOWN, buff=0.1)
        g.add(VGroup(r, t, b))
        x += w
    return g


def check_mark(size=1.0, color=GREEN):
    m = VMobject(stroke_color=color, stroke_width=22)
    m.set_points_as_corners([[-0.5 * size, 0, 0], [-0.12 * size, -0.42 * size, 0], [0.62 * size, 0.55 * size, 0]])
    return m


def placeholder(width, color="#2b3a6b", h=0.09):
    return RoundedRectangle(width=width, height=h, corner_radius=h / 2, fill_color=color, fill_opacity=1,
                            stroke_width=0)


def log_entry(title, note, chips, icon_color, width=4.2, live=False):
    icon = RoundedRectangle(width=0.42, height=0.42, corner_radius=0.08, fill_color="#3b1d2a" if live else "#22305c",
                            fill_opacity=1, stroke_width=0)
    if live:
        ring = Circle(radius=0.12, stroke_color=icon_color, stroke_width=4).move_to(icon)
        bar_ = Line(ring.point_at_angle(np.pi * 0.75), ring.point_at_angle(-np.pi * 0.25), color=icon_color,
                    stroke_width=4)
        icon = VGroup(icon, ring, bar_)
    else:
        icon = VGroup(icon, Circle(radius=0.08, fill_color=icon_color, fill_opacity=1, stroke_width=0).move_to(icon))
    if live:
        head = Text(title, font_size=19, weight=BOLD, color="#ffffff")
        sub = Text(note, font_size=14, color=SUB)
    else:
        head = placeholder(2.0, "#3a4a7d", 0.13)
        sub = placeholder(1.4)
    lines = VGroup(head, sub, placeholder(width - 1.0), placeholder(width - 1.6)).arrange(DOWN, aligned_edge=LEFT,
                                                                                         buff=0.12)
    chip_row = VGroup()
    for text, col in chips:
        t = Text(text, font_size=13, weight=BOLD, color=col)
        bg = RoundedRectangle(width=t.width + 0.24, height=0.28, corner_radius=0.14, fill_color=col,
                              fill_opacity=0.16, stroke_width=0)
        chip_row.add(VGroup(bg, t.move_to(bg)))
    chip_row.arrange(RIGHT, buff=0.12)
    if chips:
        lines.add(chip_row)
        lines.arrange(DOWN, aligned_edge=LEFT, buff=0.12)
    body = VGroup(icon, lines).arrange(RIGHT, aligned_edge=UP, buff=0.18)
    if live:
        rail = Line(lines.get_corner(UP + LEFT) + LEFT * 0.08, lines.get_corner(DOWN + LEFT) + LEFT * 0.08,
                    color=BLUE, stroke_width=3)
        body.add(rail)
    return body


class AttackClip(PacketClip):
    # world <-> screen: screen = s * world + o. "world" holds the map; HUD (title, caption, IPS panel) stays put.
    def focus(self, cx, cy, width, screen_center=(0, -0.2), edit=None):
        """Zoom/pan the world so world point (cx, cy) lands at screen_center and `width` world units fill 13 units."""
        new_s = 13.0 / width
        k = new_s / self.s
        target = np.array([*screen_center, 0.0])
        d = target - (new_s * np.array([cx, cy, 0.0]) + k * self.o)
        self.s, self.o = new_s, k * self.o + d
        target_mob = self.world.copy().scale(k, about_point=np.zeros(3)).shift(d)
        if edit:                                         # other changes to the world in the same animation
            edit(target_mob)
        return Transform(self.world, target_mob)

    def caption(self, text):
        """Same as PacketClip's, plus a dark backdrop so the line stays readable over the map."""
        anims = []
        if getattr(self, "_cap", None) is not None:
            anims.append(FadeOut(self._cap, run_time=0.25))
        self._cap = None
        if CAPTIONS and text:
            t = Text(text, font_size=24, color="#ffffff").to_edge(DOWN, buff=0.45)
            self._cap = VGroup(BackgroundRectangle(t, color=BG, fill_opacity=0.85, buff=0.14), t).set_z_index(10)
            anims.append(FadeIn(self._cap, run_time=0.35))
        return anims

    def at(self, x, y):
        return self.s * np.array([x, y, 0.0]) + self.o

    def construct(self):
        # ---- start on PacketClip's last frame (rendered silently) ------------------------
        self.renderer._original_skipping_status = True
        super().construct()
        self.renderer._original_skipping_status = False
        self.renderer.skip_animations = False
        packet_end = [m for m in self.mobjects]             # everything on screen at the end of PacketClip
        tag = packet_end[0]

        # ---- build the map (world) ------------------------------------------------------
        links = VGroup()
        for a, b, dashed in [("A", "B", False), ("B", "C", False), ("A", "D", True), ("D", "C", True)]:
            pa, pb = np.array([*POS[a], 0]), np.array([*POS[b], 0])
            u = (pb - pa) / np.linalg.norm(pb - pa)
            ln = Line(pa + u * 1.05, pb - u * 1.05, color=NODE_LINE, stroke_width=3)
            links.add(DashedVMobject(ln, num_dashes=14) if dashed else ln)
        x_arrow = DashedVMobject(Arrow([-4.2, -1.5, 0], [-4.2, -0.2, 0], buff=0, color=RED, stroke_width=3,
                                       max_tip_length_to_length_ratio=0.18), num_dashes=10)
        region = RoundedRectangle(width=12.4, height=5.3, corner_radius=0.3, fill_color="#151b27", fill_opacity=1,
                                  stroke_color="#2a3346", stroke_width=2).move_to([0, -0.3, 0])
        region_tx = Text("ESP-NOW · one Wi-Fi channel · every frame 240 B", font_size=15, color=SUB)
        region_tx.next_to(region.get_corner(DOWN + RIGHT), UP + LEFT, buff=0.15)
        nodes = {n: node(n) for n in POS}
        mapg = VGroup(region, region_tx, links, x_arrow, *nodes.values())

        # the frame being replayed sits next to X; PacketClip's bar is the same frame, zoomed way in
        P = np.array([-2.35, -2.0, 0.0])
        icon = mini_packet().move_to(P).set_z_index(3)      # in front of bubbles (z 1-2)
        bar = self.cip                                       # PacketClip's encrypted-part bar
        hud_old = [m for m in packet_end if m is not tag and m is not bar]
        self.s = bar.width / icon.width
        self.o = bar.get_center() - self.s * P
        self.world = VGroup(mapg, icon)
        self.world.scale(self.s, about_point=np.zeros(3)).shift(self.o)
        icon.set_opacity(0)
        mapg.set_opacity(0)
        self.add(self.world)
        self.bring_to_front(bar)

        # ---- 1. zoom out and pan to the map (0-3.5 s) -----------------------------------
        self._cap = None
        self._title = None
        tag2 = Text("Testbed: A → B → C, backup D, attacker X, watchtower W", font_size=20, color=SUB)
        tag2.to_corner(UP + LEFT, buff=0.35)
        self.play(*[FadeOut(m) for m in hud_old], FadeOut(tag), FadeIn(tag2), run_time=0.4)
        self.remove(bar)
        self.world.add(bar)                                  # ride along with the zoom, then hand over to the icon
        self.play(self.focus(0, -0.3, 13.2, edit=lambda w: w[0].set_opacity(1)),
                  run_time=1.9, rate_func=smooth)
        self.play(FadeOut(bar), icon.animate.set_opacity(1), *self.title("Replay attack"),
                  *self.caption("X recorded a real frame from A four minutes ago. Now it sends it again."),
                  run_time=0.4)
        self.world.remove(bar)
        self.wait(0.8)                                       # -> 3.5 s

        # ---- 2. the replayed frame, zoom up top (3.5-7.0 s) -----------------------------
        rings = VGroup(*[Circle(radius=r, stroke_color=RED, stroke_width=3).move_to(self.at(*POS["X"]))
                         for r in (0.3, 0.55, 0.8)])
        red = Circle(radius=1.0, stroke_color=RED, stroke_width=5).stretch(1.55, 0).move_to(self.at(*POS["A"]))
        mid = (np.array([*POS["A"], 0]) + np.array([*POS["B"], 0])) / 2 + np.array([-0.4, 0.15, 0])
        self.play(FadeIn(rings, scale=0.5), icon.animate.move_to(self.at(*mid[:2])), Create(red),
                  *self.caption("Every byte is A's, unchanged, so the link tag still checks out."), run_time=0.8)
        self.remove(rings)
        self.world.add(red)
        red_note = Text("pretends to be A", font_size=18, weight=BOLD, color=RED)
        red_note.next_to(red, DOWN, buff=0.05)
        self.world.add(red_note.set_opacity(0))
        fields = field_row([(1.25, "#3f8796", "msg_id", "copied", RED), (1.25, "#2f6fb5", "src_pseudo", "A's", RED),
                            (0.9, "#8c4f6a", "epoch", "1038", AMBER), (1.25, "#c98a12", "link_tag", "valid", GREEN)])
        head = Text("Replayed frame", font_size=20, weight=BOLD, color=CYAN)
        body1 = VGroup(head, fields).arrange(DOWN, buff=0.18, aligned_edge=LEFT)
        body1.move_to([-3.75, 2.25, 0])                     # world coords, top-left above A
        b1 = bubble(body1, CYAN, tail_to=[*(mid + np.array([0, 0.2, 0]))])
        b1.scale(self.s, about_point=np.zeros(3)).shift(self.o)
        self.world.add(b1)
        b1.set_opacity(0)
        self.play(b1.animate.set_opacity(1), red_note.animate.set_opacity(1), FadeOut(self._title), run_time=0.6)
        self._title = None
        self.wait(0.3)
        self.play(self.focus(-2.4, 1.4, 9.6), run_time=1.2, rate_func=smooth)
        self.wait(0.6)                                       # -> 7.0 s

        # ---- 3. B checks it, zoom to B (7.0-10.5 s) --------------------------------------
        bpos = np.array([*POS["B"], 0])
        green = RoundedRectangle(width=NW + 0.3, height=NH + 0.3, corner_radius=0.18, stroke_color=GREEN,
                                 stroke_width=5).move_to(bpos)
        exp = VGroup(Text("Expected:", font_size=18, weight=BOLD, color=CYAN),
                     Text("epoch 1041–1043 (now 1042 ± 1)", font_size=17, color="#ffffff"))
        real = VGroup(Text("Real:", font_size=18, weight=BOLD, color=CYAN),
                      Text("epoch 1038 (4 minutes old)", font_size=17, color=AMBER))
        for row in (exp, real):
            row.arrange(RIGHT, buff=0.18)
        tagline = Text("link tag valid: it's an exact copy", font_size=14, color=SUB)
        body2 = VGroup(exp, real, tagline).arrange(DOWN, aligned_edge=LEFT, buff=0.16)
        real[1].align_to(exp[1], LEFT)
        body2.move_to([-3.75, 2.3, 0])
        b2 = bubble(body2, CYAN, tail_to=[-1.3, 1.75, 0])
        b2.scale(self.s, about_point=np.zeros(3)).shift(self.o)
        green.scale(self.s, about_point=np.zeros(3)).shift(self.o)
        trail = Arrow(icon.get_center(), self.at(-1.35, 1.45), buff=0.05, color=RED, stroke_width=6)
        self.play(Create(trail), icon.animate.move_to(self.at(-1.85, 1.45)).scale(0.8),
                  *self.caption("Relay B checks it: the epoch says 1038, but B only takes 1041–1043."),
                  run_time=0.7)
        self.world.add(trail)
        self.play(Create(green), FadeOut(b1), FadeIn(b2), run_time=0.6)
        self.world.remove(b1)
        self.world.add(green, b2)
        self.play(self.focus(-1.9, 1.85, 8.6), run_time=1.1, rate_func=smooth)
        self.wait(1.1)                                       # -> 10.5 s

        # ---- 4. attack found, frame dropped (10.5-14.0 s) --------------------------------
        cross = VGroup(Line(UP + LEFT, DOWN + RIGHT), Line(UP + RIGHT, DOWN + LEFT)).set_stroke(RED, 14)
        cross.scale(0.55).set_z_index(5).move_to(b2[0].get_corner(UP + RIGHT) + np.array([0.12, 0.12, 0]))
        drop_tx = VGroup(Text("Drop", font_size=26, weight=BOLD, color="#ffffff"),
                         Text("not relayed", font_size=16, color=SUB)).arrange(DOWN, buff=0.06)
        drop_tx.move_to(self.at(1.95, 2.75))
        drop = bubble(drop_tx, CYAN, tail_to=self.at(0.9, 1.95))
        self.play(b2[0].animate.set_stroke(RED), Create(cross), run_time=0.5)
        self.play(FadeIn(drop, shift=DOWN * 0.15), icon.animate.set_opacity(0).scale(0.4), FadeOut(trail),
                  *self.caption("Too old: B drops the frame and never passes it on."), run_time=0.6)
        self.world.remove(trail)
        self.world.add(cross, drop)
        self.world.remove(icon)
        self.wait(2.4)                                       # -> 14.0 s

        # ---- 5. zoom out to the system; IPS log slides in (14.0-17.5 s) ------------------
        self.play(FadeOut(VGroup(cross, drop, b2, red, red_note)), run_time=0.3)
        self.world.remove(cross, drop, b2, red, red_note)
        panel = RoundedRectangle(width=5.2, height=5.4, corner_radius=0.2, fill_color=NAVY, fill_opacity=1,
                                 stroke_color="#2b3a6b", stroke_width=2)
        brand = VGroup(Text("Ghost", font_size=22, weight=BOLD, color="#ffffff"),
                       Text("Mesh", font_size=22, weight=BOLD, color="#4f7cff")).arrange(RIGHT, buff=0.02)
        brand_sub = Text("AI watchtower · IPS logs", font_size=14, color=SUB)
        act = Text("Activity", font_size=21, weight=BOLD, color="#ffffff")
        act_sub = Text("What the IPS did, newest first", font_size=14, color=SUB)
        old1 = log_entry("", "", [("", SUB)][:0], "#5b6678")
        old2 = log_entry("", "", [], "#5b6678")
        olds = VGroup(old1, old2).arrange(DOWN, aligned_edge=LEFT, buff=0.3).set_opacity(0.55)
        top = VGroup(VGroup(brand, brand_sub).arrange(DOWN, aligned_edge=LEFT, buff=0.06),
                     VGroup(act, act_sub).arrange(DOWN, aligned_edge=LEFT, buff=0.06)).arrange(DOWN, aligned_edge=LEFT,
                                                                                               buff=0.3)
        live = log_entry("Replay attack: Node X", "old frames re-sent · epoch 4 min stale",
                         [("AI: replay", GREEN), ("dropped at B", CYAN), ("BLOCK sent", RED)], RED, live=True)
        col = VGroup(top, live, olds).arrange(DOWN, aligned_edge=LEFT, buff=0.3)
        panel_g = VGroup(panel, col)
        col.move_to(panel).align_to(panel, LEFT).shift(RIGHT * 0.3)
        panel_g.move_to([4.05, -0.2, 0])
        live_final = live.get_center()
        col.remove(live)
        panel_bg = VGroup(panel, col).shift(RIGHT * 6)
        flag = Arrow([7.4, live_final[1], 0], [live_final[0] + 2.4, live_final[1], 0], color=RED, stroke_width=7,
                     buff=0)

        wpos = np.array([*POS["W"], 0])
        self.play(self.focus(-0.2, -0.3, 13.0 / 0.62, screen_center=(-2.7, -0.25)), panel_bg.animate.shift(LEFT * 6),
                  *self.caption("The watchtower heard it too: the IPS logs a replay from X."), run_time=1.2,
                  rate_func=smooth)
        pulse = VGroup(*[DashedVMobject(Circle(radius=r * self.s, stroke_color=YELLOW, stroke_width=4), num_dashes=16)
                         .move_to(self.at(*wpos[:2])) for r in (1.0, 1.6)])
        self.play(FadeIn(pulse, scale=0.6), Create(flag), run_time=0.5)
        self.play(FadeIn(live, shift=LEFT * 5.5), FadeOut(flag), FadeOut(pulse), run_time=0.7)
        self.wait(0.8)                                       # -> 17.5 s

        # ---- 6. checkmark (17.5-20.0 s) -------------------------------------------------
        tick = check_mark(2.4).move_to([-2.6, -0.4, 0])
        self.play(Create(tick), self.world.animate.set_opacity(0.3), *self.caption("Replay stopped at the first hop, and on the record."), run_time=0.6)
        self.wait(1.9)                                       # -> 20.0 s
