"""close_clip.py - 6 s closing slide: team names on the left, a QR code to the GitHub repo on the right.

    ~/manim-venv/Scripts/manim -qh docs/diagrams/close_clip.py CloseClip

Layout from Jose's sketch (Nov 20). Same look as packet_clip.py / attack_clip.py. Needs `segno` (pip install segno).
"""
import segno
from manim import (BOLD, DOWN, LEFT, RIGHT, UP, FadeIn, LaggedStart, Rectangle, RoundedRectangle, Scene, Text,
                   VGroup, config)

config.background_color = "#111318"
Text.set_default(font="DejaVu Sans")
SUB, BLUE = "#9aa1ad", "#4f7cff"
REPO = "https://github.com/PatriotHackFestF26/GhostMesh"
TEAM = [("Yunus", "Hassen"), ("Hannan", "Ahmed"), ("Jose", "Perez"), ("Rashad", "Safir")]


def qr_code(url, size):
    """QR as white card + black squares (4-module quiet zone, as the spec asks)."""
    m = segno.make(url, error="m").matrix
    n = len(m) + 8
    cell = size / n
    card = RoundedRectangle(width=size, height=size, corner_radius=0.12, fill_color="#ffffff", fill_opacity=1,
                            stroke_width=0)
    dots = VGroup()
    for r, row in enumerate(m):
        for c, v in enumerate(row):
            if v:
                sq = Rectangle(width=cell * 1.02, height=cell * 1.02, fill_color="#000000", fill_opacity=1,
                               stroke_width=0)
                sq.move_to(card.get_corner(UP + LEFT) + [(c + 4.5) * cell, -(r + 4.5) * cell, 0])
                dots.add(sq)
    return VGroup(card, dots)


class CloseClip(Scene):
    def construct(self):
        frame = RoundedRectangle(width=12.6, height=6.2, corner_radius=0.3, stroke_color="#3a4257", stroke_width=3,
                                 fill_color="#151b27", fill_opacity=1)
        brand = VGroup(Text("Ghost", font_size=44, weight=BOLD, color="#ffffff"),
                       Text("Mesh", font_size=44, weight=BOLD, color=BLUE)).arrange(RIGHT, buff=0.04)
        tagline = Text("Encrypted ESP32 mesh with an AI watchtower", font_size=22, color=SUB)
        names = VGroup()
        for first, last in TEAM:
            row = VGroup(Text(first, font_size=38, weight=BOLD, color="#ffffff"),
                         Text(last, font_size=38, color="#d6dae2")).arrange(RIGHT, buff=0.25)
            names.add(row)
        names.arrange(DOWN, aligned_edge=LEFT, buff=0.38)
        left = VGroup(VGroup(brand, tagline).arrange(DOWN, aligned_edge=LEFT, buff=0.12), names)
        left.arrange(DOWN, aligned_edge=LEFT, buff=0.6)

        qr = qr_code(REPO, 3.6)
        cap = Text("github.com/PatriotHackFestF26/GhostMesh", font_size=17, color=SUB).next_to(qr, DOWN, buff=0.2)
        scan = Text("Scan for the code, data and docs", font_size=20, weight=BOLD, color="#ffffff")
        scan.next_to(qr, UP, buff=0.2)
        right = VGroup(scan, qr, cap)

        VGroup(left, right).arrange(RIGHT, buff=1.4).move_to(frame)
        self.add(frame)
        self.play(FadeIn(left[0], shift=UP * 0.15), run_time=0.5)
        self.play(LaggedStart(*[FadeIn(r, shift=RIGHT * 0.2) for r in names], lag_ratio=0.25),
                  FadeIn(right, shift=LEFT * 0.2), run_time=1.0)
        self.wait(4.5)                                                                     # -> 6.0 s
