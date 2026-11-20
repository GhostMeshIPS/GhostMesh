"""
viz_frames.py - what is on screen at sim time T, for one panel of a clip (pure Python, no Manim).

Packets are drawn sliding along each link over TRAVEL ms of sim time (real airtime is ~2.5 ms,
too fast to see). Everything a reception triggers (heard, cancelled, delivered) is shown when
its packet dot arrives, so the picture stays in order. Transmit times are the real ones.
"""
import colorsys

TRAVEL = 8.0          # ms a packet dot takes along a link
RING_MS = 30.0        # ms a transmission ring stays visible

COLORS = {
    "idle": "#4a5160", "src": "#22c06a", "dst": "#e8e8e8", "heard": "#f2b134", "relayed": "#3b8bff",
    "cancelled": "#737a86", "delivered": "#ff4f8b", "ack": "#b07cff", "down": "#ff3b3b", "tx": "#3b8bff",
    "data": "#ffffff", "ack_pkt": "#d2b8ff", "other": "#8a909c", "lost": "#ff3b3b", "edge": "#2c313a",
}

LEGEND = [("sender A", "src"), ("heard, waiting (jitter)", "heard"), ("relayed", "relayed"),
          ("stayed quiet (heard k copies)", "cancelled"), ("C got it", "delivered"), ("relayed the ACK", "ack"),
          ("transmitting (packet color = which message)", "tx"), ("reception lost to a collision", "lost")]


def msg_color(idx):
    # distinct-ish hue per message for the load clip
    h = (idx * 0.618034) % 1.0
    r, g, b = colorsys.hls_to_rgb(h, 0.62, 0.75)
    return "#%02x%02x%02x" % (int(r * 255), int(g * 255), int(b * 255))


class Timeline:
    def __init__(self, panel, travel=TRAVEL, ring_ms=RING_MS):
        p = self.p = panel
        self.travel, self.ring_ms = travel, ring_ms
        self.pos, self.n, self.R = p["pos"], p["n"], p["radio_range"]
        self.adj = [[] for _ in range(self.n)]
        for a, b in p["edges"]:
            self.adj[a].append(b)
            self.adj[b].append(a)
        self.down = {int(k): v for k, v in p["down"].items()}
        self.shift = travel - p["airtime_ms"]                # reception-triggered things show on arrival
        self.frames = sorted(p["frames"], key=lambda f: f["t0"])
        self.rx = {(r["id"], r["frm"], r["to"]): r["ok"] for r in p["rx"]}
        self.focus = p.get("focus")
        if self.focus is None:
            return
        m = self.m = p["messages"][self.focus]
        self.src, self.dst = m["src"], m["dst"]
        fd = {f["id"] for f in self.frames if f["msg"] == self.focus and f["kind"] == "data"}
        fa = {f["id"] for f in self.frames if f["msg"] == self.focus and f["kind"] == "ack"}
        self.heard, self.ack_heard, self.tx, self.ack_tx, self.cancel = {}, {}, {}, {}, {}
        for r in p["rx"]:
            if r["ok"] and r["id"] in fd:
                self.heard.setdefault(r["to"], r["t"] + self.shift)
            if r["ok"] and r["id"] in fa:
                self.ack_heard.setdefault(r["to"], r["t"] + self.shift)
        for f in self.frames:
            if f["msg"] == self.focus:
                (self.tx if f["kind"] == "data" else self.ack_tx).setdefault(f["node"], f["t0"])
        for e in p["events"]:
            if e["ev"] == "RELAY_CANCELLED" and e["msg"] == self.focus and e["kind"] == "data":
                self.cancel.setdefault(e["node"], e["t"] + self.shift)
        self.delivered_at = m["delivered"] + self.shift if m["delivered"] is not None else None

    # ---- nodes ----

    def is_down(self, i, T):
        return i in self.down and T >= self.down[i]

    def node_states(self, T):
        out = []
        for i in range(self.n):
            if self.is_down(i, T):
                out.append("down")
            elif self.focus is None:
                busy = any(f["node"] == i and f["t0"] <= T < f["t1"] + self.travel for f in self._active(T))
                out.append("tx" if busy else "idle")
            elif i == self.src:
                out.append("src")
            elif i == self.dst:
                out.append("delivered" if self.delivered_at is not None and self.delivered_at <= T else "dst")
            elif self.ack_tx.get(i, 1e18) <= T:
                out.append("ack")
            elif self.tx.get(i, 1e18) <= T:
                out.append("relayed")
            elif self.cancel.get(i, 1e18) <= T:
                out.append("cancelled")
            elif self.heard.get(i, 1e18) <= T:
                out.append("heard")
            else:
                out.append("idle")
        return out

    # ---- moving things ----

    def _active(self, T):
        lo = T - max(self.travel, self.ring_ms) - 20
        return [f for f in self.frames if lo <= f["t0"] <= T]

    def packets(self, T):
        """(from_xy, to_xy, progress 0..1, color, opacity) for every packet dot on screen."""
        out = []
        for f in self._active(T):
            a = (T - f["t0"]) / self.travel
            if not 0 <= a <= 1:
                continue
            i = f["node"]
            mine = self.focus is None or f["msg"] == self.focus
            for j in self.adj[i]:
                if self.is_down(j, f["t0"]):
                    continue
                ok = self.rx.get((f["id"], i, j), True)
                if self.focus is None:
                    col = msg_color(f["msg"] or 0)
                else:
                    col = COLORS["data"] if f["kind"] == "data" else COLORS["ack_pkt"]
                    if not mine:
                        col = COLORS["other"]
                if not ok and a > 0.55:
                    col = COLORS["lost"]
                out.append((self.pos[i], self.pos[j], a, col, 1.0 if mine else 0.35))
        return out

    def rings(self, T):
        """(center_xy, radius, color, opacity) for every transmission ring on screen."""
        out = []
        for f in self._active(T):
            age = T - f["t0"]
            if not 0 <= age < self.ring_ms:
                continue
            mine = self.focus is None or f["msg"] == self.focus
            if self.focus is None:
                col = msg_color(f["msg"] or 0)
            elif not mine:
                col = COLORS["other"]
            elif f["node"] == self.src and f["kind"] == "data":
                col = COLORS["src"]
            else:
                col = COLORS["relayed"] if f["kind"] == "data" else COLORS["ack"]
            r = self.R * min(1.0, age / (0.5 * self.ring_ms))
            out.append((self.pos[f["node"]], r, col, (1 - age / self.ring_ms) * (0.75 if mine else 0.25)))
        return out

    def collisions(self, T, flash=15.0):
        """(xy, opacity) for receivers whose reception just got destroyed (load clip)."""
        out = []
        for r in self.p["rx"]:
            t = r["t"] + self.shift
            if not r["ok"] and t <= T < t + flash:
                out.append((self.pos[r["to"]], 1 - (T - t) / flash))
        return out

    # ---- counters ----

    def counts(self, T):
        """Running numbers for on-screen counters."""
        if self.focus is None:
            return {"sent": sum(1 for m in self.p["messages"].values() if self.p["window"][0] <= m["sent"] <= T),
                    "collisions": sum(1 for r in self.p["rx"] if not r["ok"] and r["t"] + self.shift <= T),
                    "delivered": sum(1 for m in self.p["messages"].values()
                                     if m["delivered"] is not None and self.p["window"][0] <= m["delivered"] + self.shift <= T)}
        return {"transmissions": sum(1 for f in self.frames if f["msg"] == self.focus and f["t0"] <= T),
                "relayed": sum(1 for t in self.tx.values() if t <= T) - (1 if self.tx.get(self.src, 1e18) <= T else 0),
                "quiet": sum(1 for i, t in self.cancel.items() if t <= T and i not in self.tx),
                "ack_tx": sum(1 for t in self.ack_tx.values() if t <= T)}
