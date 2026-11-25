"""Drive HUD - big, glanceable wardrive numbers for a car screen or tablet.

Six tiles: speed, networks this trip, networks per minute, networks per mile (or
km), distance and trip time, plus a 10-minute rate sparkline. The trip survives
leaving the screen and restarting the game; [R] starts a new one.

Pure stdlib + ctx. Permissions: gps, loot_read.
"""
import math

KM_PER_MI = 1.609344
RATE_WINDOW_S = 60.0      # nets/min is measured over the last minute
SPARK_BUCKET_S = 30.0     # one sparkline bar per 30 s ...
SPARK_BARS = 20           # ... for the last 10 minutes
MIN_STEP_M = 8.0          # ignore GPS jitter smaller than this
MAX_KMH = 250.0           # ignore jumps implying more than this
SAVE_EVERY_S = 15.0
POLL_S = 1.0


def _haversine_km(a_lat, a_lon, b_lat, b_lon):
    r = 6371.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dphi = math.radians(b_lat - a_lat)
    dl = math.radians(b_lon - a_lon)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


def _fmt_time(s):
    s = int(s)
    return "%d:%02d:%02d" % (s // 3600, (s // 60) % 60, s % 60) if s >= 3600 else "%d:%02d" % (s // 60, s % 60)


class Extra:
    def on_load(self, ctx):
        st = ctx.storage.read_json("trip.json", default=None) or {}
        self.metric = bool(st.get("metric", False))          # default miles (US)
        self.trip = st.get("trip") or self._new_trip()
        self.last_save = 0.0

    @staticmethod
    def _new_trip():
        return {"nets": 0, "km": 0.0, "secs": 0.0, "best_rate": 0, "last_count": None}

    def on_enter(self, ctx):
        self.gps, self.loot = ctx.gps, ctx.loot
        self.last_fix = None          # (lat, lon, t) of the last accepted point
        self.speed = 0.0
        self.samples = []             # (t, trip_nets) for the rolling rate
        self.spark = []               # per-bucket new-net counts
        self.bucket_t = ctx.now()
        self.bucket_n = 0
        self.last_poll = -POLL_S
        self.msg = ("", 0.0)
        self._poll(ctx)               # pick up nets collected while the screen was closed

    def _save(self, ctx):
        ctx.storage.write_json("trip.json", {"metric": self.metric, "trip": self.trip})
        self.last_save = ctx.now()

    # ---- data --------------------------------------------------------------
    def _poll(self, ctx):
        if self.loot is None:
            return
        c = int(self.loot.counts().get("networks", 0))
        last = self.trip.get("last_count")
        if last is not None and c >= last:
            d = c - last
            self.trip["nets"] += d
            self.bucket_n += d
        # c < last: the game started a new session and its list reset - just re-anchor
        self.trip["last_count"] = c

    def _gps(self, ctx, now):
        fix = self.gps.fix() if self.gps is not None else None
        if not fix or not fix.get("valid"):
            self.last_fix = None
            self.speed *= 0.9
            return None
        lat, lon = fix["lat"], fix["lon"]
        if self.last_fix is None:
            self.last_fix = (lat, lon, now)
        else:
            dts = now - self.last_fix[2]
            if dts >= 1.0:
                km = _haversine_km(self.last_fix[0], self.last_fix[1], lat, lon)
                kmh = km / dts * 3600.0
                if kmh > MAX_KMH:                      # a GPS jump - re-anchor, don't count it
                    self.last_fix = (lat, lon, now)
                elif km * 1000.0 >= MIN_STEP_M:
                    self.trip["km"] += km
                    self.speed = self.speed * 0.5 + kmh * 0.5
                    self.last_fix = (lat, lon, now)
                elif dts >= 3.0:                       # sitting still
                    self.speed *= 0.5
                    self.last_fix = (lat, lon, now)
        rep = fix.get("speed_kmh") or 0.0
        if rep > 0.5:                                  # trust the receiver's own speed when it has one
            self.speed = self.speed * 0.4 + rep * 0.6
        return fix

    def _rate(self, now):
        self.samples.append((now, self.trip["nets"]))
        while self.samples and now - self.samples[0][0] > RATE_WINDOW_S:
            self.samples.pop(0)
        if len(self.samples) < 2:
            return 0.0
        dt = self.samples[-1][0] - self.samples[0][0]
        if dt < 5.0:
            return 0.0
        return (self.samples[-1][1] - self.samples[0][1]) / dt * 60.0

    # ---- frame -------------------------------------------------------------
    def on_frame(self, ctx, dt):
        now = ctx.now()
        self.trip["secs"] += max(0.0, min(dt, 1.0))
        if ctx.key_pressed("u"):
            self.metric = not self.metric
            self._save(ctx)
        if ctx.key_pressed("r"):
            self.trip = self._new_trip()
            self.samples, self.spark, self.bucket_n = [], [], 0
            self.last_fix = None
            self._poll(ctx)
            self._save(ctx)
            self.msg = ("new trip started", now + 3.0)
            ctx.log("Drive HUD: new trip")
        if now - self.last_poll >= POLL_S:
            self.last_poll = now
            self._poll(ctx)
        if now - self.bucket_t >= SPARK_BUCKET_S:
            self.spark.append(self.bucket_n)
            self.spark = self.spark[-SPARK_BARS:]
            self.bucket_t, self.bucket_n = now, 0
        fix = self._gps(ctx, now)
        rate = self._rate(now)
        self.trip["best_rate"] = max(self.trip.get("best_rate", 0), int(round(rate)))
        if now - self.last_save >= SAVE_EVERY_S:
            self._save(ctx)

        unit = "km" if self.metric else "mi"
        dist = self.trip["km"] if self.metric else self.trip["km"] / KM_PER_MI
        spd = self.speed if self.metric else self.speed / KM_PER_MI
        per_unit = (self.trip["nets"] / dist) if dist >= 0.25 else 0.0

        w, h = ctx.w, ctx.h
        if self.loot is None:
            ctx.text("needs the loot_read permission", 10, 10, 20, "danger")
            return
        tiles = [
            ("SPEED", "%.0f" % spd, "mph" if not self.metric else "km/h", "ice"),
            ("NETS THIS TRIP", "{:,}".format(self.trip["nets"]), "", "hi"),
            ("NETS / MIN", "%.0f" % rate, "best %d" % self.trip["best_rate"], "success"),
            ("NETS / " + unit.upper(), "%.0f" % per_unit if per_unit else "--", "", "teal"),
            ("DISTANCE", "%.1f" % dist, unit, "txt"),
            ("TRIP TIME", _fmt_time(self.trip["secs"]), "", "txt"),
        ]
        cols, rows = 3, 2
        pad, foot = 10, 96
        tw = (w - pad * (cols + 1)) // cols
        th = (h - foot - pad * (rows + 1)) // rows
        big = max(28, min(80, int(th * 0.55)))
        for i, (label, val, sub, col) in enumerate(tiles):
            x = pad + (i % cols) * (tw + pad)
            y = pad + (i // cols) * (th + pad)
            ctx.rect(x, y, tw, th, "edge", fill=True, alpha=60)
            ctx.rect(x, y, tw, th, "edge", fill=False)
            ctx.text(label, x + 12, y + 8, 18, "dim", bold=True)
            vw = ctx.measure(val, big)
            ctx.text(val, x + (tw - int(vw)) // 2, y + (th - big) // 2 + 6, big, col, bold=True)
            if sub:
                ctx.text(sub, x + tw - 12 - int(ctx.measure(sub, 18)), y + th - 28, 18, "dim")

        # sparkline: new nets per 30 s over the last 10 minutes
        sy = h - foot + 6
        sh = 44
        ctx.text("last 10 min", pad, sy, 14, "dim")
        bars = self.spark + [self.bucket_n]
        peak = max([1] + bars)
        bw = max(4, (w // 2 - 120) // SPARK_BARS)
        for i, n in enumerate(bars[-(SPARK_BARS + 1):]):
            bh = int(sh * n / peak)
            bx = pad + 100 + i * (bw + 2)
            ctx.rect(bx, sy + sh - bh, bw, max(1, bh), "success" if i == len(bars) - 1 else "teal",
                     fill=True)

        gps_txt = ("GPS OK  %d sats" % fix.get("sats", 0)) if fix else "NO GPS FIX - distance & speed paused"
        ctx.text(gps_txt, w // 2 + 20, sy, 18, "success" if fix else "warn", bold=True)
        if self.msg[0] and now < self.msg[1]:
            ctx.text(self.msg[0], w // 2 + 20, sy + 28, 16, "success")
        else:
            ctx.text("[U] %s   [R] new trip" % ("miles" if self.metric else "kilometres"),
                     w // 2 + 20, sy + 28, 16, "dim")

    def on_exit(self, ctx):
        self._save(ctx)

    def on_unload(self, ctx):
        self._save(ctx)
