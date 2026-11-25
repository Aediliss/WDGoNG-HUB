"""Surveillance Spotter - flags Flock ALPR cameras and related surveillance gear
in the networks your wardrive picks up, with a GPS position for every sighting.

Detection is tiered, because a vendor MAC prefix alone is NOT proof of a camera
(the same Liteon / Silicon Labs radios ship in plenty of ordinary devices):

  CONFIRMED  the SSID itself names the device: "Flock", "Flock-XXXXXX",
             "Penguin...", "Pigvision...", "FS Ext Battery"
  SUSPECT    MAC prefix registered to / strongly tied to Flock hardware
  WEAK       contract-manufacturer MAC prefix seen on Flock units but also on
             lots of unrelated gear - hidden unless you turn it on with [W]
  KEYWORD    an SSID contains one of your own watch words (add with [K])

Known look-alikes (ClickShare, WiFi-Direct printers, Android hotspots, other
detectors' "Flock ALPR [...]" output) are excluded before matching.

Pure stdlib + ctx. Permissions: gps, loot_read, loot_write.
"""
import time

# ---- detection rules -------------------------------------------------------
CONFIRM_EXACT = ("flock",)                       # bare "Flock" (case-insensitive)
CONFIRM_PREFIX = ("flock-", "flock_", "penguin", "pigvision", "fs ext battery")
EXCLUDE_SUBSTR = ("flock alpr", "clickshare", "smartgate_", "direct-", "androidap",
                  "audi hud", "max-printer")
SUSPECT_OUI = {
    "70:c9:4e": "Flock WiFi (high-tier OUI)",
    "b4:1e:52": "Flock Safety (registered OUI)",
    "3c:91:80": "Flock WiFi device",
    "d8:f3:bc": "Flock WiFi device",
}
WEAK_OUI = {
    "58:8e:81": "Silicon Labs (FS Ext Battery)",
    "ec:1b:bd": "Silicon Labs (FS Ext Battery)",
    "90:35:ea": "Silicon Labs",
    "74:4c:a1": "Liteon", "f4:6a:dd": "Liteon", "9c:2f:9d": "Liteon",
    "c0:35:32": "Liteon", "14:5a:fc": "Liteon", "08:3a:88": "Liteon",
    "e4:aa:ea": "Liteon/USI", "e0:4f:43": "USI", "d0:39:57": "contract mfr",
}
TIER_COLOR = {"CONFIRMED": "danger", "SUSPECT": "warn", "KEYWORD": "magenta", "WEAK": "dim"}
TIER_RANK = {"CONFIRMED": 0, "SUSPECT": 1, "KEYWORD": 2, "WEAK": 3}

POLL_S = 2.0           # how often to re-read the loot list (each read is an IPC call)
ALERT_S = 8.0          # how long the big alert banner stays up
HISTORY_MAX = 1500     # keep the storage file well under the 256 KB cap
SAVE_EVERY_S = 10.0


def _norm_mac(b):
    b = (b or "").strip().lower().replace("-", ":")
    if len(b) == 12 and ":" not in b:
        b = ":".join(b[i:i + 2] for i in range(0, 12, 2))
    return b


def classify(ssid, bssid, keywords, include_weak):
    """-> (tier, reason) or None."""
    s = (ssid or "").strip()
    sl = s.lower()
    if any(x in sl for x in EXCLUDE_SUBSTR):
        return None
    if sl in CONFIRM_EXACT or any(sl.startswith(p) for p in CONFIRM_PREFIX):
        return ("CONFIRMED", "SSID '%s'" % s)
    oui = _norm_mac(bssid)[:8]
    if oui in SUSPECT_OUI:
        return ("SUSPECT", SUSPECT_OUI[oui])
    for k in keywords:
        if k and k in sl:
            return ("KEYWORD", "watch word '%s'" % k)
    if include_weak and oui in WEAK_OUI:
        return ("WEAK", WEAK_OUI[oui])
    return None


def _stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _csv_field(v):
    v = str(v)
    if any(c in v for c in ',"\n'):
        v = '"' + v.replace('"', '""') + '"'
    return v


class Extra:
    def on_load(self, ctx):
        st = ctx.storage.read_json("state.json", default=None) or {}
        self.history = st.get("history", {})          # bssid -> record (all time)
        self.keywords = [str(k).lower() for k in st.get("keywords", [])][:20]
        self.include_weak = bool(st.get("include_weak", False))
        self.dirty = False
        self.last_save = 0.0

    def on_enter(self, ctx):
        self.gps = ctx.gps
        self.loot = ctx.loot
        self.seen = set()            # bssids already classified this visit
        self.counted = set()         # bssids whose sighting was already counted this visit
        self.session = []            # bssids hit since you opened the screen
        self.checked = 0
        self.last_poll = -POLL_S
        self.alert = None            # (record, until)
        self.scroll = 0
        self.typing = None           # str while adding a watch word
        self.msg = ("", 0.0)

    # ---- helpers -----------------------------------------------------------
    def _save(self, ctx, force=False):
        if not self.dirty and not force:
            return
        if len(self.history) > HISTORY_MAX:   # drop the oldest-seen records
            keep = sorted(self.history.items(), key=lambda kv: kv[1].get("last", ""))[-HISTORY_MAX:]
            self.history = dict(keep)
        ctx.storage.write_json("state.json", {"history": self.history, "keywords": self.keywords,
                                              "include_weak": self.include_weak})
        self.dirty = False
        self.last_save = ctx.now()

    def _note(self, ctx, text):
        self.msg = (text, ctx.now() + 4.0)

    def _poll(self, ctx):
        if self.loot is None:
            return
        fix = self.gps.fix() if self.gps is not None else None
        good = bool(fix and fix.get("valid"))
        for n in self.loot.networks():
            b = _norm_mac(n.get("bssid", ""))
            key = b or ("ssid:" + n.get("ssid", ""))
            if key in self.seen:
                continue
            self.seen.add(key)
            self.checked += 1
            hit = classify(n.get("ssid", ""), b, self.keywords, self.include_weak)
            if not hit:
                continue
            tier, reason = hit
            now = _stamp()
            rec = self.history.get(key)
            if rec is None:
                rec = {"bssid": b, "ssid": n.get("ssid", ""), "tier": tier, "reason": reason,
                       "channel": n.get("channel", 0), "first": now, "last": now,
                       "sightings": 0, "lat": None, "lon": None}
                self.history[key] = rec
                new = True
            else:
                new = False
            if key in self.counted:        # a re-check (new watch word / weak toggle), not a new sighting
                if TIER_RANK.get(tier, 9) < TIER_RANK.get(rec.get("tier"), 9):
                    rec["tier"], rec["reason"] = tier, reason
                    self.dirty = True
                continue
            self.counted.add(key)
            rec["sightings"] = int(rec.get("sightings", 0)) + 1
            rec["last"] = now
            rec["ssid"] = n.get("ssid", "") or rec.get("ssid", "")
            if TIER_RANK.get(tier, 9) < TIER_RANK.get(rec.get("tier"), 9):
                rec["tier"], rec["reason"] = tier, reason
            if good:
                rec["lat"], rec["lon"] = round(fix["lat"], 6), round(fix["lon"], 6)
            if key not in self.session:
                self.session.insert(0, key)
            self.dirty = True
            if tier in ("CONFIRMED", "SUSPECT", "KEYWORD"):
                self.alert = (rec, ctx.now() + ALERT_S)
                ctx.log("%s %s %s (%s)%s" % (tier, rec["ssid"] or "<hidden>", b, reason,
                                              "" if new else " - seen before"),
                        "warn" if tier != "CONFIRMED" else "error")

    def _export(self, ctx):
        if ctx.loot_save is None:
            self._note(ctx, "export needs the loot_write permission")
            return
        cols = ["tier", "ssid", "bssid", "reason", "channel", "lat", "lon",
                "first_seen", "last_seen", "sightings"]
        rows = [",".join(cols)]
        recs = sorted(self.history.values(),
                      key=lambda r: (TIER_RANK.get(r.get("tier"), 9), r.get("last", "")))
        for r in recs:
            rows.append(",".join(_csv_field(x) for x in (
                r.get("tier"), r.get("ssid", ""), r.get("bssid", ""), r.get("reason", ""),
                r.get("channel", 0), "" if r.get("lat") is None else r["lat"],
                "" if r.get("lon") is None else r["lon"], r.get("first", ""),
                r.get("last", ""), r.get("sightings", 0))))
        name = "spotter_%s.csv" % time.strftime("%Y%m%d_%H%M%S", time.localtime())
        p = ctx.loot_save(name, "\n".join(rows) + "\n")
        self._note(ctx, ("exported %d sightings -> %s" % (len(recs), name)) if p else "export failed")

    # ---- input -------------------------------------------------------------
    def _keys(self, ctx):
        if self.typing is not None:
            for c in ctx.chars():
                if len(self.typing) < 24:
                    self.typing += c
            if ctx.key_pressed("backspace"):
                if not self.typing:            # backspace on an empty word = cancel
                    self.typing = None
                    return
                self.typing = self.typing[:-1]
            if ctx.key_pressed("enter"):
                w = self.typing.strip().lower()
                if w and w not in self.keywords and len(self.keywords) < 20:
                    self.keywords.append(w)
                    self.seen = set()          # re-check this session's nets
                    self.dirty = True
                    self._note(ctx, "watching for '%s'" % w)
                self.typing = None
            return
        if ctx.key_pressed("k"):
            self.typing = ""
            ctx.chars()                        # drop the 'k' itself
        elif ctx.key_pressed("w"):
            self.include_weak = not self.include_weak
            self.seen = set()
            self.dirty = True
            self._note(ctx, "weak vendor matches %s" % ("ON" if self.include_weak else "OFF"))
        elif ctx.key_pressed("e"):
            self._save(ctx, force=True)
            self._export(ctx)
        elif ctx.key_pressed("x") and self.keywords:
            gone = self.keywords.pop()
            self.dirty = True
            self._note(ctx, "removed watch word '%s'" % gone)
        elif ctx.key_pressed("c"):
            self.session = []
            self.alert = None
            self._note(ctx, "session list cleared (history kept)")
        elif ctx.key_pressed("down"):
            self.scroll += 1
        elif ctx.key_pressed("up"):
            self.scroll = max(0, self.scroll - 1)

    # ---- frame -------------------------------------------------------------
    def on_frame(self, ctx, dt):
        now = ctx.now()
        self._keys(ctx)
        if now - self.last_poll >= POLL_S:
            self.last_poll = now
            self._poll(ctx)
        if self.dirty and now - self.last_save >= SAVE_EVERY_S:
            self._save(ctx)

        w, h = ctx.w, ctx.h
        if self.loot is None:
            ctx.text("needs the loot_read permission", 10, 10, 18, "danger")
            return
        fix = self.gps.fix() if self.gps is not None else None
        gps_ok = bool(fix and fix.get("valid"))
        tiers = {}
        for r in self.history.values():
            tiers[r.get("tier")] = tiers.get(r.get("tier"), 0) + 1
        status = "checked %d nets   all-time: %d confirmed  %d suspect  %d keyword%s" % (
            self.checked, tiers.get("CONFIRMED", 0), tiers.get("SUSPECT", 0),
            tiers.get("KEYWORD", 0),
            ("  %d weak" % tiers.get("WEAK", 0)) if self.include_weak else "")
        ctx.text(status, 10, 8, 16, "txt")
        gtxt = "GPS OK" if gps_ok else "NO GPS FIX - hits logged without position"
        ctx.text(gtxt, w - 10 - int(ctx.measure(gtxt, 16)), 8, 16,
                 "success" if gps_ok else "warn", bold=True)

        y = 36
        if self.alert and now < self.alert[1]:
            r = self.alert[0]
            col = TIER_COLOR.get(r.get("tier"), "warn")
            ctx.rect(6, y, w - 12, 92, col, fill=True, alpha=70)
            ctx.rect(6, y, w - 12, 92, col, fill=False)
            ctx.text("%s: %s" % (r.get("tier"), r.get("ssid") or "<hidden SSID>"),
                     18, y + 8, 34, col, bold=True)
            pos = ("%.5f, %.5f" % (r["lat"], r["lon"])) if r.get("lat") is not None else "no GPS"
            ctx.text("%s   ch %s   %s   %s   seen %dx" % (r.get("bssid", ""), r.get("channel", "?"),
                                                         r.get("reason", ""), pos,
                                                         r.get("sightings", 1)),
                     18, y + 54, 17, "txt")
            y += 104

        ctx.text("THIS SESSION", 10, y, 16, "teal", bold=True)
        y += 24
        row_h = 24
        rows_fit = max(1, (h - y - 70) // row_h)
        self.scroll = min(self.scroll, max(0, len(self.session) - rows_fit))
        if not self.session:
            ctx.text("nothing flagged yet - start a WiFi wardrive and keep driving",
                     10, y, 16, "dim")
        for key in self.session[self.scroll:self.scroll + rows_fit]:
            r = self.history.get(key)
            if not r:
                continue
            col = TIER_COLOR.get(r.get("tier"), "txt")
            ctx.text("%-9s" % r.get("tier"), 10, y, 16, col, bold=True)
            ctx.text((r.get("ssid") or "<hidden>")[:26], 120, y, 16, "hi")
            ctx.text(r.get("bssid", ""), 420, y, 16, "txt")
            ctx.text(r.get("last", "")[11:], 610, y, 16, "dim")
            ctx.text(r.get("reason", "")[:40], 700, y, 16, "dim")
            y += row_h

        # footer
        kw = ", ".join(self.keywords) if self.keywords else "none"
        ctx.text("watch words: " + kw[:110], 10, h - 46, 14, "magenta")
        if self.typing is not None:
            ctx.rect(6, h - 28, w - 12, 24, "void", fill=True, alpha=230)
            ctx.text("new watch word: %s_   [ENTER] save  [BKSP] on empty = cancel" % self.typing,
                     10, h - 26, 16, "hi")
        elif self.msg[0] and now < self.msg[1]:
            ctx.text(self.msg[0], 10, h - 24, 15, "success")
        else:
            ctx.text("[K] add watch word  [X] remove last  [W] weak vendor matches %s  "
                     "[E] export CSV  [C] clear list  [UP/DN] scroll" %
                     ("ON" if self.include_weak else "OFF"), 10, h - 24, 14, "dim")

    def on_exit(self, ctx):
        self._save(ctx)

    def on_unload(self, ctx):
        self._save(ctx)
