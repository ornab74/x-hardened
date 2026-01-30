items: List[CarouselItem] = []
        remaining = float(self.session_left_s if self.session_active else 7 * 60.0)
        tlim = min(len(self.tweets), int(max(50, min(CAROUSEL_LIST_MAX, len(self.tweets)))))
        for t in self.tweets[:tlim]:
            lab = self.labels.get(t.tid)
            if not lab:
                continue
            v = {
                "neg": float(lab.neg),
                "sar": float(lab.sar),
                "tone": float(lab.tone),
                "edu": float(lab.edu),
                "truth": float(lab.truth),
                "cool": float(lab.cool),
                "click": float(lab.click),
                "incl": float(lab.incl),
                "ext": float(lab.ext),
            }
            tol_pt = (v["tone"], v["neg"], v["sar"])
            learn_pt = (v["edu"], v["truth"], v["click"])
            if not vec_in_sphere(tol_pt, self.tol_center, self.tol_radius):
                continue
            if not vec_in_sphere(learn_pt, self.learn_center, self.learn_radius):
                continue
            ipm = float(social_safety_quantum(v))
            if ipm < 0.45:
                continue
            dwell = float(estimate_dwell_seconds(t.text, v, remaining))
            items.append(CarouselItem(tweet=t, label=lab, v=v, ipm=ipm, dwell_s=dwell))
        items.sort(
            key=lambda it: (
                it.ipm,
                float(it.v.get("truth", 0.0)),
                float(it.v.get("edu", 0.0)),
                float(it.v.get("incl", 0.0)),
                float(1.0 - it.v.get("click", 0.0)),
                float(1.0 - it.v.get("neg", 0.0)),
            ),
            reverse=True,
        )
        self.carousel = items[: max(10, min(240, len(items)))]
        self.car_idx = 0
        if self.carousel:
            self.car_next_ts = time.time() + float(
                max(CAROUSEL_MIN_DWELL, min(CAROUSEL_MAX_DWELL, self.carousel[0].dwell_s))
            )
        else:
            self.car_next_ts = time.time() + 2.0

    def _refresh_posts(self):
        fut = self.runner.submit(self.store.list_posts(limit=110))
        try:
            self.posts = fut.result(timeout=30)
        except Exception:
            self.posts = []
        self.posts_sel = max(0, min(self.posts_sel, max(0, len(self.posts) - 1)))

    def _prompt_post(self):
        if not self.vault.unlocked:
            self.log("unlock first")
            return
        if not self.carousel:
            self.log("carousel empty")
            return
        it = self.carousel[self.car_idx % len(self.carousel)]
        self._post_tid = it.tweet.tid
        self._post_title = ""
        self._post_notes = ""
        self._prompt_input("post title", "post_title", secret=False)

    def _save_post(self):
        if not getattr(self, "_post_tid", ""):
            self.log("no tweet selected")
            return
        tid = clean_text(getattr(self, "_post_tid", ""), 64)
        title = clean_text(getattr(self, "_post_title", ""), 180)
        notes = clean_text(getattr(self, "_post_notes", ""), 3000)
        tags_json = "[]"
        try:
            it = self.labels.get(tid)
            if it:
                tags_json = it.tags_json or "[]"
        except Exception:
            tags_json = "[]"
        self.status("saving post...")
        fut = self.runner.submit(self.store.add_post(tid, title, notes, tags_json))
        def done():
            try:
                fut.result(timeout=30)
                self.log("post saved")
                self.status("")
                if self.posts_view:
                    self._refresh_posts()
            except Exception as e:
                self.log(f"post save error: {e}")
                self.status("")
        threading.Thread(target=done, daemon=True).start()

    def _handle_key(self, ch: int):
        if self._settings_hotkey(ch):
            return
        if ch in (ord("u"), ord("U")):
            self._prompt_input("vault passphrase", "unlock", secret=True)
            return
        if ch in (ord("s"), ord("S")):
            self._open_settings_menu()
            return
        if ch in (ord("f"), ord("F")):
            self._fetch_x()
            return
        if ch in (ord("l"), ord("L")):
            self._label_more()
            return
        if ch in (ord("b"), ord("B")):
            self._rebuild_carousel()
            self.log("carousel rebuilt")
            return
        if ch in (ord("t"), ord("T")):
            self._prompt_input("free time minutes (1-240)", "timebox", secret=False)
            return
        if ch == ord(" "):
            self.car_paused = not self.car_paused
            self.log("paused" if self.car_paused else "resumed")
            return
        if ch in (ord("n"), ord("N")):
            self._advance_carousel(force=True)
            return
        if ch in (ord("p"), ord("P")):
            self._prompt_post()
            return
        if ch in (ord("v"), ord("V")):
            self.posts_view = not self.posts_view
            if self.posts_view:
                self._refresh_posts()
            self.log("posts view" if self.posts_view else "main view")
            return
        if ch in (ord("i"), ord("I")):
            self.log(self._salt_hint)
            return
        if ch == curses.KEY_LEFT:
            self.tol_center = (clamp01(self.tol_center[0] - 0.03), self.tol_center[1], self.tol_center[2])
            self._rebuild_carousel()
            return
        if ch == curses.KEY_RIGHT:
            self.tol_center = (clamp01(self.tol_center[0] + 0.03), self.tol_center[1], self.tol_center[2])
            self._rebuild_carousel()
            return
        if ch == curses.KEY_UP:
            self.tol_center = (self.tol_center[0], clamp01(self.tol_center[1] - 0.03), self.tol_center[2])
            self._rebuild_carousel()
            return
        if ch == curses.KEY_DOWN:
            self.tol_center = (self.tol_center[0], clamp01(self.tol_center[1] + 0.03), self.tol_center[2])
            self._rebuild_carousel()
            return
        if ch in (ord(","),):
            self.tol_center = (self.tol_center[0], self.tol_center[1], clamp01(self.tol_center[2] - 0.03))
            self._rebuild_carousel()
            return
        if ch in (ord("."),):
            self.tol_center = (self.tol_center[0], self.tol_center[1], clamp01(self.tol_center[2] + 0.03))
            self._rebuild_carousel()
            return
        if ch in (ord("+"), ord("=")):
            self.tol_radius = float(max(0.08, min(1.2, self.tol_radius + 0.04)))
            self._rebuild_carousel()
            return
        if ch in (ord("-"), ord("_")):
            self.tol_radius = float(max(0.08, min(1.2, self.tol_radius - 0.04)))
            self._rebuild_carousel()
            return
        if ch == ord("["):
            self.learn_radius = float(max(0.08, min(1.2, self.learn_radius - 0.04)))
            self._rebuild_carousel()
            return
        if ch == ord("]"):
            self.learn_radius = float(max(0.08, min(1.2, self.learn_radius + 0.04)))
            self._rebuild_carousel()
            return
        if ch in (ord("1"),):
            self._prompt_input("set tol center x,y,z (0-1)", "set_tol_center", secret=False)
            return
        if ch in (ord("2"),):
            self._prompt_input("set learn center x,y,z (0-1)", "set_learn_center", secret=False)
            return
        if self.posts_view:
            if ch in (curses.KEY_PPAGE,):
                self.posts_sel = max(0, self.posts_sel - 5)
                return
            if ch in (curses.KEY_NPAGE,):
                self.posts_sel = min(max(0, len(self.posts) - 1), self.posts_sel + 5)
                return
            if ch in (ord("j"), ord("J")):
                self.posts_sel = min(max(0, len(self.posts) - 1), self.posts_sel + 1)
                return
            if ch in (ord("k"), ord("K")):
                self.posts_sel = max(0, self.posts_sel - 1)
                return

    def _bar(self, w: int, v: float) -> str:
        w = max(1, int(w))
        v = clamp01(v)
        n = int(round(v * w))
        if n <= 0:
            return " " * w
        if n >= w:
            return "█" * w
        return ("█" * n) + (" " * (w - n))

    def _safe_add(self, stdscr, y: int, x: int, s: str, attr: int = 0):
        try:
            h, w = stdscr.getmaxyx()
            if y < 0 or y >= h:
                return
            if x < 0:
                s = s[-x:]
                x = 0
            if x >= w:
                return
            s2 = s[: max(0, w - x - 1)]
            stdscr.addstr(y, x, s2, attr)
        except Exception:
            pass

    def _draw_orb(self, stdscr, y: int, x: int, w: int, h: int, center: Tuple[float, float, float], radius: float, pt: Tuple[float, float, float], title: str):
        w = max(14, int(w))
        h = max(7, int(h))
        r = float(max(0.01, min(1.25, radius)))
        cx, cy, cz = float(center[0]), float(center[1]), float(center[2])
        px, py, pz = float(pt[0]), float(pt[1]), float(pt[2])
        self._safe_add(stdscr, y, x, title[: w - 1], curses.A_BOLD)
        grid_h = h - 2
        grid_w = w
        ox = x
        oy = y + 1
        for yy in range(grid_h):
            self._safe_add(stdscr, oy + yy, ox, (" " * (grid_w - 1))[: grid_w - 1], curses.A_DIM)
        rr = min(grid_w - 2, grid_h - 1) / 2.0
        gx = (px - cx) / max(1e-9, r)
        gy = (py - cy) / max(1e-9, r)
        gz = (pz - cz) / max(1e-9, r)
        gx = max(-1.0, min(1.0, gx))
        gy = max(-1.0, min(1.0, gy))
        gz = max(-1.0, min(1.0, gz))
        sx = int(round((grid_w - 2) / 2.0 + gx * rr))
        sy = int(round((grid_h - 1) / 2.0 + gy * rr))
        sx = max(0, min(grid_w - 2, sx))
        sy = max(0, min(grid_h - 1, sy))
        dot = "●" if abs(gz) < 0.33 else ("◆" if gz > 0 else "◇")
        ring = set()
        for a in range(0, 360, 12):
            ang = a * math.pi / 180.0
            rx = int(round((grid_w - 2) / 2.0 + math.cos(ang) * rr))
            ry = int(round((grid_h - 1) / 2.0 + math.sin(ang) * rr))
            ring.add((rx, ry))
        for (rx, ry) in ring:
            self._safe_add(stdscr, oy + ry, ox + rx, "·", curses.A_DIM)
        self._safe_add(stdscr, oy + sy, ox + sx, dot, curses.A_BOLD)
        meta = f"c=({cx:.2f},{cy:.2f},{cz:.2f}) r={r:.2f}"
        self._safe_add(stdscr, y + h - 1, x, meta[: w - 1], curses.A_DIM)

    def _draw(self, stdscr):
        stdscr.erase()
        h, w = stdscr.getmaxyx()
        title = UI_TITLE
        status = self._status or ""
        pend = f" pending={self._pending}" if self._pending else ""
        lock = "UNLOCKED" if self.vault.unlocked else "LOCKED"
        ses = ""
        if self.session_active:
            ses = f" timebox {int(self.session_left_s//60):02d}:{int(self.session_left_s%60):02d}"
        elif self.session_total_s > 0:
            ses = f" done"
        line0 = f"{title} | {lock}{pend}{ses} | {status}"
        self._safe_add(stdscr, 0, 1, line0[: w - 2], curses.A_BOLD)
        top_y = 2
        mid_h = max(10, h - 10)
        left_w = max(32, int(w * 0.38))
        right_w = max(30, w - left_w - 3)
        orb_h = 10
        if self.posts_view:
            self._draw_posts(stdscr, top_y, 1, w - 2, h - 3)
        else:
            self._draw_main_panels(stdscr, top_y, 1, left_w, right_w, mid_h, orb_h)
        self._draw_logs(stdscr, h - 7, 1, w - 2, 7)
        if self.mode == "input":
            self._draw_input(stdscr, h, w)
        stdscr.refresh()

    def _draw_main_panels(self, stdscr, y: int, x: int, left_w: int, right_w: int, mid_h: int, orb_h: int):
        box_h = max(8, mid_h)
        self._safe_add(stdscr, y, x, "ORBS / FILTERS", curses.A_UNDERLINE)
        it = self.carousel[self.car_idx % len(self.carousel)] if self.carousel else None
        if it:
            tol_pt = (float(it.v.get("tone", 0.0)), float(it.v.get("neg", 0.0)), float(it.v.get("sar", 0.0)))
            learn_pt = (float(it.v.get("edu", 0.0)), float(it.v.get("truth", 0.0)), float(it.v.get("click", 0.0)))
        else:
            tol_pt = self.tol_center
            learn_pt = self.learn_center
        orb_w = max(18, (left_w - 2))
        self._draw_orb(stdscr, y + 1, x, orb_w, orb_h, self.tol_center, self.tol_radius, tol_pt, "tolerance orb (tone,neg,sar)")
        self._draw_orb(stdscr, y + 1 + orb_h, x, orb_w, orb_h, self.learn_center, self.learn_radius, learn_pt, "learning orb (edu,truth,click)")
        self._safe_add(stdscr, y + 1 + 2 * orb_h, x, "QUEUE", curses.A_UNDERLINE)
        qy = y + 2 + 2 * orb_h
        qh = max(6, box_h - (2 * orb_h + 3))
        self._draw_queue(stdscr, qy, x, left_w - 2, qh)
        self._safe_add(stdscr, y, x + left_w + 1, "CAROUSEL", curses.A_UNDERLINE)
        self._draw_carousel(stdscr, y + 1, x + left_w + 1, right_w, box_h)

    def _draw_queue(self, stdscr, y: int, x: int, w: int, h: int):
        w = max(18, int(w))
        h = max(4, int(h))
        if not self.carousel:
            self._safe_add(stdscr, y, x, "(empty)", curses.A_DIM)
            return
        start = self.car_idx % len(self.carousel)
        show = min(h, max(1, len(self.carousel)))
        for i in range(show):
            it = self.carousel[(start + i) % len(self.carousel)]
            lab = it.label
            ipm = it.ipm
            r, g, b = gradient_ipm_color(ipm)
            ci = rgb_to_xterm256(r, g, b)
            pid = self.color_cache.get(ci)
            attr = curses.color_pair(pid) | (curses.A_BOLD if i == 0 else curses.A_NORMAL) if pid else (curses.A_BOLD if i == 0 else curses.A_NORMAL)
            s = f"{i:02d} ipm={ipm:0.2f} neg={lab.neg:0.2f} edu={lab.edu:0.2f} truth={lab.truth:0.2f} @{it.tweet.author}"
            self._safe_add(stdscr, y + i, x, s[: w - 1], attr)

    def _draw_carousel(self, stdscr, y: int, x: int, w: int, h: int):
        w = max(24, int(w))
        h = max(10, int(h))
        if not self.carousel:
            self._safe_add(stdscr, y, x, "no items (label more / widen radius)", curses.A_DIM)
            return
        it = self.carousel[self.car_idx % len(self.carousel)]
        t = it.tweet
        lab = it.label
        v = it.v
        head = f"#{self.car_idx+1}/{len(self.carousel)}  id={t.tid}  @{t.author}  {t.created_at}"
        self._safe_add(stdscr, y, x, head[: w - 1], curses.A_BOLD)
        ipm = it.ipm
        ipm_rgb = gradient_ipm_color(ipm)
        ipm_ci = rgb_to_xterm256(*ipm_rgb)
        ipm_pid = self.color_cache.get(ipm_ci)
        ipm_attr = curses.color_pair(ipm_pid) | curses.A_BOLD if ipm_pid else curses.A_BOLD
        self._safe_add(stdscr, y + 1, x, f"SSQ(ipm)={ipm:0.2f}  dwell={it.dwell_s:0.1f}s", ipm_attr)
        neg_rgb = gradient_neg_color(v.get("neg", 0.0))
        neg_ci = rgb_to_xterm256(*neg_rgb)
        neg_pid = self.color_cache.get(neg_ci)
        neg_attr = curses.color_pair(neg_pid) | curses.A_BOLD if neg_pid else curses.A_BOLD
        bars_y = y + 3
        bw = max(8, min(24, w - 22))
        self._safe_add(stdscr, bars_y + 0, x, f"neg  {lab.neg:0.2f} {self._bar(bw, lab.neg)}", neg_attr)
        self._safe_add(stdscr, bars_y + 1, x, f"sar  {lab.sar:0.2f} {self._bar(bw, lab.sar)}", curses.A_DIM)
        self._safe_add(stdscr, bars_y + 2, x, f"tone {lab.tone:0.2f} {self._bar(bw, lab.tone)}", curses.A_DIM)
        self._safe_add(stdscr, bars_y + 3, x, f"edu  {lab.edu:0.2f} {self._bar(bw, lab.edu)}", curses.A_DIM)
        self._safe_add(stdscr, bars_y + 4, x, f"truth{lab.truth:0.2f} {self._bar(bw, lab.truth)}", curses.A_DIM)
        self._safe_add(stdscr, bars_y + 5, x, f"cool {lab.cool:0.2f} {self._bar(bw, lab.cool)}", curses.A_DIM)
        self._safe_add(stdscr, bars_y + 6, x, f"click{lab.click:0.2f} {self._bar(bw, lab.click)}", curses.A_DIM)
        self._safe_add(stdscr, bars_y + 7, x, f"incl {lab.incl:0.2f} {self._bar(bw, lab.incl)}", curses.A_DIM)
        self._safe_add(stdscr, bars_y + 8, x, f"ext  {lab.ext:0.2f} {self._bar(bw, lab.ext)}", curses.A_DIM)
        sy = bars_y + 10
        summ = clean_text(lab.summary, 460)
        self._safe_add(stdscr, sy, x, ("summary: " + summ)[: w - 1], curses.A_NORMAL)
        try:
            pack = json.loads(lab.raw_json or "{}")
            title = clean_text((pack.get("title") or ""), 200)
        except Exception:
            title = ""
        if title:
            self._safe_add(stdscr, sy + 1, x, ("title: " + title)[: w - 1], curses.A_BOLD)
        try:
            tags = json.loads(lab.tags_json or "[]")
            if not isinstance(tags, list):
                tags = []
        except Exception:
            tags = []
        tags_s = " ".join([f"#{clean_text(z, 24)}" for z in tags[:10]])
        if tags_s:
            self._safe_add(stdscr, sy + 2, x, ("tags: " + tags_s)[: w - 1], curses.A_DIM)
        txt_lines = []
        tt = clean_text(t.text, 2200)
        words = tt.split(" ")
        line = ""
        for wds in words:
            if len(line) + len(wds) + 1 > max(18, w - 2):
                txt_lines.append(line)
                line = wds
            else:
                line = (line + " " + wds).strip()
            if len(txt_lines) >= max(1, h - (sy - y) - 5):
                break
        if line and len(txt_lines) < max(1, h - (sy - y) - 5):
            txt_lines.append(line)
        ty = sy + 4
        self._safe_add(stdscr, ty - 1, x, "tweet:", curses.A_UNDERLINE)
        for i, ln in enumerate(txt_lines):
            self._safe_add(stdscr, ty + i, x, ln[: w - 1], curses.A_NORMAL)

    def _draw_posts(self, stdscr, y: int, x: int, w: int, h: int):
        self._safe_add(stdscr, y, x, "POSTS (j/k move, PgUp/PgDn jump, V back)", curses.A_BOLD)
        if not self.posts:
            self._safe_add(stdscr, y + 2, x, "(no posts yet; press P while viewing a tweet)", curses.A_DIM)
            return
        self.posts_sel = max(0, min(self.posts_sel, len(self.posts) - 1))
        top = max(0, self.posts_sel - max(0, (h - 6) // 2))
        show = self.posts[top : top + max(1, h - 4)]
        for i, p in enumerate(show):
            idx = top + i
            attr = curses.A_REVERSE if idx == self.posts_sel else curses.A_NORMAL
            head = f"{p.get('id')} tid={p.get('tid')} {p.get('created_at')}"
            self._safe_add(stdscr, y + 2 + i, x, head[: w - 1], attr)
        p = self.posts[self.posts_sel]
        ly = y + max(3, min(h - 3, (h // 2)))
        title = clean_text(p.get("title", ""), 220)
        notes = clean_text(p.get("notes", ""), 1200)
        self._safe_add(stdscr, ly, x, ("title: " + title)[: w - 1], curses.A_BOLD)
        self._safe_add(stdscr, ly + 1, x, ("notes: " + notes)[: w - 1], curses.A_DIM)

    def _draw_logs(self, stdscr, y: int, x: int, w: int, h: int):
        self._safe_add(stdscr, y, x, "LOGS", curses.A_UNDERLINE)
        show = self.logs[-max(0, h - 1) :]
        for i, ln in enumerate(show):
            self._safe_add(stdscr, y + 1 + i, x, ln[: w - 1], curses.A_DIM)

    def _draw_input(self, stdscr, h: int, w: int):
        prompt = self.input_prompt or "input"
        buf = self.input_buf or ""
        disp = ("*" * len(buf)) if self.input_secret else buf
        pad = " " * max(0, w - 3)
        self._safe_add(stdscr, h - 2, 1, pad[: w - 2], curses.A_REVERSE)
        self._safe_add(stdscr, h - 2, 2, f"{prompt}: {disp}"[: w - 4], curses.A_REVERSE)
        self._safe_add(stdscr, h - 1, 1, "ENTER submit | ESC cancel"[: w - 2], curses.A_DIM)

def main():
    app = App()
    app.run()

if __name__ == "__main__":
    main()
```0
