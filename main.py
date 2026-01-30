from __future__ import annotations

import os
import re
import json
import time
import math
import base64
import queue
import html
import errno
import signal
import sqlite3
import secrets
import asyncio
import threading
import datetime as _dt
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import curses
import httpx
import aiosqlite

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except Exception as _e:
    AESGCM = None

try:
    from argon2.low_level import hash_secret_raw, Type as _Argon2Type
except Exception:
    hash_secret_raw = None
    _Argon2Type = None

try:
    import bleach as _bleach
except Exception:
    _bleach = None

try:
    import numpy as np
except Exception:
    np = None


APP_DB = os.environ.get("RGN_SOCIAL_DB", os.path.expanduser("~/.rgn_social_tui.sqlite3"))
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
OPENAI_MODEL_DEFAULT = os.environ.get("OPENAI_MODEL", "gpt-3.5-turbo")
X_BASE_URL = os.environ.get("X_BASE_URL", "https://api.x.com").rstrip("/")
RGN_REFRESH = float(os.environ.get("RGN_TUI_REFRESH", "0.35"))
RGN_SALT_B64_ENV = os.environ.get("RGN_SALT_B64", "")
RGN_SALT_FILE = os.environ.get("RGN_SALT_FILE", os.path.expanduser("~/.rgn_social_salt.b64"))

MAX_TWEETS_STORE = int(os.environ.get("RGN_MAX_TWEETS_STORE", "2500"))
CAROUSEL_LIST_MAX = int(os.environ.get("RGN_CAROUSEL_MAX", "800"))
CAROUSEL_MIN_DWELL = float(os.environ.get("RGN_CAROUSEL_MIN_DWELL", "3.8"))
CAROUSEL_MAX_DWELL = float(os.environ.get("RGN_CAROUSEL_MAX_DWELL", "22.0"))
LABEL_BATCH = int(os.environ.get("RGN_LABEL_BATCH", "8"))
HTTP_TIMEOUT = float(os.environ.get("RGN_HTTP_TIMEOUT", "30.0"))
HTTP_RETRIES = int(os.environ.get("RGN_HTTP_RETRIES", "3"))
HTTP_BACKOFF = float(os.environ.get("RGN_HTTP_BACKOFF", "0.55"))

# --- Preference prediction / topic search knobs ---
TOPIC_REFRESH_S = float(os.environ.get("RGN_TOPIC_REFRESH_S", "420"))  # 7 min default
TOPIC_MAX = int(os.environ.get("RGN_TOPIC_MAX", "8"))
TOPIC_SEARCH_PER_TOPIC = int(os.environ.get("RGN_TOPIC_SEARCH_PER_TOPIC", "14"))
TOPIC_MAX_RATIO_IN_CAROUSEL = float(os.environ.get("RGN_TOPIC_MAX_RATIO", "0.45"))
TOPIC_QUERY_LANG = os.environ.get("RGN_TOPIC_LANG", "en").strip() or "en"
TOPIC_EXCLUDE_RETWEETS = os.environ.get("RGN_TOPIC_EXCLUDE_RETWEETS", "1").strip() != "0"

UI_TITLE = "RGN SOCIAL SAFETY QUANTUM | X Carousel + CEB + Orb Filters (+ Pref Topics)"


def clamp01(x: float) -> float:
    try:
        return float(max(0.0, min(1.0, float(x))))
    except Exception:
        return 0.0


def now_iso() -> str:
    return _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc).isoformat()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def clean_text(s: str, max_len: int = 8000) -> str:
    if s is None:
        return ""
    try:
        s = str(s)
    except Exception:
        s = ""
    s = s.replace("\x00", "")
    s = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > max_len:
        s = s[:max_len]
    if _bleach is not None:
        try:
            return _bleach.clean(s, tags=[], attributes={}, styles=[], strip=True)
        except Exception:
            return html.escape(s, quote=False)
    return html.escape(s, quote=False)


def parse_int(s: str, default: int = 0) -> int:
    try:
        return int(str(s).strip())
    except Exception:
        return default


def parse_float(s: str, default: float = 0.0) -> float:
    try:
        return float(str(s).strip())
    except Exception:
        return default


def ensure_salt_b64() -> Tuple[str, bool]:
    if RGN_SALT_B64_ENV.strip():
        return RGN_SALT_B64_ENV.strip(), False
    try:
        if os.path.exists(RGN_SALT_FILE):
            with open(RGN_SALT_FILE, "rb") as f:
                v = f.read().decode("utf-8", errors="ignore").strip()
                if v:
                    return v, False
    except Exception:
        pass
    salt = secrets.token_bytes(16)
    salt_b64 = b64e(salt)
    try:
        with open(RGN_SALT_FILE, "wb") as f:
            f.write(salt_b64.encode("utf-8"))
    except Exception:
        pass
    return salt_b64, True


def hashlib_scrypt(p: bytes, salt: bytes, out_len: int) -> bytes:
    import hashlib
    return hashlib.scrypt(p, salt=salt, n=2**15, r=8, p=1, dklen=out_len)


def kdf_argon2(passphrase: str, salt: bytes, out_len: int = 32) -> bytes:
    p = passphrase.encode("utf-8", errors="ignore")
    if hash_secret_raw is not None and _Argon2Type is not None:
        try:
            return hash_secret_raw(
                secret=p,
                salt=salt,
                time_cost=3,
                memory_cost=128 * 1024,
                parallelism=2,
                hash_len=out_len,
                type=_Argon2Type.ID,
            )
        except Exception:
            pass
    try:
        return hashlib_scrypt(p, salt, out_len)
    except Exception:
        return (p + salt + b"\x00" * out_len)[:out_len]


def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
    if AESGCM is None:
        raise RuntimeError("cryptography AESGCM missing")
    n = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(n, plaintext, aad)
    return {"n": b64e(n), "ct": b64e(ct), "aad": b64e(aad)}


def aesgcm_decrypt(key: bytes, blob: Dict[str, str]) -> bytes:
    if AESGCM is None:
        raise RuntimeError("cryptography AESGCM missing")
    n = b64d(blob["n"])
    ct = b64d(blob["ct"])
    aad = b64d(blob.get("aad", "")) if blob.get("aad") else b""
    return AESGCM(key).decrypt(n, ct, aad)


def rgb_to_xterm256(r: int, g: int, b: int) -> int:
    r = int(max(0, min(255, r)))
    g = int(max(0, min(255, g)))
    b = int(max(0, min(255, b)))
    if r == g == b:
        if r < 8:
            return 16
        if r > 248:
            return 231
        return 232 + int((r - 8) / 10)

    def to_6(v: int) -> int:
        return int(round((v / 255) * 5))

    ri, gi, bi = to_6(r), to_6(g), to_6(b)
    return 16 + 36 * ri + 6 * gi + bi


class ColorPairCache:
    def __init__(self, max_pairs: int = 96):
        self.max_pairs = int(max_pairs)
        self.lru: Dict[int, int] = {}
        self.order: List[int] = []
        self.next_id = 1

    def get(self, color_index: int) -> int:
        if color_index in self.lru:
            try:
                self.order.remove(color_index)
            except Exception:
                pass
            self.order.append(color_index)
            return self.lru[color_index]
        if len(self.lru) >= self.max_pairs:
            ev = self.order.pop(0) if self.order else None
            if ev is not None and ev in self.lru:
                _ = self.lru.pop(ev)
        pid = self.next_id
        self.next_id += 1
        try:
            curses.init_pair(pid, int(color_index), -1)
        except Exception:
            pid = 0
        self.lru[color_index] = pid
        self.order.append(color_index)
        return pid


DEFAULT_DOMAINS = [
    "attention_integrity",
    "learning_velocity",
    "inclusion_empathy",
    "truth_grounding",
    "extremism_resilience",
]

DOMAIN_COUPLING = {
    "attention_integrity": ["learning_velocity", "truth_grounding", "extremism_resilience"],
    "learning_velocity": ["attention_integrity", "truth_grounding", "inclusion_empathy"],
    "inclusion_empathy": ["learning_velocity", "extremism_resilience"],
    "truth_grounding": ["learning_velocity", "attention_integrity", "extremism_resilience"],
    "extremism_resilience": ["truth_grounding", "inclusion_empathy", "attention_integrity"],
}


def vec_in_sphere(v: Tuple[float, float, float], c: Tuple[float, float, float], r: float) -> bool:
    dx = float(v[0] - c[0])
    dy = float(v[1] - c[1])
    dz = float(v[2] - c[2])
    return (dx * dx + dy * dy + dz * dz) <= float(r) * float(r)


def social_safety_quantum(v: Dict[str, float]) -> float:
    edu = clamp01(v.get("edu", 0.4))
    truth = clamp01(v.get("truth", 0.4))
    cool = clamp01(v.get("cool", 0.35))
    click = clamp01(v.get("click", 0.35))
    neg = clamp01(v.get("neg", 0.35))
    sar = clamp01(v.get("sar", 0.35))
    tone = clamp01(v.get("tone", 0.45))
    incl = clamp01(v.get("incl", 0.5))
    ext = clamp01(v.get("ext", 0.15))

    protect = (0.45 + 0.55 * edu) * (0.45 + 0.55 * truth) * (0.72 + 0.28 * (1.0 - click))
    inclusion = (0.60 + 0.40 * incl) * (0.70 + 0.30 * tone) * (0.78 + 0.22 * (1.0 - neg))
    risk = (0.35 + 0.65 * click) * (0.45 + 0.55 * neg) * (0.45 + 0.55 * sar) * (0.55 + 0.45 * ext)
    novelty = (0.58 + 0.42 * cool)
    q = (protect * inclusion * novelty) / max(0.35, risk)
    return float(max(0.0, min(3.5, q)))


def estimate_dwell_seconds(text: str, v: Dict[str, float], remaining_s: float) -> float:
    t = clean_text(text, 2400)
    wc = max(1, len(t.split()))
    read_s = wc / 3.6
    q = social_safety_quantum(v)
    base = read_s * (0.78 + 0.40 * min(1.0, q / 2.0))
    base = float(max(CAROUSEL_MIN_DWELL, min(CAROUSEL_MAX_DWELL, base)))
    if remaining_s < 20:
        base = min(base, max(CAROUSEL_MIN_DWELL, remaining_s / 4.0))
    return float(max(CAROUSEL_MIN_DWELL, min(CAROUSEL_MAX_DWELL, base)))


def gradient_neg_color(neg: float) -> Tuple[int, int, int]:
    neg = clamp01(neg)
    r = int(70 + 185 * (neg))
    g = int(210 - 160 * (neg))
    b = int(90 - 70 * (neg))
    return (max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b)))


def gradient_ipm_color(ipm: float) -> Tuple[int, int, int]:
    ipm = float(max(0.0, min(3.5, ipm)))
    t = ipm / 3.5
    r = int(85 + 140 * (1.0 - t))
    g = int(90 + 165 * (t))
    b = int(170 + 70 * (t))
    return (max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b)))


def safe_json_extract(s: str) -> Optional[Dict[str, Any]]:
    """
    Accepts either:
      - [REPLYFORMAT] ... [/REPLYFORMAT]
      - REPLYFORMAT ... /REPLYFORMAT   (your earlier private-use markers)
      - or raw JSON object
    """
    if not s:
        return None
    s2 = s.strip()

    # Private markers variant
    m = re.search(r"REPLYFORMAT(.+?)/REPLYFORMAT", s2, re.DOTALL | re.IGNORECASE)
    if m:
        blob = m.group(1).strip()
    else:
        # Bracket tags variant
        m = re.search(r"\[REPLYFORMAT\](.+?)\[/REPLYFORMAT\]", s2, re.DOTALL | re.IGNORECASE)
        if m:
            blob = m.group(1).strip()
        else:
            blob = s2

    m2 = re.search(r"\{.*\}", blob, re.DOTALL)
    if not m2:
        return None
    jtxt = m2.group(0)
    try:
        return json.loads(jtxt)
    except Exception:
        try:
            jtxt2 = re.sub(r",\s*}", "}", jtxt)
            jtxt2 = re.sub(r",\s*]", "]", jtxt2)
            return json.loads(jtxt2)
        except Exception:
            return None


def _quote_topic(t: str) -> str:
    t = clean_text(t, 80)
    if not t:
        return ""
    # If it already looks like an operator, keep it
    if ":" in t and " " not in t and len(t) < 40:
        return t
    # Quote if spaces / punctuation heavy
    if re.search(r"\s", t) or re.search(r"[^a-zA-Z0-9_#@:\-]", t):
        t = t.replace('"', "")
        return f'"{t}"'
    return t


def build_topic_query(topics: List[str]) -> str:
    toks = [x for x in (_quote_topic(t) for t in topics) if x]
    toks = toks[: max(1, TOPIC_MAX)]
    if not toks:
        return ""
    if len(toks) == 1:
        q = toks[0]
    else:
        q = "(" + " OR ".join(toks) + ")"
    if TOPIC_QUERY_LANG:
        q += f" lang:{TOPIC_QUERY_LANG}"
    if TOPIC_EXCLUDE_RETWEETS:
        q += " -is:retweet"
    # keep it compact-ish
    return q[:480]


@dataclass
class TweetRow:
    tid: str
    author: str
    created_at: str
    text: str
    src: str = ""  # "user" or "topic" (or anything)


@dataclass
class TweetLabel:
    tid: str
    neg: float
    sar: float
    tone: float
    edu: float
    truth: float
    cool: float
    click: float
    incl: float
    ext: float
    summary: str
    tags_json: str
    raw_json: str
    model: str
    created_at: str


@dataclass
class CarouselItem:
    tweet: TweetRow
    label: TweetLabel
    v: Dict[str, float]
    ipm: float
    dwell_s: float


class AsyncRunner:
    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def submit(self, coro):
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut

    def stop(self):
        try:
            self.loop.call_soon_threadsafe(self.loop.stop)
        except Exception:
            pass


class Store:
    def __init__(self, db_path: str):
        self.db_path = db_path

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA synchronous=NORMAL")
            await db.execute("PRAGMA foreign_keys=ON")

            await db.execute(
                "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL, updated_at TEXT NOT NULL)"
            )

            # tweets table (add src column if needed)
            await db.execute(
                "CREATE TABLE IF NOT EXISTS tweets ("
                "tid TEXT PRIMARY KEY, author TEXT, created_at TEXT, text TEXT, src TEXT, inserted_at TEXT)"
            )
            # upgrade older schema that lacked src
            try:
                async with db.execute("PRAGMA table_info(tweets)") as cur:
                    cols = []
                    async for row in cur:
                        cols.append(str(row[1] or ""))
                if "src" not in cols:
                    await db.execute("ALTER TABLE tweets ADD COLUMN src TEXT DEFAULT ''")
            except Exception:
                pass

            await db.execute(
                "CREATE TABLE IF NOT EXISTS labels ("
                "tid TEXT PRIMARY KEY, neg REAL, sar REAL, tone REAL, edu REAL, truth REAL, cool REAL, click REAL, "
                "incl REAL, ext REAL, summary TEXT, tags_json TEXT, raw_json TEXT, model TEXT, created_at TEXT)"
            )
            await db.execute(
                "CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "tid TEXT, title TEXT, notes TEXT, tags_json TEXT, created_at TEXT)"
            )
            await db.execute("CREATE INDEX IF NOT EXISTS idx_tweets_time ON tweets(inserted_at)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_posts_time ON posts(created_at)")
            await db.commit()

    async def kv_set(self, k: str, v: str):
        k = clean_text(k, 200)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO kv(k,v,updated_at) VALUES(?,?,?) "
                "ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated_at=excluded.updated_at",
                (k, v, now_iso()),
            )
            await db.commit()

    async def kv_get(self, k: str) -> Optional[str]:
        k = clean_text(k, 200)
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT v FROM kv WHERE k=?", (k,)) as cur:
                row = await cur.fetchone()
                return row[0] if row else None

    async def upsert_tweets(self, tweets: List[TweetRow]):
        if not tweets:
            return
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("BEGIN")
            for t in tweets:
                await db.execute(
                    "INSERT INTO tweets(tid,author,created_at,text,src,inserted_at) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(tid) DO UPDATE SET author=excluded.author, created_at=excluded.created_at, "
                    "text=excluded.text, src=excluded.src",
                    (t.tid, t.author, t.created_at, t.text, t.src or "", now_iso()),
                )
            await db.commit()
            await db.execute(
                "DELETE FROM tweets WHERE tid NOT IN (SELECT tid FROM tweets ORDER BY inserted_at DESC LIMIT ?)",
                (MAX_TWEETS_STORE,),
            )
            await db.commit()

    async def list_tweets(self, limit: int = 500) -> List[TweetRow]:
        out: List[TweetRow] = []
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT tid,author,created_at,text,src FROM tweets ORDER BY inserted_at DESC LIMIT ?",
                (int(limit),),
            ) as cur:
                async for row in cur:
                    out.append(
                        TweetRow(
                            tid=row[0],
                            author=row[1] or "",
                            created_at=row[2] or "",
                            text=row[3] or "",
                            src=row[4] or "",
                        )
                    )
        return out

    async def get_tweet(self, tid: str) -> Optional[TweetRow]:
        tid = clean_text(tid, 64)
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT tid,author,created_at,text,src FROM tweets WHERE tid=?", (tid,)) as cur:
                row = await cur.fetchone()
                if not row:
                    return None
                return TweetRow(tid=row[0], author=row[1] or "", created_at=row[2] or "", text=row[3] or "", src=row[4] or "")

    async def upsert_label(self, lab: TweetLabel):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO labels(tid,neg,sar,tone,edu,truth,cool,click,incl,ext,summary,tags_json,raw_json,model,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(tid) DO UPDATE SET "
                "neg=excluded.neg, sar=excluded.sar, tone=excluded.tone, edu=excluded.edu, truth=excluded.truth, "
                "cool=excluded.cool, click=excluded.click, incl=excluded.incl, ext=excluded.ext, "
                "summary=excluded.summary, tags_json=excluded.tags_json, raw_json=excluded.raw_json, model=excluded.model, created_at=excluded.created_at",
                (
                    lab.tid,
                    lab.neg,
                    lab.sar,
                    lab.tone,
                    lab.edu,
                    lab.truth,
                    lab.cool,
                    lab.click,
                    lab.incl,
                    lab.ext,
                    lab.summary,
                    lab.tags_json,
                    lab.raw_json,
                    lab.model,
                    lab.created_at,
                ),
            )
            await db.commit()

    async def get_label(self, tid: str) -> Optional[TweetLabel]:
        tid = clean_text(tid, 64)
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT tid,neg,sar,tone,edu,truth,cool,click,incl,ext,summary,tags_json,raw_json,model,created_at FROM labels WHERE tid=?",
                (tid,),
            ) as cur:
                row = await cur.fetchone()
                if not row:
                    return None
                return TweetLabel(
                    tid=row[0],
                    neg=float(row[1] or 0.0),
                    sar=float(row[2] or 0.0),
                    tone=float(row[3] or 0.0),
                    edu=float(row[4] or 0.0),
                    truth=float(row[5] or 0.0),
                    cool=float(row[6] or 0.0),
                    click=float(row[7] or 0.0),
                    incl=float(row[8] or 0.0),
                    ext=float(row[9] or 0.0),
                    summary=row[10] or "",
                    tags_json=row[11] or "[]",
                    raw_json=row[12] or "{}",
                    model=row[13] or "",
                    created_at=row[14] or "",
                )

    async def unlabeled_tweet_ids(self, limit: int = 50) -> List[str]:
        out: List[str] = []
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT t.tid FROM tweets t LEFT JOIN labels l ON t.tid=l.tid "
                "WHERE l.tid IS NULL ORDER BY t.inserted_at DESC LIMIT ?",
                (int(limit),),
            ) as cur:
                async for row in cur:
                    out.append(row[0])
        return out

    async def add_post(self, tid: str, title: str, notes: str, tags_json: str):
        tid = clean_text(tid, 64)
        title = clean_text(title, 180)
        notes = clean_text(notes, 4000)
        if not tags_json:
            tags_json = "[]"
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO posts(tid,title,notes,tags_json,created_at) VALUES(?,?,?,?,?)",
                (tid, title, notes, tags_json, now_iso()),
            )
            await db.commit()

    async def list_posts(self, limit: int = 80) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT id,tid,title,notes,tags_json,created_at FROM posts ORDER BY created_at DESC LIMIT ?",
                (int(limit),),
            ) as cur:
                async for row in cur:
                    out.append(
                        {
                            "id": int(row[0]),
                            "tid": row[1] or "",
                            "title": row[2] or "",
                            "notes": row[3] or "",
                            "tags_json": row[4] or "[]",
                            "created_at": row[5] or "",
                        }
                    )
        return out


class Vault:
    def __init__(self, store: Store):
        self.store = store
        self.salt_b64, self.salt_new = ensure_salt_b64()
        self.key: Optional[bytes] = None
        self.unlocked = False
        self.last_hint = ""
        self._cache: Dict[str, Any] = {}

    def lock(self):
        self.key = None
        self.unlocked = False
        self._cache = {}

    async def unlock(self, passphrase: str) -> bool:
        passphrase = clean_text(passphrase, 256)
        salt = b64d(self.salt_b64)
        key = kdf_argon2(passphrase, salt, 32)
        blob = await self.store.kv_get("vault_blob")
        if not blob:
            self.key = key
            self.unlocked = True
            self._cache = {}
            await self._save({})
            return True
        try:
            data = json.loads(blob)
            pt = aesgcm_decrypt(key, data)
            obj = json.loads(pt.decode("utf-8", errors="ignore") or "{}")
            if not isinstance(obj, dict):
                obj = {}
            self.key = key
            self.unlocked = True
            self._cache = obj
            return True
        except Exception:
            self.last_hint = "bad passphrase or corrupt vault"
            self.key = None
            self.unlocked = False
            self._cache = {}
            return False

    async def _save(self, obj: Dict[str, Any]):
        if not self.key:
            return
        pt = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        blob = aesgcm_encrypt(self.key, pt, aad=b"RGN_SOCIAL_VAULT_V1")
        await self.store.kv_set("vault_blob", json.dumps(blob))

    async def set(self, k: str, v: Any):
        if not self.unlocked:
            return
        k = clean_text(k, 64)
        self._cache[k] = v
        await self._save(self._cache)

    def get(self, k: str, default: Any = None) -> Any:
        if not self.unlocked:
            return default
        return self._cache.get(k, default)

    def export_salt_hint(self) -> str:
        return f'export RGN_SALT_B64="{self.salt_b64}"'


class XClient:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(HTTP_TIMEOUT))

    async def close(self):
        try:
            await self.client.aclose()
        except Exception:
            pass

    async def fetch_user_tweets(
        self,
        bearer: str,
        user_id: str,
        max_results: int = 80,
        pagination_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        bearer = clean_text(bearer, 4000)
        user_id = clean_text(user_id, 64)
        url = f"{X_BASE_URL}/2/users/{user_id}/tweets"
        params = {
            "max_results": int(max(5, min(100, max_results))),
            "tweet.fields": "id,text,created_at,author_id",
            "expansions": "author_id",
            "user.fields": "id,username,name",
        }
        if pagination_token:
            params["pagination_token"] = clean_text(pagination_token, 256)
        headers = {"Authorization": f"Bearer {bearer}"}
        last_err = None
        for attempt in range(max(1, HTTP_RETRIES)):
            try:
                r = await self.client.get(url, headers=headers, params=params)
                if r.status_code >= 400:
                    raise RuntimeError(f"HTTP {r.status_code}: {r.text[:4000]}")
                return r.json()
            except Exception as e:
                last_err = e
                await asyncio.sleep((2 ** attempt) * HTTP_BACKOFF)
        raise RuntimeError(str(last_err) if last_err else "X fetch failed")

    async def search_recent(
        self,
        bearer: str,
        query: str,
        max_results: int = 50,
        next_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        GET /2/tweets/search/recent  (Recent Search)
        Pagination uses next_token.  2
        """
        bearer = clean_text(bearer, 4000)
        q = clean_text(query, 512)
        if not q:
            return {"data": [], "meta": {}}
        url = f"{X_BASE_URL}/2/tweets/search/recent"
        params: Dict[str, Any] = {
            "query": q,
            "max_results": int(max(10, min(100, max_results))),
            "tweet.fields": "id,text,created_at,author_id",
            "expansions": "author_id",
            "user.fields": "id,username,name",
        }
        if next_token:
            params["next_token"] = clean_text(next_token, 256)
        headers = {"Authorization": f"Bearer {bearer}"}

        last_err = None
        for attempt in range(max(1, HTTP_RETRIES)):
            try:
                r = await self.client.get(url, headers=headers, params=params)
                if r.status_code >= 400:
                    raise RuntimeError(f"HTTP {r.status_code}: {r.text[:4000]}")
                return r.json()
            except Exception as e:
                last_err = e
                await asyncio.sleep((2 ** attempt) * HTTP_BACKOFF)
        raise RuntimeError(str(last_err) if last_err else "X search failed")

    @staticmethod
    def parse_tweets(payload: Dict[str, Any], src: str = "") -> List[TweetRow]:
        data = payload.get("data") or []
        includes = payload.get("includes") or {}
        users = includes.get("users") or []
        id_to_user: Dict[str, str] = {}
        for u in users:
            try:
                uid = str(u.get("id", ""))
                un = u.get("username") or u.get("name") or uid
                id_to_user[uid] = str(un)
            except Exception:
                pass
        out: List[TweetRow] = []
        for t in data:
            try:
                tid = str(t.get("id", ""))
                au = str(t.get("author_id", "")) if t.get("author_id") is not None else ""
                author = id_to_user.get(au, au)
                created = str(t.get("created_at", "")) if t.get("created_at") is not None else ""
                txt = str(t.get("text", "")) if t.get("text") is not None else ""
                out.append(
                    TweetRow(
                        tid=clean_text(tid, 64),
                        author=clean_text(author, 64),
                        created_at=clean_text(created, 64),
                        text=clean_text(txt, 8000),
                        src=clean_text(src, 24),
                    )
                )
            except Exception:
                pass
        return out


class OpenAIClient:
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(HTTP_TIMEOUT))

    async def close(self):
        try:
            await self.client.aclose()
        except Exception:
            pass

    async def label_tweet(self, api_key: str, model: str, ceb: Dict[str, Any], tweet: TweetRow) -> Dict[str, Any]:
        api_key = clean_text(api_key, 4000)
        model = clean_text(model, 128) or OPENAI_MODEL_DEFAULT
        sys_cebs = ceb.get("cebs", "")
        orb = ceb.get("orb", {})
        url = f"{OPENAI_BASE_URL}/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        prompt = self._prompt(sys_cebs, orb, tweet)
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": sys_cebs},
                {"role": "user", "content": prompt},
            ],
            "temperature": float(0.12),
            "max_tokens": int(340),
        }
        last_err = None
        for attempt in range(max(1, HTTP_RETRIES)):
            try:
                r = await self.client.post(url, headers=headers, json=payload)
                if r.status_code >= 400:
                    raise RuntimeError(f"HTTP {r.status_code}: {r.text[:2000]}")
                j = r.json()
                content = j["choices"][0]["message"]["content"]
                obj = safe_json_extract(content)
                if obj is None:
                    obj = {"raw": content}
                obj["_raw_text"] = content
                return obj
            except Exception as e:
                last_err = e
                await asyncio.sleep((2 ** attempt) * HTTP_BACKOFF)
        raise RuntimeError(str(last_err) if last_err else "OpenAI label failed")

    async def predict_topics(self, api_key: str, model: str, context: Dict[str, Any]) -> List[str]:
        """
        Autonomous preference prediction:
        - uses your recent labeled tags/summaries/posts to predict topics the user would like
        - returns a small list of topic strings suitable for X queries
        """
        api_key = clean_text(api_key, 4000)
        model = clean_text(model, 128) or OPENAI_MODEL_DEFAULT
        url = f"{OPENAI_BASE_URL}/chat/completions"
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        ctx = json.dumps(context, ensure_ascii=False)[:12000]
        user_prompt = (
            "[ACTION]\n"
            "You are a preference predictor for a content carousel.\n"
            "Infer topics this user will likely enjoy *next* based on recent items.\n"
            "Return ONLY JSON in [REPLYFORMAT] tags.\n"
            "Constraints:\n"
            "- 4 to 10 topics\n"
            "- Each topic: 1-5 words, or an operator-like token (e.g., #AI, from:NASA)\n"
            "- Avoid sensitive personal inference.\n"
            "- Favor: learning, practical tech, science, calm longform, constructive discourse.\n"
            "[/ACTION]\n"
            f"CONTEXT_JSON={ctx}\n"
            "[REPLYFORMAT]\n"
            '{ "topics": ["topic one", "topic two"], "reason": "short" }\n'
            "[/REPLYFORMAT]\n"
        )
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You produce strict JSON only, inside the tags requested."},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": float(0.35),
            "max_tokens": int(220),
        }

        last_err = None
        for attempt in range(max(1, HTTP_RETRIES)):
            try:
                r = await self.client.post(url, headers=headers, json=payload)
                if r.status_code >= 400:
                    raise RuntimeError(f"HTTP {r.status_code}: {r.text[:2000]}")
                j = r.json()
                content = j["choices"][0]["message"]["content"]
                obj = safe_json_extract(content) or {}
                topics = obj.get("topics", [])
                if not isinstance(topics, list):
                    topics = []
                topics = [clean_text(t, 60) for t in topics if clean_text(t, 60)]
                # de-dupe (stable)
                seen = set()
                out = []
                for t in topics:
                    k = t.lower()
                    if k in seen:
                        continue
                    seen.add(k)
                    out.append(t)
                    if len(out) >= TOPIC_MAX:
                        break
                return out
            except Exception as e:
                last_err = e
                await asyncio.sleep((2 ** attempt) * HTTP_BACKOFF)
        raise RuntimeError(str(last_err) if last_err else "OpenAI topic prediction failed")

    def _prompt(self, cebs: str, orb: Dict[str, Any], tweet: TweetRow) -> str:
        t = clean_text(tweet.text, 3200)
        meta = {
            "tweet_id": tweet.tid,
            "author": tweet.author,
            "created_at": tweet.created_at,
            "src": tweet.src,
        }
        orb_ctx = json.dumps(orb, ensure_ascii=False)
        return (
            "[ACTION]\n"
            "You are a Social Safety Quantum scorer.\n"
            "Do not quote hate or extremist propaganda. If present, summarize safely.\n"
            "Return ONLY the specified JSON inside [REPLYFORMAT] tags.\n"
            "All scores are floats in [0,1].\n"
            "Fields:\n"
            "neg: negativity/hostility\n"
            "sar: sarcasm/wit intensity\n"
            "tone: bland/positive/constructive tone (1 = calm/positive)\n"
            "edu: educational value\n"
            "truth: truth-grounding (signals of evidence/uncertainty discipline)\n"
            "cool: interesting/novel (non-clickbait)\n"
            "click: clickbait/outrage bait\n"
            "incl: inclusion/empathy\n"
            "ext: extremism risk (polarization / dehumanization / recruitment vibes)\n"
            "summary: 1-2 sentences of what the tweet says\n"
            "tags: short list of topical tags\n"
            "title: a short safe title\n"
            "[/ACTION]\n"
            f"ORB_CONTEXT={orb_ctx}\n"
            f"META={json.dumps(meta, ensure_ascii=False)}\n"
            "TWEET_TEXT:\n"
            f"{t}\n"
            "[REPLYFORMAT]\n"
            "{\n"
            '  "neg": 0.0,\n'
            '  "sar": 0.0,\n'
            '  "tone": 0.0,\n'
            '  "edu": 0.0,\n'
            '  "truth": 0.0,\n'
            '  "cool": 0.0,\n'
            '  "click": 0.0,\n'
            '  "incl": 0.0,\n'
            '  "ext": 0.0,\n'
            '  "summary": "",\n'
            '  "tags": [],\n'
            '  "title": ""\n'
            "}\n"
            "[/REPLYFORMAT]\n"
        )


class CEBSystem:
    def __init__(self):
        self.seed = secrets.randbits(64)
        self.last = time.time()
        self.palette = self._new_palette()
        self.domain_bias = {d: (secrets.randbelow(1000) / 1000.0) for d in DEFAULT_DOMAINS}

    def _new_palette(self) -> List[Tuple[int, int, int]]:
        out = []
        for _ in range(18):
            a = secrets.randbelow(256)
            b = secrets.randbelow(256)
            c = secrets.randbelow(256)
            out.append((a, b, c))
        return out

    def tick(self):
        if time.time() - self.last > 5.0:
            self.palette = self._new_palette()
            self.last = time.time()

    def ceb_prompt(self) -> str:
        self.tick()
        cols = self.palette[:12]
        cebs = []
        for i, (r, g, b) in enumerate(cols):
            cebs.append({"i": i, "rgb": [r, g, b], "w": round(0.35 + 0.65 * secrets.randbelow(1000) / 1000.0, 6)})
        body = {
            "rgn": "RGN CEB SYSTEM (Color-Entanglement Bits) — SOCIAL SAFETY META-GENERATOR",
            "seed": str(self.seed),
            "cebs": cebs,
            "domains": DEFAULT_DOMAINS,
            "coupling": DOMAIN_COUPLING,
            "rules": [
                "No propaganda quoting",
                "No hate amplification",
                "Prefer calm and inclusive summaries",
                "Return strict JSON only",
            ],
        }
        return json.dumps(body, ensure_ascii=False)


def _mix_by_source(items: List[CarouselItem], max_ratio_topic: float) -> List[CarouselItem]:
    """
    Blend topic-sourced items into the queue without letting them dominate.
    Keeps order *within* each source by their existing ranking.
    """
    if not items:
        return items
    user_items = [it for it in items if (it.tweet.src or "") != "topic"]
    topic_items = [it for it in items if (it.tweet.src or "") == "topic"]
    if not topic_items:
        return items

    total = len(items)
    max_topic = int(max(1, round(total * float(max(0.0, min(1.0, max_ratio_topic))))))
    topic_items = topic_items[:max_topic]

    # simple interleave: 2 user : 1 topic (approx), adaptively
    out: List[CarouselItem] = []
    ui = ti = 0
    while ui < len(user_items) or ti < len(topic_items):
        # push a couple user items
        for _ in range(2):
            if ui < len(user_items):
                out.append(user_items[ui])
                ui += 1
        # push one topic item
        if ti < len(topic_items):
            out.append(topic_items[ti])
            ti += 1
        # if user exhausted, drain topics (already capped)
        if ui >= len(user_items) and ti < len(topic_items):
            out.extend(topic_items[ti:])
            break
    return out


class App:
    def __init__(self):
        self.runner = AsyncRunner()
        self.store = Store(APP_DB)
        self.vault = Vault(self.store)
        self.x = XClient()
        self.oai = OpenAIClient()
        self.ceb = CEBSystem()

        self.logs: List[str] = []
        self.mode = "main"
        self.input_buf = ""
        self.input_prompt = ""
        self.input_target = ""
        self.input_secret = False

        self.tweets: List[TweetRow] = []
        self.labels: Dict[str, TweetLabel] = {}
        self.carousel: List[CarouselItem] = []
        self.car_idx = 0
        self.car_paused = False
        self.car_next_ts = time.time() + 2.0
        self.session_total_s = 0.0
        self.session_left_s = 0.0
        self.session_active = False
        self.last_tick = time.time()

        self.tol_center = (0.55, 0.30, 0.30)
        self.tol_radius = 0.62
        self.learn_center = (0.55, 0.55, 0.25)
        self.learn_radius = 0.70

        self.posts_view = False
        self.posts: List[Dict[str, Any]] = []
        self.posts_sel = 0

        self.color_cache = ColorPairCache(max_pairs=120)

        self._pending = 0
        self._status = ""
        self._salt_hint = self.vault.export_salt_hint()
        self._salt_new = self.vault.salt_new

        # --- autonomous preference topic engine ---
        self.pref_enabled = True
        self.pref_topics: List[str] = []
        self.pref_last_reason = ""
        self.pref_next_ts = time.time() + 6.0

    def log(self, s: str):
        ts = time.strftime("%H:%M:%S")
        line = f"{ts} {clean_text(s, 240)}"
        self.logs.append(line)
        self.logs = self.logs[-220:]

    def status(self, s: str):
        self._status = clean_text(s, 240)

    def shutdown(self):
        try:
            self.runner.submit(self.x.close())
            self.runner.submit(self.oai.close())
        except Exception:
            pass
        try:
            self.runner.stop()
        except Exception:
            pass

    def run(self):
        fut = self.runner.submit(self.store.init())
        fut.result(timeout=30)
        curses.wrapper(self._main)

    def _main(self, stdscr):
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(30)
        try:
            curses.start_color()
            curses.use_default_colors()
        except Exception:
            pass

        self.log(
            "keys: Q quit | U unlock | S settings | F fetch | B build carousel | T timebox | "
            "SPACE pause | N next | L label | R refresh topics | G toggle topics | "
            "P post | V posts | arrows move orb | +/- radius | [] learning radius | I show salt export"
        )
        if self._salt_new:
            self.log("new salt generated; press I to display export line")

        self._refresh_cache()

        while True:
            now = time.time()
            dt = max(0.001, now - self.last_tick)
            self.last_tick = now

            if self.session_active and not self.car_paused:
                self.session_left_s = max(0.0, self.session_left_s - dt)
                if self.session_left_s <= 0.0:
                    self.session_active = False
                    self.car_paused = True
                    self.log("session complete")

            if (not self.car_paused) and self.carousel:
                if time.time() >= self.car_next_ts:
                    self._advance_carousel()

            # autonomous topic refresh tick
            if self.pref_enabled and self.vault.unlocked and time.time() >= float(self.pref_next_ts):
                self.pref_next_ts = time.time() + float(max(60.0, TOPIC_REFRESH_S))
                self._refresh_topics_async()

            if now - getattr(self, "_last_refresh_ui", 0.0) > RGN_REFRESH:
                self._draw(stdscr)
                self._last_refresh_ui = now

            ch = stdscr.getch()
            if ch == -1:
                continue
            if self.mode == "input":
                if self._handle_input_key(ch):
                    continue
            if ch in (ord("q"), ord("Q")):
                self.log("quit")
                break
            self._handle_key(ch)

        self.shutdown()

    def _handle_input_key(self, ch: int) -> bool:
        if ch in (27,):
            self.mode = "main"
            self.input_buf = ""
            self.input_prompt = ""
            self.input_target = ""
            self.input_secret = False
            self.log("input canceled")
            return True
        if ch in (10, 13):
            val = self.input_buf
            tgt = self.input_target
            self.mode = "main"
            self.input_buf = ""
            self.input_prompt = ""
            self.input_target = ""
            self.input_secret = False
            self._on_input_submit(tgt, val)
            return True
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            self.input_buf = self.input_buf[:-1]
            return True
        if 0 <= ch <= 255:
            c = chr(ch)
            if c.isprintable():
                if len(self.input_buf) < 2048:
                    self.input_buf += c
            return True
        return False

    def _prompt_input(self, prompt: str, target: str, secret: bool = False):
        self.mode = "input"
        self.input_prompt = clean_text(prompt, 140)
        self.input_target = clean_text(target, 64)
        self.input_buf = ""
        self.input_secret = bool(secret)

    def _on_input_submit(self, target: str, val: str):
        val = val.rstrip("\n")
        if target == "unlock":
            self._unlock(val)
            return
        if target == "set_x_user":
            self._set_setting("x_user_id", val)
            return
        if target == "set_x_bearer":
            self._set_setting("x_bearer", val)
            return
        if target == "set_openai_key":
            self._set_setting("openai_key", val)
            return
        if target == "set_openai_model":
            self._set_setting("openai_model", val)
            return
        if target == "timebox":
            mins = max(1, min(240, parse_int(val, 10)))
            self._start_timebox(mins)
            return
        if target == "post_title":
            self._post_title = clean_text(val, 180)
            self._prompt_input("post notes", "post_notes", secret=False)
            return
        if target == "post_notes":
            self._post_notes = clean_text(val, 3000)
            self._save_post()
            return
        if target == "set_tol_center":
            parts = [p.strip() for p in val.split(",")]
            if len(parts) == 3:
                self.tol_center = (
                    clamp01(parse_float(parts[0], self.tol_center[0])),
                    clamp01(parse_float(parts[1], self.tol_center[1])),
                    clamp01(parse_float(parts[2], self.tol_center[2])),
                )
                self.log("tolerance center set")
                self._rebuild_carousel()
            return
        if target == "set_learn_center":
            parts = [p.strip() for p in val.split(",")]
            if len(parts) == 3:
                self.learn_center = (
                    clamp01(parse_float(parts[0], self.learn_center[0])),
                    clamp01(parse_float(parts[1], self.learn_center[1])),
                    clamp01(parse_float(parts[2], self.learn_center[2])),
                )
                self.log("learning center set")
                self._rebuild_carousel()
            return

    def _unlock(self, passphrase: str):
        self.status("unlocking...")
        fut = self.runner.submit(self.vault.unlock(passphrase))
        ok = False
        try:
            ok = bool(fut.result(timeout=30))
        except Exception:
            ok = False
        if ok:
            self.log("vault unlocked")
            self.status("vault unlocked")
            self._refresh_cache()
            self.pref_next_ts = time.time() + 2.5
        else:
            self.log(self.vault.last_hint or "unlock failed")
            self.status("unlock failed")

    def _set_setting(self, key: str, val: str):
        if not self.vault.unlocked:
            self.log("unlock first")
            return
        val = clean_text(val, 4000)
        self.status(f"set {key}")
        fut = self.runner.submit(self.vault.set(key, val))
        try:
            fut.result(timeout=30)
            self.log(f"saved {key}")
            self._refresh_cache()
            if key in ("openai_key", "x_bearer"):
                self.pref_next_ts = time.time() + 3.0
        except Exception as e:
            self.log(f"save failed: {e}")

    def _refresh_cache(self):
        self._pending = 1
        fut = self.runner.submit(self.store.list_tweets(limit=900))
        try:
            self.tweets = fut.result(timeout=30)
        except Exception:
            self.tweets = []
        self.labels = {}
        if self.tweets:
            ids = [t.tid for t in self.tweets[:650]]
            fut2 = self.runner.submit(self._bulk_labels(ids))
            try:
                self.labels = fut2.result(timeout=30)
            except Exception:
                self.labels = {}
        self._pending = 0
        self._rebuild_carousel()

    async def _bulk_labels(self, ids: List[str]) -> Dict[str, TweetLabel]:
        out: Dict[str, TweetLabel] = {}
        if not ids:
            return out
        async with aiosqlite.connect(self.store.db_path) as db:
            q = "SELECT tid,neg,sar,tone,edu,truth,cool,click,incl,ext,summary,tags_json,raw_json,model,created_at FROM labels WHERE tid IN ({})".format(
                ",".join(["?"] * len(ids))
            )
            async with db.execute(q, tuple(ids)) as cur:
                async for row in cur:
                    out[row[0]] = TweetLabel(
                        tid=row[0],
                        neg=float(row[1] or 0.0),
                        sar=float(row[2] or 0.0),
                        tone=float(row[3] or 0.0),
                        edu=float(row[4] or 0.0),
                        truth=float(row[5] or 0.0),
                        cool=float(row[6] or 0.0),
                        click=float(row[7] or 0.0),
                        incl=float(row[8] or 0.0),
                        ext=float(row[9] or 0.0),
                        summary=row[10] or "",
                        tags_json=row[11] or "[]",
                        raw_json=row[12] or "{}",
                        model=row[13] or "",
                        created_at=row[14] or "",
                    )
        return out

    def _open_settings_menu(self):
        if not self.vault.unlocked:
            self.log("unlock first")
            return
        self.log("settings: X user id, X bearer, OpenAI key, OpenAI model")
        self.log("press: a=x_user_id  b=x_bearer  c=openai_key  d=openai_model")
        self.status("settings hotkeys active for 2s")
        self._settings_until = time.time() + 2.0

    def _settings_hotkey(self, ch: int) -> bool:
        if not hasattr(self, "_settings_until"):
            return False
        if time.time() > float(getattr(self, "_settings_until", 0.0)):
            return False
        if ch in (ord("a"), ord("A")):
            self._prompt_input("X user id", "set_x_user", secret=False)
            return True
        if ch in (ord("b"), ord("B")):
            self._prompt_input("X bearer token", "set_x_bearer", secret=True)
            return True
        if ch in (ord("c"), ord("C")):
            self._prompt_input("OpenAI API key", "set_openai_key", secret=True)
            return True
        if ch in (ord("d"), ord("D")):
            self._prompt_input("OpenAI model", "set_openai_model", secret=False)
            return True
        return False

    def _fetch_x(self):
        if not self.vault.unlocked:
            self.log("unlock first")
            return
        bearer = self.vault.get("x_bearer", "")
        user_id = self.vault.get("x_user_id", "")
        if not bearer or not user_id:
            self.log("missing x_bearer or x_user_id in settings")
            return
        self.status("fetching X...")
        self._pending += 1

        async def job():
            payload = await self.x.fetch_user_tweets(bearer=bearer, user_id=user_id, max_results=90)
            tweets = self.x.parse_tweets(payload, src="user")
            await self.store.upsert_tweets(tweets)
            return len(tweets), payload.get("meta", {})

        fut = self.runner.submit(job())

        def done():
            try:
                n, meta = fut.result(timeout=60)
                self.log(f"fetched {n} tweets")
                if meta:
                    self.log(f"meta result_count={meta.get('result_count')}")
                self._refresh_cache()
                self.pref_next_ts = time.time() + 2.0
            except Exception as e:
                self.log(f"fetch error: {e}")
            self._pending -= 1
            self.status("")

        threading.Thread(target=done, daemon=True).start()

    def _label_more(self):
        if not self.vault.unlocked:
            self.log("unlock first")
            return
        api_key = self.vault.get("openai_key", "")
        model = self.vault.get("openai_model", OPENAI_MODEL_DEFAULT) or OPENAI_MODEL_DEFAULT
        if not api_key:
            self.log("missing openai_key")
            return
        self.status("labeling...")
        self._pending += 1
        ceb_pack = {"cebs": self.ceb.ceb_prompt(), "orb": self._orb_context()}

        async def job():
            ids = await self.store.unlabeled_tweet_ids(limit=LABEL_BATCH)
            if not ids:
                return 0
            for tid in ids:
                t = await self.store.get_tweet(tid)
                if not t:
                    continue
                obj = await self.oai.label_tweet(api_key=api_key, model=model, ceb=ceb_pack, tweet=t)
                lab = self._label_from_obj(tid, obj, model)
                await self.store.upsert_label(lab)
            return len(ids)

        fut = self.runner.submit(job())

        def done():
            try:
                n = fut.result(timeout=160)
                self.log(f"labeled {n}")
                self._refresh_cache()
            except Exception as e:
                self.log(f"label error: {e}")
            self._pending -= 1
            self.status("")

        threading.Thread(target=done, daemon=True).start()

    def _label_from_obj(self, tid: str, obj: Dict[str, Any], model: str) -> TweetLabel:
        neg = clamp01(obj.get("neg", 0.0))
        sar = clamp01(obj.get("sar", 0.0))
        tone = clamp01(obj.get("tone", 0.0))
        edu = clamp01(obj.get("edu", 0.0))
        truth = clamp01(obj.get("truth", 0.0))
        cool = clamp01(obj.get("cool", 0.0))
        click = clamp01(obj.get("click", 0.0))
        incl = clamp01(obj.get("incl", 0.0))
        ext = clamp01(obj.get("ext", 0.0))
        summary = clean_text(obj.get("summary", "") or "", 420)
        tags = obj.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        tags = [clean_text(x, 48) for x in tags[:14]]
        title = clean_text(obj.get("title", "") or "", 140)
        raw_json = json.dumps(obj, ensure_ascii=False)
        pack = {"title": title, "obj": obj}
        return TweetLabel(
            tid=clean_text(tid, 64),
            neg=float(neg),
            sar=float(sar),
            tone=float(tone),
            edu=float(edu),
            truth=float(truth),
            cool=float(cool),
            click=float(click),
            incl=float(incl),
            ext=float(ext),
            summary=summary,
            tags_json=json.dumps(tags, ensure_ascii=False),
            raw_json=json.dumps(pack, ensure_ascii=False),
            model=clean_text(model, 128),
            created_at=now_iso(),
        )

    def _orb_context(self) -> Dict[str, Any]:
        return {
            "tolerance": {"center": list(self.tol_center), "radius": float(self.tol_radius), "axes": ["tone", "neg", "sar"]},
            "learning": {"center": list(self.learn_center), "radius": float(self.learn_radius), "axes": ["edu", "truth", "click"]},
            "goal": "maximize learning per minute, minimize doomscroll, promote inclusion, reduce extremism risk",
        }

    def _start_timebox(self, minutes: int):
        self.session_total_s = float(minutes) * 60.0
        self.session_left_s = float(minutes) * 60.0
        self.session_active = True
        self.car_paused = False
        self.car_next_ts = time.time() + 1.5
        self.log(f"timebox started: {minutes} min")
        self._rebuild_carousel()
        self.pref_next_ts = time.time() + 2.0

    def _advance_carousel(self, force: bool = False):
        if not self.carousel:
            return
        if self.car_paused and not force:
            return
        self.car_idx = (self.car_idx + 1) % max(1, len(self.carousel))
        it = self.carousel[self.car_idx]
        self.car_next_ts = time.time() + float(max(CAROUSEL_MIN_DWELL, min(CAROUSEL_MAX_DWELL, it.dwell_s)))
        if force:
            self.log("next")
        if self.session_active and self.session_left_s < 8.0:
            self.car_next_ts = time.time() + min(2.2, max(0.8, self.session_left_s / 3.0))

    def _rebuild_carousel(self):
        self.ceb.tick()
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

        # Blend topic-sourced items, capped
        items = _mix_by_source(items, TOPIC_MAX_RATIO_IN_CAROUSEL)

        self.carousel = items[: max(10, min(240, len(items)))]
        self.car_idx = 0
        if self.carousel:
            self.car_next_ts = time.time() + float(max(CAROUSEL_MIN_DWELL, min(CAROUSEL_MAX_DWELL, self.carousel[0].dwell_s)))
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

    def _build_pref_context(self) -> Dict[str, Any]:
        """
        Summarize your recent labeled items + saved posts into a compact context
        for topic prediction.
        """
        # recent labeled tags/summaries
        recent = []
        for t in self.tweets[:220]:
            lab = self.labels.get(t.tid)
            if not lab:
                continue
            try:
                tags = json.loads(lab.tags_json or "[]")
                if not isinstance(tags, list):
                    tags = []
            except Exception:
                tags = []
            recent.append(
                {
                    "tid": t.tid,
                    "src": t.src,
                    "author": t.author,
                    "summary": clean_text(lab.summary, 240),
                    "tags": [clean_text(x, 24) for x in tags[:8]],
                    "scores": {
                        "edu": round(float(lab.edu), 3),
                        "truth": round(float(lab.truth), 3),
                        "incl": round(float(lab.incl), 3),
                        "click": round(float(lab.click), 3),
                        "neg": round(float(lab.neg), 3),
                    },
                }
            )
            if len(recent) >= 60:
                break

        # posts (user-curated)
        posts = []
        try:
            posts = (self.posts or [])[:40]
        except Exception:
            posts = []
        posts_slim = [{"title": clean_text(p.get("title", ""), 120), "notes": clean_text(p.get("notes", ""), 240)} for p in posts[:18]]

        return {
            "time_utc": now_iso(),
            "recent_labeled": recent,
            "saved_posts": posts_slim,
            "orb": self._orb_context(),
        }

    def _refresh_topics_async(self):
        if not self.vault.unlocked:
            return
        api_key = self.vault.get("openai_key", "")
        model = self.vault.get("openai_model", OPENAI_MODEL_DEFAULT) or OPENAI_MODEL_DEFAULT
        bearer = self.vault.get("x_bearer", "")
        if not api_key or not bearer:
            self.log("topics: need openai_key + x_bearer")
            return

        self._pending += 1
        self.status("topics: predicting + searching...")

        async def job():
            # ensure posts cache is fresh-ish (for context)
            try:
                self.posts = await self.store.list_posts(limit=110)
            except Exception:
                pass

            ctx = self._build_pref_context()
            topics = await self.oai.predict_topics(api_key=api_key, model=model, context=ctx)
            q = build_topic_query(topics)
            if not q:
                return {"topics": topics, "fetched": 0, "labeled": 0, "query": ""}

            # Search a few pages (bounded)
            fetched_rows: List[TweetRow] = []
            next_token = None
            pages = 0
            target = max(10, min(80, int(TOPIC_SEARCH_PER_TOPIC * max(1, len(topics)) / 2)))
            while pages < 2 and len(fetched_rows) < target:
                payload = await self.x.search_recent(bearer=bearer, query=q, max_results=50, next_token=next_token)
                rows = self.x.parse_tweets(payload, src="topic")
                fetched_rows.extend(rows)
                meta = payload.get("meta") or {}
                next_token = meta.get("next_token")
                pages += 1
                if not next_token:
                    break

            # upsert tweets
            await self.store.upsert_tweets(fetched_rows)

            # label newest topic tweets so they can enter carousel immediately
            ceb_pack = {"cebs": self.ceb.ceb_prompt(), "orb": self._orb_context()}
            to_label = await self.store.unlabeled_tweet_ids(limit=max(LABEL_BATCH, 12))
            labeled = 0
            for tid in to_label:
                t = await self.store.get_tweet(tid)
                if not t:
                    continue
                # prioritize topic rows if possible
                if t.src == "topic" or labeled < LABEL_BATCH:
                    obj = await self.oai.label_tweet(api_key=api_key, model=model, ceb=ceb_pack, tweet=t)
                    lab = self._label_from_obj(tid, obj, model)
                    await self.store.upsert_label(lab)
                    labeled += 1
                    if labeled >= 14:
                        break

            return {"topics": topics, "fetched": len(fetched_rows), "labeled": labeled, "query": q}

        fut = self.runner.submit(job())

        def done():
            try:
                res = fut.result(timeout=220)
                self.pref_topics = list(res.get("topics", []) or [])
                self.log(f"topics: {', '.join(self.pref_topics[:10])}" if self.pref_topics else "topics: (none)")
                self.log(f"topics: fetched={res.get('fetched')} labeled={res.get('labeled')}")
                q = res.get("query", "")
                if q:
                    self.log(f"topics query: {q[:180]}")
                self._refresh_cache()
            except Exception as e:
                self.log(f"topics error: {e}")
            self._pending -= 1
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

        if ch in (ord("g"), ord("G")):
            self.pref_enabled = not self.pref_enabled
            self.log("topics enabled" if self.pref_enabled else "topics disabled")
            if self.pref_enabled:
                self.pref_next_ts = time.time() + 1.0
            return

        if ch in (ord("r"), ord("R")):
            if not self.vault.unlocked:
                self.log("unlock first")
                return
            self.pref_next_ts = time.time() + 0.2
            self.log("topics refresh requested")
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

    def _draw_orb(
        self,
        stdscr,
        y: int,
        x: int,
        w: int,
        h: int,
        center: Tuple[float, float, float],
        radius: float,
        pt: Tuple[float, float, float],
        title: str,
    ):
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
            ses = " done"
        tflag = "topics:on" if self.pref_enabled else "topics:off"
        tpeek = (", ".join(self.pref_topics[:4])[:64]) if self.pref_topics else ""
        line0 = f"{title} | {lock}{pend}{ses} | {tflag} {tpeek} | {status}"
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
            src = it.tweet.src or "user"
            s = f"{i:02d} ipm={ipm:0.2f} neg={lab.neg:0.2f} edu={lab.edu:0.2f} truth={lab.truth:0.2f} [{src}] @{it.tweet.author}"
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
        src = t.src or "user"
        head = f"#{self.car_idx+1}/{len(self.carousel)}  id={t.tid}  [{src}] @{t.author}  {t.created_at}"
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
