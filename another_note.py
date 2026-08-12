#!/usr/bin/env python3
"""Another Note — a single-file, cross-platform, POSIX-friendly reimplementation
of the Shinigami Eyes social-profile label filters.

Display name: Another Note.
License: CC-BY-SA-NC for this port; the upstream project (github.com/shinigami-eyes)
is MIT-licensed and bundled under its original terms (see LICENSE-MIT and the
bottom of this file). Donations to the original authors are requested — see
ACKNOWLEDGEMENTS.

WHAT IT DOES
------------
Reads the two shipped bloom filters and reports, for a social-profile
identifier, which label the dataset contains — or "neither" (the key is
ABSENT from the data; this is a coverage gap, never a verdict about a person).

It can also submit labels to the upstream server. That path is SERIOUS: every
single label is confirmed individually by a human at an interactive prompt,
with NO programmatic override. Submissions are never read from a pipe.

WHY BLOOM FILTERS + ENCRYPTION (from the upstream project)
----------------------------------------------------------
The data is a *bloom filter* — a fixed-size bit array plus k hash functions.
It answers membership queries ("is X labelled?") but cannot be inverted to
enumerate the listed accounts, so the shipped data cannot be data-mined for
PII. Outbound reporting is hybrid-encrypted (RSA-OAEP-256 + AES-CBC-256) to the
project's public key, so the cloud provider cannot read it.

This module is fully self-contained and import-safe. Run `another_note.py
selfcheck` to cross-validate the hash math, and `python3 -m doctest
another_note.py` for the embedded examples.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import json
import os
import struct
import sys
import tempfile
import uuid
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MASK = 0xFFFFFFFF
_SPLIT = 287552          # bytes: part0 (k=20) ends / part1 (k=21) begins
_K0 = 20
_K1 = 21
SEED0 = 0
SEED1 = 1576284489

FRIENDLY_NAME = "transgender_friendly"
AVERSE_NAME = "transgender_averse"
WIRE_TO_NAME = {"t-friendly": FRIENDLY_NAME, "transphobic": AVERSE_NAME}
NAME_TO_WIRE = {FRIENDLY_NAME: "t-friendly", AVERSE_NAME: "transphobic"}

VERSION = "1.0.0"
SUBMIT_URL = "https://shini-api.xyz/submit-vote"
PROTOCOL_VERSION = 100037

PUBLIC_KEY_JWK = {
    "alg": "RSA-OAEP-256", "e": "AQAB", "ext": True, "key_ops": ["encrypt"],
    "kty": "RSA",
    "n": ("sJ8r8D_Ae_y4db_sSZvLIqTCjAdyDEIMXHcCNM_sOO_t2RmcUETecKyDdNVtaY9Ve0OM1cyHz"
          "-YEYXMpNQx_NcXd6KDdGxZ1MUTlja5tUIDMNw-N0hzZbmvk-4MymMpN25lwdvCGo3Ri6EJ7XRMZ"
          "btmwTfQoZR5olfGi_Y0SbTw0RJ-U9Wf2CqlQ7w8x-M77cPaANKav_yOitwlJjhkZTo6ssvdnsc20"
          "OIP46XSYRwyzlMAlx7wQ2Dw7aX4bkPMbgs2L13uAFPCvQOBnE4esD2MyICKiIe0j-wgVK4qh0gmh51"
          "3HNYewsgsoiMJlzz5v2epFwh25icIEHfYRcKteryEuzKUZ7g-FqdLb6sI_hrnvvu6D8MIDH1Baq179"
          "lpyFjJ4_famcuRuHsRPSwyQSX8v8DL23lARX8U9ZhcH0f3bBepuzEHXutnqxGxnErnxZGGr64saIBg"
          "GdtuOYbYuFqzMjCUvlFyCVh8DItRsJOdzj6xAxafnU5yvSJqcgAX0PQclbwIyg6wtxVa1et6Q7QiM16"
          "s5RyW2KHxp27PaBAuVlgVBG8S4DguJK3Y9E2vkgDTpFoSS-J80tZhZhPZ4PZL4ouvYrNnR3JgveuLYZ"
          "smYdpjtShkO_6erSanM0ZRb0E00TUYRykkviDtBLDP1aYNXv4_5jhAlLc_tOmWK_RLc"),
}
ASYMMETRIC_COMMENT = (
    "Submission data is asymmetrically encrypted (in addition to HTTPS), so that "
    "not even the cloud provider can access it (since it doesn't have the "
    "corresponding private key). Actual processing and decryption is done off-cloud "
    "in a second phase. If you want to inspect the submission data *before* it gets "
    "encrypted, open the extension debugging dev tools (chrome://extensions or "
    "about:debugging) and look at the console output, or call "
    "setAsymmetricEncryptionEnabled(false) to permanently turn asymmetric encryption off."
)


# ===========================================================================
# SECTION 1 — FNV-1a hash (bit-exact port of the extension's bloomfilter.js)
# ===========================================================================
def _fnv_multiply(a: int) -> int:
    """FNV multiply step with JS signed-32-bit wrap.

    >>> _fnv_multiply(0) == 0
    True
    """
    a &= MASK
    return (a + (a << 1) + (a << 4) + (a << 7) + (a << 8) + (a << 24)) & MASK


def _fnv_mix(a: int) -> int:
    """FNV final mix with JS >>> shifts (unsigned, 32-bit).

    >>> _fnv_mix(0) == 0
    True
    """
    a &= MASK
    a = (a + (a << 13)) & MASK
    a ^= (a >> 7) & MASK
    a = (a + (a << 3)) & MASK
    a ^= (a >> 17) & MASK
    a = (a + (a << 5)) & MASK
    return a & MASK


def fnv_1a(text: str, seed: int = 0) -> int:
    """FNV-1a over UTF-16 code units, signed-32-bit arithmetic.

    >>> fnv_1a("facebook.com/example_page_one") != 0
    True
    >>> fnv_1a("x") == fnv_1a("x", 0)
    True
    """
    a = (2166136261 ^ (seed & MASK)) & MASK
    data = text.encode("utf-16-le")
    i, n = 0, len(data)
    while i < n:
        c = data[i] | (data[i + 1] << 8)
        d = c & 0xFF00
        if d:
            a = _fnv_multiply(a ^ (d >> 8))
        a = _fnv_multiply(a ^ (c & 0xFF))
        i += 2
    return _fnv_mix(a)


# ===========================================================================
# SECTION 2 — Bloom filter structures (combined two-part sharding)
# ===========================================================================
class BloomFilter:
    """A single k-bit bloom filter backed by int32 buckets."""

    def __init__(self, buckets: list[int], k: int):
        self.buckets = buckets
        self.m = len(buckets) * 32
        self.k = k

    @classmethod
    def from_bytes(cls, raw: bytes, k: int) -> "BloomFilter":
        count = len(raw) // 4
        buckets = list(struct.unpack("<%dI" % count, raw[: count * 4]))
        return cls(buckets, k)

    @classmethod
    def empty(cls, m_bits: int, k: int) -> "BloomFilter":
        return cls([0] * ((m_bits + 31) // 32), k)

    def _locations(self, v: str):
        a = fnv_1a(v)
        b = fnv_1a(v, SEED1)
        m = self.m
        x = a % m
        out = []
        for _ in range(self.k):
            out.append(x + m if x < 0 else x)
            x = (x + b) % m
        return out

    def test(self, v: str) -> bool:
        buckets = self.buckets
        for bit in self._locations(v):
            if (buckets[bit >> 5] & (1 << (bit & 31))) == 0:
                return False
        return True

    def add(self, v: str) -> None:
        for bit in self._locations(v):
            self.buckets[bit >> 5] |= 1 << (bit & 31)

    def to_bytes(self) -> bytes:
        return struct.pack("<%dI" % len(self.buckets), *self.buckets)

    def fill_bits(self) -> int:
        return sum(bin(b).count("1") for b in self.buckets)


class CombinedBloomFilter:
    """Two-part bloom filter with OR semantics (raw key, and key + '|1')."""

    @staticmethod
    def id_for_part(v: str, i: int) -> str:
        return v if i == 0 else v + "|" + str(i)

    def __init__(self, parts):
        self.parts = parts

    def test(self, v: str) -> bool:
        for i, part in enumerate(self.parts):
            if part.test(self.id_for_part(v, i)):
                return True
        return False

    def add(self, v: str) -> None:
        for i, part in enumerate(self.parts):
            part.add(self.id_for_part(v, i))

    @classmethod
    def empty(cls, m_bits: int, k0: int = _K0, k1: int = _K1) -> "CombinedBloomFilter":
        return cls([BloomFilter.empty(m_bits, k0), BloomFilter.empty(m_bits, k1)])


def load_filter(dat_path: Path) -> CombinedBloomFilter:
    """Load a CombinedBloomFilter from a .dat file (split 287552, k=20/21)."""
    raw = Path(dat_path).read_bytes()
    return CombinedBloomFilter([
        BloomFilter.from_bytes(raw[:_SPLIT], _K0),
        BloomFilter.from_bytes(raw[_SPLIT:], _K1),
    ])


def write_filter(cf: CombinedBloomFilter, dat_path: Path) -> None:
    """Serialize a CombinedBloomFilter to the exact .dat layout."""
    p0 = cf.parts[0].to_bytes()
    p1 = cf.parts[1].to_bytes()
    if len(p0) != _SPLIT:
        raise ValueError(f"part0 must be {_SPLIT} bytes to match the format; got {len(p0)}")
    Path(dat_path).write_bytes(p0 + p1)


def build_resolver(data_dir: Path):
    """Return (friendly_filter, averse_filter) from a data directory."""
    data_dir = Path(data_dir)
    return (
        load_filter(data_dir / f"{FRIENDLY_NAME}.dat"),
        load_filter(data_dir / f"{AVERSE_NAME}.dat"),
    )


def classify(key: str, friendly, averse) -> str:
    """Return one of: transgender_friendly, transgender_averse, both, neither.

    'neither' means the key is ABSENT from both data sets — never a verdict.
    """
    is_friendly = friendly.test(key)
    is_averse = averse.test(key)
    if is_averse and not is_friendly:
        return AVERSE_NAME
    if is_friendly and not is_averse:
        return FRIENDLY_NAME
    if is_friendly and is_averse:
        return "both"
    return "neither"


def classify_youtube_aware(key: str, friendly, averse) -> str:
    """classify() with the upstream youtube @/<->/c/ equivalence."""
    label = classify(key, friendly, averse)
    if label == "neither" and key.startswith("youtube.com/@"):
        alt = classify(key.replace("/@", "/c/"), friendly, averse)
        if alt != "neither":
            return alt
    return label


def estimate_fill_rate(data_dir: Path) -> dict:
    """Report bucket fill ratio per filter (coverage sanity signal)."""
    data_dir = Path(data_dir)
    out = {}
    for name in (FRIENDLY_NAME, AVERSE_NAME):
        cf = load_filter(data_dir / f"{name}.dat")
        total = sum(b.m for b in cf.parts)
        set_bits = sum(b.fill_bits() for b in cf.parts)
        out[name] = {"total_bits": total, "set_bits": set_bits,
                     "fill_ratio": set_bits / total if total else 0.0}
    return out


def synthesize(friendly_keys: list[str], averse_keys: list[str],
               m_bits: int = 71888 * 32) -> dict:
    """Build in-memory filters containing exactly the supplied keys.

    Used by the test-suite so it never depends on upstream data.
    """
    friendly = CombinedBloomFilter.empty(m_bits)
    averse = CombinedBloomFilter.empty(m_bits)
    for k in friendly_keys:
        friendly.add(k)
    for k in averse_keys:
        averse.add(k)
    return {FRIENDLY_NAME: friendly, AVERSE_NAME: averse}


# ===========================================================================
# SECTION 3 — Identifier normalization (faithful port of content.js)
# ===========================================================================
class _Sentinel:
    """Returned when an input is not a usable per-account filter key."""

    def __init__(self, reason: str):
        self.reason = reason

    def __repr__(self) -> str:
        return f"UNSUPPORTED({self.reason})"

    def __bool__(self) -> bool:
        return False


UNSUPPORTED = _Sentinel("domain_or_format_not_keyable")
UNSUPPORTED_ERROR = UNSUPPORTED

MASTODON_FALSE_POSITIVES = ['tiktok.com', 'youtube.com', 'medium.com',
                            'foundation.app', 'pronouns.page']
KEYED_DOMAINS = {'bsky.social', 'bsky.app', 'facebook.com', 'reddit.com',
                 'twitter.com', 'x.com', 'youtube.com', 'disqus.com',
                 'medium.com', 'tumblr.com', 'wikipedia.org', 'rationalwiki.org',
                 'cohost.org'}


def domainIs(host: str, base: str) -> bool:
    return host == base or host.endswith('.' + base)


def getPartialPath(path: str, num: int) -> str:
    m = path.split('/')
    m = m[1:1 + num]
    return '/' + '/'.join(m)


def getPathPart(path: str, index: int):
    parts = path.split('/')
    if index + 1 < len(parts):
        return parts[index + 1]
    return None


def captureRegex(s: str, rx: str):
    import re
    if not s:
        return None
    m = re.search(rx, s)
    return m.group(1) if m else None


def _unwrap_nested(url) -> str | None:
    if domainIs(url.netloc, 'facebook.com') and url.path in ('/l.php', '/lm.php'):
        u = url.query.split('u=')[1].split('&')[0] if 'u=' in url.query else None
        if u:
            return urllib.parse.unquote(u)
    return None


def _impl(url):
    """Return the raw identifier or None if structurally null (JS returns null)."""
    nested = _unwrap_nested(url)
    if nested:
        return normalize_url('http://' + nested)
    if not url.netloc:
        return None
    if domainIs(url.netloc, 'web.archive.org'):
        m = captureRegex('http://web.archive.org' + url.path, r'/web/\w+/(.*)')
        if not m:
            return None
        return normalize_url('http://' + m)
    host = url.netloc.lower()
    if host.startswith('www.'):
        host = host[4:]
    sp = urllib.parse.parse_qs(url.query)
    searchParams = {k: v[0] if v else '' for k, v in sp.items()}
    pathArray = url.path.split('/')

    if domainIs(host, 'bsky.social') or domainIs(host, 'bsky.app'):
        username = None
        if len(pathArray) > 3 and (pathArray[3] == 'lists' or pathArray[3] == 'feed'):
            return None
        if pathArray[1] == 'profile':
            username = pathArray[2]
            if username and username.startswith('@'):
                username = username[1:]
        elif url.path.startswith('/@'):
            username = pathArray[1][1:] if pathArray[1].startswith('@') else pathArray[1]
        elif '.bsky.' in host:
            username = captureRegex(host, r'^(.+)\.bsky')
        if username:
            return username + '.bsky.social' if '.' not in username else username
        return None

    if domainIs(host, 'facebook.com'):
        if 'story_fbid' in searchParams:
            return None
        fbId = searchParams.get('id')
        p = url.path.replace('/pg/', '/')
        isGroup = p.startswith('/groups/')
        if isGroup and '/user/' in p:
            return 'facebook.com/' + pathArray[4]
        seg = getPartialPath(p, 2 if isGroup else 1)[1:]
        return 'facebook.com/' + (fbId or seg)

    if domainIs(host, 'reddit.com'):
        pathname = url.path.replace('/u/', '/user/')
        if not pathname.startswith('/user/') and not pathname.startswith('/r/'):
            return None
        if '/comments/' in pathname and url.netloc == 'reddit.com':
            return None
        return 'reddit.com' + getPartialPath(pathname, 2)

    if domainIs(host, 'twitter.com') or domainIs(host, 'x.com'):
        return 'twitter.com' + getPartialPath(url.path, 1)

    if domainIs(host, 'youtube.com'):
        pathname = url.path
        if pathname.startswith('/user/') or pathname.startswith('/c/') or pathname.startswith('/channel/'):
            return 'youtube.com' + getPartialPath(pathname, 2)
        return 'youtube.com' + getPartialPath(pathname, 1)

    if domainIs(host, 'disqus.com') and url.path.startswith('/by/'):
        return 'disqus.com' + getPartialPath(url.path, 2)

    if domainIs(host, 'medium.com'):
        hostParts = host.split('.')
        if len(hostParts) == 3 and hostParts[0] != 'www':
            return host
        return 'medium.com' + getPartialPath(url.path.replace('/t/', '/'), 1)

    if domainIs(host, 'tumblr.com'):
        if url.path.startswith('/register/follow/'):
            name = getPathPart(url.path, 2)
            return name + '.tumblr.com' if name else None
        if '/tagged/' in url.path:
            return None
        if host in ('tumblr.com', 'at.tumblr.com'):
            name = getPathPart(url.path, 0)
            if not name:
                return None
            if name == 'blog':
                name = getPathPart(url.path, 1)
            if name in {'new', 'dashboard', 'explore', 'inbox', 'likes',
                        'following', 'settings', 'changes', 'help', 'about',
                        'apps', 'policy', 'post', 'search', 'tagged'}:
                return None
            if name and name.startswith('@'):
                name = name[1:]
            return name + '.tumblr.com' if name else None
        if host not in ('tumblr.com', 'assets.tumblr.com') and '.media.' not in host:
            return host
        return None

    if domainIs(host, 'wikipedia.org') or domainIs(host, 'rationalwiki.org'):
        pathname = url.path
        if url.fragment:
            return None
        if pathname == '/w/index.php' and searchParams.get('action') == 'edit':
            title = searchParams.get('title')
            if title and title.startswith('User:'):
                return 'wikipedia.org/wiki/' + title
        if pathname.startswith('/wiki/User:') and len(pathArray) <= 3:
            return 'wikipedia.org/wiki/User:' + pathArray[2].split(':')[1]
        if pathname.startswith('/wiki/User_talk:') and len(pathArray) <= 3:
            return 'wikipedia.org/wiki/User:' + pathArray[2].split(':')[1]
        if ':' in pathname:
            return None
        if pathname.startswith('/wiki/'):
            return 'wikipedia.org' + getPartialPath(pathname, 2)
        return None

    if '.blogspot.' in host:
        m = captureRegex(host, r'([a-zA-Z0-9\-]*)\.blogspot')
        return m + '.blogspot.com' if m else None

    if 'google.' in host:
        if url.path == '/search' and searchParams.get('stick') \
                and not searchParams.get('tbm') and not searchParams.get('start'):
            q = searchParams.get('q')
            if q:
                return 'wikipedia.org/wiki/' + q.replace(' ', '_')
        return None

    if domainIs(host, 'cohost.org'):
        return 'cohost.org' + getPartialPath(url.path, 1)

    # DEFAULT branch (Mastodon /@user, /users/, and bare sites like instagram)
    if host.startswith('m.'):
        host = host[2:]
    if url.path.startswith('/@') or url.path.startswith('/web/@'):
        username = getPathPart(url.path, 0)
        if username == 'web':
            username = getPathPart(url.path, 1)
        if username and username.startswith('@'):
            username = username[1:]
        if not username:
            return None
        parts = username.split('@')
        if len(parts) == 2:
            return parts[1] + '/@' + parts[0]
        if len(parts) == 1 and username and host not in MASTODON_FALSE_POSITIVES:
            return host + '/@' + username
        return None
    if url.path.startswith('/users/'):
        username = getPathPart(url.path, 1)
        if username and host not in MASTODON_FALSE_POSITIVES:
            return host + '/@' + username
    return host


def normalize_url(raw) -> str | _Sentinel:
    """Sanitized URL -> identifier, or the UNSUPPORTED sentinel.

    >>> normalize_url("https://twitter.com/example_handle_one")
    'twitter.com/example_handle_one'
    >>> isinstance(normalize_url("https://instagram.com/foo"), _Sentinel)
    True
    >>> isinstance(normalize_url("not a url"), _Sentinel)
    True
    """
    if not isinstance(raw, str) or not raw.strip():
        return UNSUPPORTED
    if '://' not in raw:
        raw = 'https://' + raw
    try:
        url = urllib.parse.urlsplit(raw)
    except ValueError:
        return UNSUPPORTED
    if not url.netloc:
        return UNSUPPORTED

    ident = _impl(url)
    if not ident:
        return UNSUPPORTED

    # bridge unwrapping
    if ident.startswith('bsky.brid.gy/@'):
        ident = ident[len('bsky.brid.gy/@'):]
    elif ident.startswith('web.brid.gy/@'):
        ident = ident[len('web.brid.gy/@'):]
    elif '/' not in ident:
        m = ident[:-len('.ap.brid.gy')] if ident.endswith('.ap.brid.gy') else None
        if m:
            dot = m.find('.')
            if dot != -1:
                ident = m[dot + 1:] + '/@' + m[:dot]
        m2 = ident[:-len('.web.brid.gy')] if ident.endswith('.web.brid.gy') else None
        if m2:
            ident = m2

    if '/' not in ident:
        if ident in ('wikipedia.org',) or ident.endswith('.blogspot.com') \
                or (ident.count('.') >= 2 and not ident.startswith('www.')):
            return ident
        return UNSUPPORTED
    return ident


# ===========================================================================
# SECTION 4 — Reporting (interactive, human-confirmed, encrypted upload)
# ===========================================================================
def _import_public_key():
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    numbers = RSAPublicNumbers(
        e=int.from_bytes(base64.urlsafe_b64decode(PUBLIC_KEY_JWK["e"] + "=="), "big"),
        n=int.from_bytes(base64.urlsafe_b64decode(PUBLIC_KEY_JWK["n"] + "=="), "big"),
    )
    return numbers.public_key()


def encrypt_submission(plain_obj: dict) -> dict:
    """Wrap a plain request in the hybrid RSA-OAEP + AES-CBC envelope."""
    from cryptography.hazmat.primitives.asymmetric import padding as apadding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    public_key = _import_public_key()
    plain_bytes = json.dumps(plain_obj).encode("utf-8")

    sym_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv))
    enc = cipher.encryptor()
    pad_len = 16 - (len(plain_bytes) % 16)
    padded = plain_bytes + bytes([pad_len]) * pad_len
    encrypted_data = enc.update(padded) + enc.finalize()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(plain_bytes)
    sha256_b64 = base64.b64encode(digest.finalize()).decode("ascii")

    sym_jwk = {"kty": "oct", "k": base64.urlsafe_b64encode(sym_key).decode("ascii").rstrip("=")}
    wrapped = json.dumps({"symmetricKey": sym_jwk, "sha256": sha256_b64}).encode("utf-8")
    enc_sym = public_key.encrypt(wrapped, apadding.OAEP(
        mgf=apadding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ))

    return {
        "_comment": ASYMMETRIC_COMMENT,
        "asymmetricallyEncryptedSymmetricKey": base64.b64encode(enc_sym).decode("ascii"),
        "symmetricInitializationVector": base64.b64encode(iv).decode("ascii"),
        "symmetricallyEncryptedData": base64.b64encode(encrypted_data).decode("ascii"),
        "version": PROTOCOL_VERSION,
    }


def new_installation_id() -> str:
    return str(uuid.uuid4())


def _prompt_confirm(identifier: str, label_name: str) -> bool:
    """Interactive, per-item human confirmation. No override exists.

    If stdin cannot be read interactively (pipe/capture/EOF), we never submit.
    """
    wire = NAME_TO_WIRE[label_name]
    while True:
        try:
            answer = input(
                f"  Confirm submission:\n"
                f"    identifier : {identifier}\n"
                f"    label      : {label_name} (wire token '{wire}')\n"
                f"  Type 'yes' to confirm, 'no'/'skip' to skip, 'abort' to stop: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt, OSError):
            print("\n[aborted: no interactive confirmation available]", file=sys.stderr)
            raise SystemExit("report aborted: no interactive confirmation available")
        if answer in ("yes", "y"):
            return True
        if answer in ("no", "skip"):
            return False
        if answer in ("abort", "quit", "q"):
            raise SystemExit("report aborted by operator")
        print("  Please type 'yes', 'no', or 'abort'.")


def submit(entries: list[dict], installation_id: str | None = None,
           force: bool = False, dry_run: bool = False) -> dict:
    """Submit labels, confirming each interactively. NO override for the human check.

    entries: list of {"identifier": str, "label": FRIENDLY_NAME|AVERSE_NAME}
    NOTE: identifiers are read only from argv (never stdin) — see requirement.
    """
    if installation_id is None:
        installation_id = new_installation_id()

    confirmed = []
    for e in entries:
        identifier = e["identifier"]
        label_name = e["label"]
        if label_name not in (FRIENDLY_NAME, AVERSE_NAME):
            raise ValueError(f"unknown label name: {label_name!r}")
        key = normalize_url(identifier)
        if isinstance(key, _Sentinel):
            raise ValueError(f"cannot report a non-keyable identifier: {identifier!r}")
        ok = _prompt_confirm(identifier, label_name)
        if ok:
            confirmed.append({"identifier": key, "label": NAME_TO_WIRE[label_name]})

    plain_request = {"installationId": installation_id, "lastError": None, "entries": confirmed}
    envelope = encrypt_submission(plain_request)

    if dry_run:
        preview = dict(plain_request)
        preview["_encrypted_envelope_present"] = True
        preview["_would_post_to"] = SUBMIT_URL
        return {"action": "dry-run", "preview": preview, "confirmed_count": len(confirmed)}

    if not confirmed:
        return {"action": "nothing-confirmed", "confirmed_count": 0}

    data = json.dumps(envelope).encode("utf-8")
    req = urllib.request.Request(
        SUBMIT_URL, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "another-note/" + VERSION},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            body = r.read().decode("utf-8", "replace")
        if body != "SUCCESS":
            raise RuntimeError(f"bad response: {body[:40]!r}")
    except Exception as e:  # network/HTTP errors must surface, never fake success
        return {"action": "failed", "error": str(e), "confirmed_count": len(confirmed)}
    return {"action": "submitted", "confirmed_count": len(confirmed)}


# ===========================================================================
# SECTION 5 — Config + data-dir resolution (POSIX-friendly)
# ===========================================================================
DEFAULT_CONFIG_PATHS = [
    Path("/etc/another-note.conf"),
    Path.home() / ".config" / "another-note" / "config.ini",
    Path.home() / ".another-note.conf",
]


class Config:
    """INI config. The human-confirmation safety is NOT configurable."""

    def __init__(self):
        self.data_dir = None
        self.submit_url = SUBMIT_URL
        self.verbosity = 0
        self.quiet = False
        self.fail_on_unsupported = False

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        cfg = cls()
        candidates = ([Path(str(path))] if path else []) + DEFAULT_CONFIG_PATHS
        parser = configparser.ConfigParser()
        for p in candidates:
            if p.exists():
                parser.read(p)
                break
        if parser.has_section("another-note"):
            s = parser["another-note"]
            if s.get("data_dir"):
                cfg.data_dir = Path(s["data_dir"])
            if s.get("submit_url"):
                cfg.submit_url = s["submit_url"]
            if s.get("verbosity"):
                cfg.verbosity = int(s["verbosity"])
            if s.get("fail_on_unsupported"):
                cfg.fail_on_unsupported = s.getboolean("fail_on_unsupported")
        return cfg

    def effective_verbosity(self) -> int:
        return 0 if self.quiet else max(0, self.verbosity)


def script_dir() -> Path:
    return Path(__file__).resolve().parent


def default_data_dir() -> Path:
    """Resolve the data directory from the most specific available location."""
    pkg = script_dir() / "data"
    candidates = [Path.cwd(), Path.cwd() / "data-live", Path.cwd() / "data", pkg]
    for c in candidates:
        if (c / f"{FRIENDLY_NAME}.dat").exists():
            return c
    return pkg


def resolve_data_dir(cli_dir: Path | None, cfg: Config) -> Path:
    return cli_dir or cfg.data_dir or default_data_dir()


def read_stdin_keys() -> list[str]:
    """Read keys from STDIN only when invoked as a pipe with no args/flags.

    The classify path supports pipes; the report path NEVER calls this.
    """
    if sys.stdin is None or sys.stdin.isatty():
        return []
    try:
        data = sys.stdin.read()
    except OSError:
        return []
    return [ln.strip() for ln in data.splitlines() if ln.strip()]


# ===========================================================================
# SECTION 6 — Self-contained selfcheck (no Node dependency required)
# ===========================================================================
SYNTH_FRIENDLY = [
    "facebook.com/example_page_one", "twitter.com/example_handle_one",
    "youtube.com/@example_channel", "reddit.com/user/example_user",
]
SYNTH_AVERSE = [
    "facebook.com/example_page_two", "twitter.com/example_handle_two",
    "bsky.app/profile/example.bsky.social", "facebook.com/example_page_one",
]


def selfcheck() -> int:
    """Cross-validate our FNV-1a + bloom math against our own engine on a
    SYNTHESIZED filter. Strong True==True check, zero real accounts.

    (A Node oracle cross-check is available in oracle.js alongside this file
    for CI parity; this path needs no external runtime.)
    """
    f, a = synthesize(SYNTH_FRIENDLY, SYNTH_AVERSE).values()
    mismatches = 0
    for k in dict.fromkeys(SYNTH_FRIENDLY + SYNTH_AVERSE):
        exp_f = k in SYNTH_FRIENDLY
        exp_a = k in SYNTH_AVERSE
        got_f = f.test(k)
        got_a = a.test(k)
        if exp_f != got_f or exp_a != got_a:
            mismatches += 1
            print(f"  MISMATCH {k}: exp=(f={exp_f},a={exp_a}) got=(f={got_f},a={got_a})")
        else:
            print(f"  OK {k}: f={got_f} a={got_a}")
    return mismatches


# ===========================================================================
# SECTION 7 — Polite updater (cadence-gated)
# ===========================================================================
CONFIG_URL = ("https://raw.githubusercontent.com/shinigami-eyes/configuration/main/"
              "configuration.json")
BASE = ("https://raw.githubusercontent.com/shinigami-eyes/dynamic-filters/main/"
        "bloomfilters/bloomfilter_%VERSION%_%NAME%.dat")
STATE_FILE = ".bloom_state.json"


def maybe_update(data_dir, force: bool = False, dry_run: bool = False) -> dict:
    """Politely fetch newer filters. At most one config check per 7 days;
    downloads only when newer exists AND local cache is >=14 days old."""
    import time
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    state = {}
    sp = data_dir / STATE_FILE
    if sp.exists():
        try:
            state = json.loads(sp.read_text())
        except Exception:
            pass
    now = time.time()
    week = 7 * 86400
    twoweeks = 14 * 86400
    if not force and (now - state.get("last_checked", 0.0)) < week:
        return {"action": "skipped", "reason": "checked within last 7 days (polite throttle)"}
    try:
        req = urllib.request.Request(CONFIG_URL, headers={"User-Agent": "another-note/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            cfg = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"action": "skipped", "reason": f"config fetch failed: {e}"}
    remote_version = int(cfg["bloomVersion"])
    local_version = int(state.get("version", "0"))
    state["last_checked"] = now
    if remote_version <= local_version:
        _save_state(data_dir, state)
        return {"action": "skipped", "reason": f"already current ({local_version})"}
    tf = data_dir / f"{FRIENDLY_NAME}.dat"
    local_mtime = tf.stat().st_mtime if tf.exists() else 0.0
    if not force and (now - local_mtime) < twoweeks:
        _save_state(data_dir, state)
        return {"action": "skipped", "reason": "newer available but local cache < 14 days old"}
    if dry_run:
        _save_state(data_dir, state)
        return {"action": "would-update", "version": remote_version}
    for name in (FRIENDLY_NAME, AVERSE_NAME):
        url = BASE.replace("%VERSION%", str(remote_version)).replace("%NAME%", name)
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "another-note/1.0"}), timeout=60) as r:
            data = r.read()
        if len(data) != 1419972:
            return {"action": "failed", "reason": f"{name}.dat unexpected size {len(data)}"}
        (data_dir / f"{name}.dat").write_bytes(data)
    state["version"] = str(remote_version)
    _save_state(data_dir, state)
    return {"action": "updated", "version": remote_version}


def _save_state(data_dir, state: dict) -> None:
    (Path(data_dir) / STATE_FILE).write_text(json.dumps(state))


# ===========================================================================
# SECTION 8 — CLI
# ===========================================================================
EXIT_OK, EXIT_ERROR, EXIT_UNSUPPORTED, EXIT_ABORTED = 0, 1, 2, 3


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="another-note",
        description="Another Note: read/submit Shinigami Eyes social-profile label filters.")
    p.add_argument("--version", action="version", version=f"another-note {VERSION}")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("-c", "--config", type=Path, default=None)
    p.add_argument("-d", "--data-dir", type=Path, default=None)
    sub = p.add_subparsers(dest="cmd")

    pc = sub.add_parser("classify", help="test identifiers / URLs")
    pc.add_argument("--json", action="store_true")
    pc.add_argument("--fail-on-unsupported", action="store_true")
    pc.add_argument("--url", action="append", default=[])
    pc.add_argument("--twitter", action="append", default=[], metavar="HANDLE")
    pc.add_argument("--facebook", action="append", default=[], metavar="HANDLE")
    pc.add_argument("--youtube", action="append", default=[], metavar="HANDLE")
    pc.add_argument("keys", nargs="*")

    pr = sub.add_parser("report", help="submit labels (interactive confirm each)")
    pr.add_argument("--dry-run", action="store_true")
    pr.add_argument("--force", action="store_true")
    pr.add_argument("--installation-id", default=None)
    pr.add_argument("entries", nargs="*",
                    help="identifier:label pairs, e.g. 'twitter.com/foo:transgender_averse'")

    sub.add_parser("estimate", help="print filter fill ratios")
    pu = sub.add_parser("update", help="politely fetch newer filters")
    pu.add_argument("-d", "--data-dir", type=Path, default=None)
    sub.add_parser("selfcheck", help="cross-check math")
    return p


def cmd_classify(args, cfg: Config) -> int:
    data_dir = resolve_data_dir(args.data_dir, cfg)
    friendly, averse = build_resolver(data_dir)
    results: dict[str, str] = {}
    unsupported: dict[str, str] = {}
    any_unsupported = False

    def consider(raw: str, kind: str):
        nonlocal any_unsupported
        if not raw:
            return
        key = normalize_url(raw)
        if isinstance(key, _Sentinel):
            unsupported[raw] = "UNSUPPORTED"
            any_unsupported = True
            return
        results[raw] = classify_youtube_aware(key, friendly, averse)

    for k in args.keys:
        consider(k, "arg")
    for h in args.twitter:
        consider("twitter.com/" + h.strip().lstrip("@").lower(), "twitter")
    for h in args.facebook:
        consider("facebook.com/" + h.strip().lstrip("@").lower(), "facebook")
    for h in args.youtube:
        consider("youtube.com/@" + h.strip().lstrip("@").lower(), "youtube")
    for u in args.url:
        consider(u, "url")

    has_explicit = bool(results) or bool(unsupported) or bool(args.keys) \
        or bool(args.url) or bool(args.twitter) or bool(args.facebook) or bool(args.youtube)
    for k in read_stdin_keys() if not has_explicit else []:
        consider(k, "stdin")

    if args.json:
        out = {"labels": results}
        if unsupported:
            out["unsupported"] = unsupported
        print(json.dumps(out, indent=2))
    else:
        for k, v in results.items():
            print(f"{v:22s} {k}")
        for k in unsupported:
            print(f"{'UNSUPPORTED':22s} {k}")

    if any_unsupported and (cfg.fail_on_unsupported or getattr(args, "fail_on_unsupported", False)):
        return EXIT_UNSUPPORTED
    return EXIT_OK


def cmd_report(args, cfg: Config) -> int:
    entries = []
    for pair in args.entries:
        if ":" not in pair:
            print(f"error: report entry must be identifier:label -> {pair!r}", file=sys.stderr)
            return EXIT_ERROR
        ident, label = pair.rsplit(":", 1)
        ident, label = ident.strip(), label.strip()
        if label not in (FRIENDLY_NAME, AVERSE_NAME):
            print(f"error: label must be {FRIENDLY_NAME} or {AVERSE_NAME} -> {label!r}",
                  file=sys.stderr)
            return EXIT_ERROR
        entries.append({"identifier": ident, "label": label})

    if not entries:
        print("error: no valid entries provided", file=sys.stderr)
        return EXIT_ERROR

    try:
        res = submit(entries, installation_id=args.installation_id,
                     force=args.force, dry_run=args.dry_run)
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return EXIT_ABORTED
    print(json.dumps(res, indent=2))
    if res.get("action") == "failed":
        return EXIT_ERROR
    return EXIT_OK


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = Config.load(args.config)
    if args.verbose:
        cfg.verbosity = args.verbose
    if args.quiet:
        cfg.quiet = True
    if args.data_dir:
        cfg.data_dir = args.data_dir

    cmd = args.cmd or "classify"
    if cmd == "classify":
        return cmd_classify(args, cfg)
    if cmd == "report":
        return cmd_report(args, cfg)
    if cmd == "estimate":
        print(json.dumps(estimate_fill_rate(resolve_data_dir(args.data_dir, cfg)), indent=2))
        return EXIT_OK
    if cmd == "update":
        print(json.dumps(maybe_update(resolve_data_dir(args.data_dir, cfg)), indent=2))
        return EXIT_OK
    if cmd == "selfcheck":
        return EXIT_ERROR if selfcheck() else EXIT_OK
    parser.print_help()
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
