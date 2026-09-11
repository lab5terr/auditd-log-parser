#!/usr/bin/env python3
"""
auditd-log-parser -- parse Linux auditd logs and browse them as a sortable
terminal table: every record except login sessions, one row each.

Reads raw /var/log/audit/audit.log style files (not the ausearch-interpreted
format).  Correlates the SYSCALL / EXECVE / PROCTITLE / CWD / PATH records
that make up one audit event and shows one row per process execution --
including a non-execve syscall that a custom rule tagged with -k (a file
integrity watch on /etc/passwd, sudoers, cron, ...), shown as "type: watch".
Account/group changes, service start/stop, auditd's own rule changes
(CONFIG_CHANGE) and kernel-flagged anomalies (ANOM_*) are rows too. The `m`
key opens a checkbox menu to show/hide each of these row types; the `type`
column and its own filter substring both reflect the same six kinds: exec,
watch, account, service, config, anomaly.

User/group names come from the auditd ENRICHED fields when the log has them
(log_format = ENRICHED in auditd.conf), so names resolve even under sudo or on
a different host; otherwise the local passwd/group database is used.  A
systemd-nspawn container UID (vu-<machine>-0) is shown as "nspawn: <machine>".

Records that share a session id (ses) get the same faint background so a
session reads as one block.  Any row whose command looks potentially dangerous
(recursive rm, disk wipe, piping a download to a shell, disabling auditd/the
firewall, credential changes, ...) is flagged with a red highlight and a "!" in
the # column -- see classify_danger(); anomalies, failed account/group changes,
and anything touching audit or its own configuration (auditctl, /etc/audit,
a CONFIG_CHANGE row, the auditd/audit-rules services) are always flagged too.
A sudo/su/doas exec's own execve() always succeeds regardless of the password
that follows it, so a wrong password would otherwise look like a clean run --
the LAST same-pid USER_AUTH outcome is cross-referenced and, if it denies,
flags that row too and annotates its result as "success (auth failed)".
Each column header shows the key
that sorts it in brackets, e.g. "exe [3]".  Palette: --color auto|dark|light|off.

Login records (LOGIN / USER_LOGIN / USER_START / USER_END, plus USER_ACCT for the
source and USER_AUTH / USER_ERR for failures) build a session table -- who logged
in, from where -- shown in the "s" view (grouped by user+source) and in each
event's detail popup.  Failed authentications are collected and counted.  These
are the only records NOT shown in the main table.

Usage:
    auditd-log-parser.py [LOGFILE ...]          # open the TUI (default: /var/log/audit/audit.log)
    auditd-log-parser.py -f                     # follow the log, appending new events live
    auditd-log-parser.py --plain                # dump an aligned table to stdout and exit
    auditd-log-parser.py --plain --sort time -r # ... sorted, descending
    auditd-log-parser.py --plain --flagged      # only potentially-dangerous commands
    auditd-log-parser.py --color light          # TUI palette for a light terminal

TUI keys:
    up/down, PgUp/PgDn, Home/End   move the row cursor
    left/right                     scroll horizontally (also in detail/sessions views)
    1..9, 0, -, =, [               sort by that column (shown in brackets in its header; press again to reverse)
    /                              filter rows by substring (Esc clears)
    !                              toggle "show only sessions that contain a flagged command"
    m                              row-type menu: show/hide exec/watch/account/service/config/anomaly rows
    s                              sessions & auth-failures view
    Enter                          show the full record for the selected row
    f                              toggle live follow
    g                              re-seed parent info from /proc (live mode)
    q                              quit
"""

import argparse
import curses
import glob
import grp
import gzip
import locale
import os
import pwd
import re
import signal
import sys
import time
from datetime import datetime

# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

TYPE_RE = re.compile(r"\btype=(\S+)")
MSG_RE = re.compile(r"\bmsg=audit\((\d+(?:\.\d+)?):(\d+)\)")
FIELD_RE = re.compile(r'([^\s=]+)=("(?:[^"\\]|\\.)*"|\([^)]*\)|\S+)')
HEX_RE = re.compile(r"\A[0-9A-Fa-f]+\Z")
SPLIT_RE = re.compile(r"\):\s*")
# PAM-style records wrap their payload in msg='op=... acct="..." ...'
PAM_MSG_RE = re.compile(r"\bmsg='([^']*)'")

# auditd ENRICHED log format (auditd.conf: log_format = ENRICHED) appends the
# names it resolved on the originating host after a 0x1D separator, e.g.
#   ... uid=1000 gid=1000 ... \x1dUID="alice" GID="alice" AUID="alice" ...
INTERP_SEP = "\x1d"

# Records that can belong to an execve event.  auditd writes the records of
# concurrently-running events interleaved in the log, so events are correlated
# purely by their audit id (timestamp:serial), never by record adjacency.
EXEC_RECORD_TYPES = frozenset(("SYSCALL", "EXECVE", "CWD", "PROCTITLE", "PATH"))
EXECVE_SYSCALLS = frozenset(("59", "322", "11", "358", "221", "281"))
# Login / session / auth records -- each is self-contained (no multi-record
# assembly).  Different distros populate different ones: USER_LOGIN carries the
# source on some, USER_ACCT on others; USER_ERR / USER_AUTH hold the failures.
SESSION_RECORD_TYPES = frozenset((
    "LOGIN", "USER_LOGIN", "USER_START", "USER_END",
    "USER_ACCT", "USER_AUTH", "USER_ERR"))
# "System" records: not part of an execve or a login session, but still worth
# surfacing -- account/group changes made outside execve (e.g. via netlink),
# service lifecycle, auditd's own rule changes, and kernel-flagged anomalies.
ACCOUNT_RECORD_TYPES = frozenset((
    "USER_MGMT", "GRP_MGMT", "ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP",
    "CHGRP_ID", "CHUSER_ID", "USER_CHAUTHTOK"))
SERVICE_RECORD_TYPES = frozenset(("SERVICE_START", "SERVICE_STOP"))
ANOM_RECORD_TYPES = frozenset(("ANOM_PROMISCUOUS", "ANOM_LOGIN_FAILURES", "ANOM_ABEND"))
SYSTEM_RECORD_TYPES = (ACCOUNT_RECORD_TYPES | SERVICE_RECORD_TYPES | ANOM_RECORD_TYPES
                       | frozenset(("CONFIG_CHANGE",)))
SIGNAME = {1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 5: "SIGTRAP",
           6: "SIGABRT", 7: "SIGBUS", 8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV",
           13: "SIGPIPE", 24: "SIGXCPU", 25: "SIGXFSZ", 31: "SIGSYS"}
UNSET_UID = "4294967295"          # auid/ses "not set" sentinel
ESCALATION_TOOLS = frozenset(("sudo", "su", "sudo-rs", "doas"))
# How many still-open events to keep buffered before flushing the oldest.
# The interleave window in practice is a handful of events; this is generous.
PENDING_LAG = 500

ENRICHED_KEY = {
    "uid": "UID", "auid": "AUID", "euid": "EUID", "suid": "SUID", "fsuid": "FSUID",
    "gid": "GID", "egid": "EGID", "sgid": "SGID", "fsgid": "FSGID",
}

ERRNO = {
    1: "EPERM", 2: "ENOENT", 5: "EIO", 8: "ENOEXEC", 9: "EBADF", 11: "EAGAIN",
    12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 20: "ENOTDIR", 21: "EISDIR",
    22: "EINVAL", 26: "ETXTBSY", 36: "ENAMETOOLONG", 40: "ELOOP",
}

_uid_cache = {}
_gid_cache = {}


def uid_name(uid):
    try:
        key = int(uid)
    except (TypeError, ValueError):
        return None
    if key == 0xFFFFFFFF:          # auid=4294967295 -> "unset"
        return "unset"
    if key not in _uid_cache:
        try:
            _uid_cache[key] = pwd.getpwuid(key).pw_name
        except (KeyError, OverflowError):
            _uid_cache[key] = None
    return _uid_cache[key]


def gid_name(gid):
    try:
        key = int(gid)
    except (TypeError, ValueError):
        return None
    if key not in _gid_cache:
        try:
            _gid_cache[key] = grp.getgrgid(key).gr_name
        except (KeyError, OverflowError):
            _gid_cache[key] = None
    return _gid_cache[key]


def id_label(fields, key, kind):
    """Render an id field as "1000 (alice)".

    The name is taken from the auditd ENRICHED field (resolved on the host that
    produced the log) when present, and falls back to a local passwd/group
    lookup otherwise -- useful when the script runs under sudo or on a box
    where the accounts differ.
    """
    raw = unq(fields.get(key, ""))
    if raw == "":
        return "", ""
    name = unq(fields.get(ENRICHED_KEY.get(key, ""), ""))
    if not name:
        name = uid_name(raw) if kind == "u" else gid_name(raw)
    if not name:
        return raw, ""
    return "%s (%s)" % (raw, name), name


def unq(val):
    if val and len(val) >= 2 and val[0] == '"' and val[-1] == '"':
        return val[1:-1]
    if val in ("(null)", "(none)", None):
        return ""
    return val


def audit_decode(raw, nul_to_space=True):
    """Decode an auditd string field: quoted literal or hex-encoded bytes."""
    if raw is None:
        return ""
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1]
    if raw in ("(null)", "(none)", ""):
        return ""
    if HEX_RE.match(raw) and len(raw) % 2 == 0:
        try:
            text = bytes.fromhex(raw).decode("utf-8", "replace")
        except ValueError:
            return raw
        if nul_to_space:
            text = text.replace("\x00", " ").strip()
        return text
    return raw


def parse_fields(blob):
    out = {}
    for match in FIELD_RE.finditer(blob):
        out[match.group(1)] = match.group(2)
    return out


def build_cmdline(execve_fields):
    """Reconstruct argv from an EXECVE record (handles a0, a1, ... and split a1[0])."""
    args = {}
    chunks = {}
    for key, val in execve_fields.items():
        m = re.fullmatch(r"a(\d+)", key)
        if m:
            args[int(m.group(1))] = audit_decode(val, nul_to_space=False)
            continue
        m = re.fullmatch(r"a(\d+)\[(\d+)\]", key)
        if m:
            chunks.setdefault(int(m.group(1)), {})[int(m.group(2))] = val
    for idx, parts in chunks.items():
        args[idx] = "".join(audit_decode(parts[j], nul_to_space=False)
                            for j in sorted(parts))
    return " ".join(args[i] for i in sorted(args))


def fmt_result(success, exit_code):
    try:
        code = int(exit_code)
    except (TypeError, ValueError):
        code = None

    def failed():
        if code is not None and code < 0:
            return "failed (%s)" % ERRNO.get(-code, str(code))
        return "failed"

    if success == "no":                       # the SYSCALL verdict wins
        return failed()
    if success == "yes":
        return "success"
    if code is not None:                       # no explicit verdict -> infer from exit
        return "success" if code >= 0 else failed()
    return "?"


def to_int(val, default=0):
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def fmt_time(ts, fmt="%Y-%m-%d %H:%M:%S"):
    try:
        return datetime.fromtimestamp(float(ts)).strftime(fmt)
    except (OverflowError, OSError, ValueError, TypeError):
        return "?"


def clean_val(val):
    """unquote a field and normalise auditd's placeholders to ''."""
    val = unq(val or "")
    return "" if val in ("?", "unset", "none", "(none)", "(null)", "(unknown)") else val


def field_str(val):
    """clean_val, but also hex-decode -- auditd hex-encodes e.g. acct when it
    holds "(invalid user)" or a name with spaces."""
    return clean_val(audit_decode(val, nul_to_space=True))


def parse_ses(raw):
    """(num, display) for a ses field: a real int, or (-1, '-') when unset/bad."""
    raw = unq(raw or "")
    if raw.isdigit() and raw != UNSET_UID:
        return int(raw), raw
    return -1, "-"


# systemd names UIDs owned by an nspawn machine (PrivateUsers=) "vu-<machine>-<n>";
# the range base is uid = K*65536 (offset 0 = the container's root).
_NSPAWN_RE = re.compile(r"\bvu-([a-z][\w.-]*?)-(\d+)\b")
NSPAWN_STRIDE = 65536


def denspawn(text):
    """vu-pi-hole-0 -> 'nspawn: pi-hole' (offset 0 = root; else 'nspawn: pi-hole+N')."""
    return _NSPAWN_RE.sub(
        lambda m: "nspawn: " + m.group(1) + ("" if m.group(2) == "0"
                                             else "+" + m.group(2)),
        text or "")


def label_uid(num, name):
    """Human uid label; recognises systemd-nspawn container UIDs even w/o a name."""
    name = denspawn(name)
    if name:
        return "%s (%s)" % (num, name) if num >= 0 else name
    if num > NSPAWN_STRIDE and num % NSPAWN_STRIDE == 0:
        return "%s (nspawn container)" % num
    return str(num) if num >= 0 else "?"


def session_source(s):
    """The 'from' field: 'addr', 'addr (host)', 'host', or '-'."""
    addr, host = s.get("addr"), s.get("host")
    if addr and host and host.split("%")[0] != addr:   # "%zone" on link-local v6
        return "%s (%s)" % (addr, host)
    return addr or host or "-"


def session_summary(s):
    """One line: 'alice  10.0.0.5 (host)  pts/3  09:12:44 - 09:41:03'."""
    out = [denspawn(s.get("user")) or "?"]
    src = session_source(s)
    if src != "-":
        out.append(src)
    if s.get("tty"):
        out.append(s["tty"])
    span = fmt_time(s.get("start"))
    end = s.get("end")
    if end and end > s.get("start", end):
        span += " - " + fmt_time(end, "%H:%M:%S")
    out.append(span)
    if not s.get("ok", True):
        out.append("[login failed]")
    return "  ".join(out)


def describe_anomaly(rec_type, f):
    """Human summary of an ANOM_* record's payload."""
    if rec_type == "ANOM_PROMISCUOUS":
        dev = clean_val(f.get("dev")) or "?"
        state = "enabled" if to_int(f.get("prom")) else "disabled"
        return "%s: promiscuous mode %s" % (dev, state)
    if rec_type == "ANOM_ABEND":
        comm = field_str(f.get("comm")) or "?"
        exe = field_str(f.get("exe"))
        signame = SIGNAME.get(to_int(f.get("sig")), "signal %s" % clean_val(f.get("sig")))
        return "%s%s crashed: %s" % (comm, " (%s)" % exe if exe else "", signame)
    if rec_type == "ANOM_LOGIN_FAILURES":
        return "account locked: %s" % (clean_val(f.get("op")) or "?")
    return rec_type


def render_table(headers, rows, indent="  ", gap="  "):
    """Aligned monospace lines (header, rule, rows) with auto-fitted columns.

    Each column is only as wide as its own longest cell, so a lone IPv6
    address widens that one column instead of shifting the whole table.
    """
    def clean(c):
        return str(c).replace("\t", " ").replace("\n", " ")

    grid = [[clean(c) for c in r] for r in rows]
    n = len(headers)
    width = [len(str(headers[i])) for i in range(n)]
    for r in grid:
        for i in range(n):
            width[i] = max(width[i], len(r[i]))

    def fmt(cells):
        return (indent + gap.join(str(cells[i]).ljust(width[i])
                                  for i in range(n))).rstrip()

    return [fmt(headers), indent + gap.join("-" * w for w in width)] + \
           [fmt(r) for r in grid]


# --------------------------------------------------------------------------- #
# "Potentially dangerous command" heuristics
# --------------------------------------------------------------------------- #

# Executables that are inherently sensitive -- matched on the exe basename so
# "getent passwd" or "grep useradd ..." are not mistaken for the real command.
_DANGER_EXE = {
    "shred": "secure file wipe", "wipefs": "disk signature wipe",
    "blkdiscard": "disk discard", "useradd": "user/group change",
    "userdel": "user/group change", "usermod": "user/group change",
    "groupadd": "user/group change", "groupdel": "user/group change",
    "passwd": "password change", "chpasswd": "password change",
    "visudo": "sudoers change", "setenforce": "SELinux mode change",
    "insmod": "kernel module insert", "auditctl": "audit config change",
}
# A command name appearing in command position inside a shell one-liner
# (start, after ; | && sudo xargs, or after `-c`).
_CMD_POS = r"(?:^|[;|&]\s*|\b(?:sudo|xargs|env)\s+|(?<!\S)-c\s+)"
_DANGER_RULES = (
    (_CMD_POS + r"rm\s+(?:-\S+\s+)*(?:-[a-zA-Z]*r|--recursive\b)", "recursive rm"),
    (_CMD_POS + r"(?:useradd|userdel|usermod|groupadd|passwd|chpasswd)\b", "account/password change"),
    (_CMD_POS + r"mkfs(?:\.\w+)?\s",                     "filesystem format"),
    (r"\bdd\s[^|;&]*\bof=/dev/(?:sd|nvme|vd|hd|mmcblk)", "dd to raw disk"),
    (r">\s*/dev/(?:sd|nvme|vd|hd)[a-z]",                 "redirect to raw disk"),
    (r"\bchmod\s+(?:\S+\s+)*[0-7]?777(?:\s|$)",          "chmod 777"),
    (r"\bchmod\s+(?:-[a-zA-Z]+\s+)*(?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)\b", "recursive chmod"),
    (r"\bchown\s+(?:-[a-zA-Z]+\s+)*(?:-[a-zA-Z]*R[a-zA-Z]*|--recursive)\b", "recursive chown"),
    (r"\bchattr\s+[+-][a-zA-Z]*[aiu]",                   "chattr immutable/append"),
    (r"(?:curl|wget|fetch)\s[^|]*\|\s*(?:sudo\s+)?"
     r"(?:sh|bash|zsh|python[0-9.]*|perl|ruby)(?:\s|$)", "pipe download to interpreter"),
    (r"\b(?:base64|xxd|openssl enc)\b[^|]*\|\s*(?:sh|bash)(?:\s|$)", "decode then execute"),
    (r"\beval\s[^|]*\$\(\s*(?:curl|wget)\b",             "eval of downloaded content"),
    (r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",  "fork bomb"),
    (r"/dev/(?:tcp|udp)/[\w.\-]+/\d+",                   "shell network socket"),
    (r"\b(?:nc|ncat|netcat)\s[^|;]*\s-[a-zA-Z]*e[a-zA-Z]*\s", "netcat with -e"),
    (r"/etc/sudoers\b",                                  "sudoers change"),
    (r"/etc/(?:shadow|gshadow)\b",                       "credential file access"),
    (r"\bauthorized_keys\b",                             "authorized_keys change"),
    (r"\bsetenforce\s+0\b|\bselinux=0\b|\benforcing=0\b", "SELinux disabled"),
    (r"\b(?:iptables|ip6tables)\s[^|;]*?(?:-F\b|--flush\b)|\bnft\s+flush\b", "firewall flush"),
    (r"\bufw\s+disable\b",                               "firewall disabled"),
    (r"\bsystemctl\s+(?:stop|disable|mask)\s+\S*"
     r"(?:auditd|apparmor|firewall|fail2ban)",           "security service disabled"),
    (r"\bauditctl\s+-e\s*0\b|\bpkill\s+\S*auditd\b|\bservice\s+auditd\s+stop\b", "auditd disabled"),
    (r"\bauditctl\b",                                    "audit config change"),
    (r"/etc/audit\b",                                    "audit config file touched"),
    (r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|>\s*\S*\.bash_history\b", "shell history cleared"),
    (r"(?:>|truncate\s[^;|]*|rm\s[^;|]*)\s*/var/log/",   "log files wiped"),
    (r"\bdmesg\s+(?:-[a-zA-Z]*[cC]\b|--clear\b)",        "kernel ring buffer cleared"),
    (r"\bkill(?:all)?\s+-[a-zA-Z0-9]*9[a-zA-Z0-9]*\s+-1\b", "kill all processes"),
    (r"\bcrontab\s+-r\b",                                "crontab removed"),
    (r"\bsudo\s+(?:-i|-s|su|bash|sh)(?:\s|$)|\bsudo\s+-u\s+root\s+(?:sh|bash)\b", "root shell via sudo"),
)
_DANGER_RX = tuple((re.compile(p), label) for p, label in _DANGER_RULES)
_WWDIR = ("/tmp/", "/dev/shm/", "/var/tmp/")


def classify_danger(exe, cmd):
    """Return a list of reasons the command looks potentially dangerous."""
    text = "%s %s" % (cmd or "", exe or "")
    seen = []

    base = os.path.basename(exe or "")
    label = _DANGER_EXE.get(base)
    if label is None and base.startswith("mkfs"):
        label = "filesystem format"
    if label:
        seen.append(label)

    for rx, lab in _DANGER_RX:
        if lab not in seen and rx.search(text):
            seen.append(lab)

    if (exe or "").startswith(_WWDIR):
        seen.append("binary in world-writable dir")
    return seen


class Event:
    """One row of the main table -- an execve, a watched syscall, or a
    synthesized row for an account/service/config/anomaly record. `kind`
    says which, and drives the type-filter menu and the `type` column."""

    __slots__ = ("idx", "ts", "time_s", "exe", "cmd", "key", "ses_num", "ses_s",
                 "pid", "ppid", "uid_num", "uid_s", "uid_name",
                 "pcomm", "pexe", "result", "danger", "detail", "raw", "blob", "kind")

    def __init__(self, idx, ts, *, exe="", cmd="", key="-", ses_num=-1, ses_s="-",
                pid=0, ppid=0, uid_num=-1, uid_name="", pcomm="", pexe="",
                result="-", detail=None, raw=None, kind="exec"):
        self.idx = idx
        self.ts = ts
        self.time_s = fmt_time(ts)

        self.exe = exe
        self.cmd = cmd
        self.key = key or "-"
        self.ses_num, self.ses_s = ses_num, ses_s

        self.pid = pid
        self.ppid = ppid

        self.uid_num = uid_num
        self.uid_name = denspawn(uid_name)
        self.uid_s = label_uid(uid_num, self.uid_name)

        self.pcomm, self.pexe = pcomm, pexe
        self.result = result
        self.danger = classify_danger(exe, cmd)

        self.detail = detail if detail is not None else {}
        self.raw = raw if raw is not None else []
        self.kind = kind
        self.blob = " ".join((
            self.time_s, self.kind, self.exe, self.cmd, self.key, self.ses_s,
            str(self.pid), str(self.ppid), self.uid_s,
            self.pcomm, self.pexe, self.result,
            ("danger " + " ".join(self.danger)) if self.danger else "",
        )).lower()


class Builder:
    __slots__ = ("ts", "types", "fields", "raw", "last")

    def __init__(self, ts):
        self.ts = ts
        self.types = set()
        self.fields = {}
        self.raw = []
        self.last = time.time()

    def add(self, rec_type, fields, raw):
        self.types.add(rec_type)
        self.fields.setdefault(rec_type, {}).update(fields)
        self.raw.append(raw)


class Model:
    """Accumulates audit records and exposes the list of execution events."""

    def __init__(self):
        self.events = []
        self.pending = {}          # event-key -> Builder, in arrival order
        self.proc_map = {}         # pid -> (comm, exe)
        self.sessions = []         # session dicts, in creation order
        self._open_ses = {}        # ses id -> the currently-open session dict
        self._acct_hint = {}       # pid -> (ts, addr, host, tty) from a recent USER_ACCT
        self._last_reject = {}     # addr -> ts of the last real auth rejection
        self.auth_failures = []    # rejected/failed auth: USER_LOGIN/AUTH/ACCT/ERR
        self._pam_last = {}        # pid -> (ts, ok) of the LAST USER_AUTH seen

    # -- ingestion --------------------------------------------------------- #

    @staticmethod
    def _record_fields(line):
        tail = SPLIT_RE.split(line, maxsplit=1)
        body = tail[1] if len(tail) > 1 else line
        fields = {}
        for chunk in body.split(INTERP_SEP):   # original + ENRICHED name fields
            fields.update(parse_fields(chunk))
        pam = PAM_MSG_RE.search(body)
        if pam:                                # unpack msg='op=... acct="..." ...'
            fields.update(parse_fields(pam.group(1)))
        return fields

    def feed(self, line):
        rec_type = TYPE_RE.search(line)
        rec_type = rec_type.group(1) if rec_type else "?"
        if rec_type in SESSION_RECORD_TYPES:
            self._session_record(rec_type, line)
            return
        if rec_type in SYSTEM_RECORD_TYPES:
            self._system_record(rec_type, line)
            return
        if rec_type not in EXEC_RECORD_TYPES:
            return
        msg = MSG_RE.search(line)
        if not msg:
            return
        # Full audit id "<epoch>:<serial>" -- the serial alone repeats after an
        # auditd restart / reboot, which would merge unrelated events.
        key = msg.group(1) + ":" + msg.group(2)
        ts = float(msg.group(1))
        fields = self._record_fields(line)

        builder = self.pending.get(key)
        if builder is None:
            builder = Builder(ts)
            self.pending[key] = builder
        builder.last = time.time()
        builder.add(rec_type, fields, line.rstrip("\n"))

        while len(self.pending) > PENDING_LAG:
            oldest = next(iter(self.pending))
            self._finalize(self.pending.pop(oldest))

    def _session(self, ses_num, ts, is_login=False):
        """Return the open session dict for ses_num, creating one if needed.

        Session ids are reused after a reboot (like serials).  A *login* record
        (LOGIN / USER_LOGIN) for a ses whose open instance already looks
        finished -- it carries a login, an explicit end, or a start more than an
        hour old -- starts a fresh instance.  Non-login records (USER_START from
        su/sudo mid-session) always attach to the open instance.
        """
        s = self._open_ses.get(ses_num)
        if s is not None and is_login and (
                s.get("login") or "end" in s or ts - s.get("start", ts) > 3600):
            s = None
        if s is None:
            s = {"ses": ses_num, "start": ts}
            self.sessions.append(s)
            self._open_ses[ses_num] = s
        return s

    def session_for(self, ses_num, ts):
        """The session instance that was open at time ts (for the detail popup)."""
        best = None
        for s in self.sessions:
            if s["ses"] == ses_num and s.get("start", ts) <= ts + 1:
                best = s
        return best

    def _apply_acct_hint(self, s, pid, ts):
        """Pull source (addr/host/tty/via) buffered from a same-pid USER_ACCT."""
        hint = self._acct_hint.get(pid)
        if hint and 0 <= ts - hint[0] < 60:
            _, addr, host, tty, via = hint
            if addr:
                s.setdefault("addr", addr)
            if host:
                s.setdefault("host", host)
            if tty:
                s.setdefault("tty", tty)
            if via:
                s.setdefault("via", via)
            self._acct_hint.pop(pid, None)

    def _session_record(self, rec_type, line):
        msg = MSG_RE.search(line)
        if not msg:
            return
        ts = float(msg.group(1))
        f = self._record_fields(line)
        res = unq(f.get("res", ""))
        acct = field_str(f.get("acct"))
        addr = clean_val(f.get("addr"))
        host = field_str(f.get("hostname"))
        term = field_str(f.get("terminal"))
        tool = os.path.basename(clean_val(f.get("exe")))
        pid = to_int(f.get("pid"), -1)

        def fail(reason, trailing=False):
            if trailing:                        # bad_ident etc. -- the tail of a
                last = self._last_reject.get(addr)   # rejection already logged
                if addr and last is not None and 0 <= ts - last < 10:
                    return
            elif addr:
                self._last_reject[addr] = ts
                if len(self._last_reject) > 2048:
                    self._last_reject = {a: t for a, t in self._last_reject.items()
                                         if 0 <= ts - t < 30}
            self.auth_failures.append({
                "ts": ts, "reason": reason, "acct": acct or "-",
                "addr": addr, "host": host, "pid": pid,
                "via": tool or term or "-"})

        if rec_type == "USER_ACCT":
            if addr or host:                   # remote source -- keep for the LOGIN
                self._acct_hint[pid] = (ts, addr, host, term, tool)
                if len(self._acct_hint) > 256:  # drop hints no LOGIN ever claimed
                    self._acct_hint = {p: h for p, h in self._acct_hint.items()
                                       if 0 <= ts - h[0] < 120}
            if res in ("failed", "0"):
                fail("account denied")
            return
        if rec_type == "USER_AUTH":
            # last outcome wins -- a process (pid) that fails once and then
            # succeeds on retry must not be remembered as "failed" (see
            # _mark_failed_escalations, which only cares about the final one)
            self._pam_last[pid] = (ts, res != "failed")
            if len(self._pam_last) > 512:   # pids get reused; stale entries
                self._pam_last = {p: v for p, v in self._pam_last.items()
                                  if 0 <= ts - v[0] < 120}
            if res == "failed":
                fail("auth failed")
            return
        if rec_type == "USER_ERR":
            # bad_ident etc. usually follow a rejected login from the same host
            fail(clean_val(f.get("op")).replace("PAM:", "") or "error", trailing=True)
            return
        if rec_type == "USER_LOGIN" and res == "failed":
            fail("login rejected")
            return

        ses, _ = parse_ses(f.get("ses"))
        if ses < 0:
            return

        if rec_type == "LOGIN":
            s = self._session(ses, ts, is_login=True)
            self._apply_acct_hint(s, pid, ts)
            auid = unq(f.get("auid", ""))
            name = unq(f.get("AUID", "")) or uid_name(auid) or ""
            s["user"] = denspawn(name) or label_uid(to_int(auid, -1), "")
            tty = clean_val(f.get("tty"))
            if tty:
                s.setdefault("tty", tty)
                s["interactive"] = True             # a real tty -> not a service session
            s["ok"] = f.get("res") != "0"
        elif rec_type == "USER_LOGIN":
            s = self._session(ses, ts, is_login=True)
            s["login"] = True                       # a credential-checked login
            self._apply_acct_hint(s, pid, ts)
            if acct:
                s.setdefault("user", denspawn(acct))
            if addr:
                s["addr"] = addr
            if host:
                s["host"] = host
            if term:
                s.setdefault("tty", term)
            if tool:
                s.setdefault("via", tool)
        elif rec_type == "USER_START":
            s = self._session(ses, ts)
            self._apply_acct_hint(s, pid, ts)
        elif rec_type == "USER_END":
            if tool in ESCALATION_TOOLS:
                return                              # a sudo/su session closing
            s = self._open_ses.pop(ses, None)
            if s is not None:
                s["end"] = ts

    def _system_record(self, rec_type, line):
        """Turn an account/service/config/anomaly record into a row of the
        main table, right alongside execve/watch events (everything except
        login sessions, which stay in the 's' view)."""
        msg = MSG_RE.search(line)
        if not msg:
            return
        ts = float(msg.group(1))
        f = self._record_fields(line)
        res = unq(f.get("res", "")) or "-"
        actor = denspawn(unq(f.get("AUID", "")) or uid_name(f.get("auid")) or "-")
        ses_num, ses_s = parse_ses(f.get("ses"))
        pid = to_int(f.get("pid"), 0)
        raw = [line.rstrip("\n")]

        def emit(kind, exe, cmd, result, extra_danger=None):
            ev = Event(len(self.events) + 1, ts, exe=exe, cmd=cmd, key="-",
                      ses_num=ses_num, ses_s=ses_s, pid=pid, ppid=0,
                      uid_num=-1, uid_name=actor, result=result,
                      detail=f, raw=raw, kind=kind)
            if extra_danger:
                ev.danger = (ev.danger + [extra_danger]) if ev.danger else [extra_danger]
            self.events.append(ev)

        if rec_type in ACCOUNT_RECORD_TYPES:
            op = clean_val(f.get("op")) or rec_type.lower()
            target = clean_val(f.get("id")) or field_str(f.get("acct")) or "-"
            tool = os.path.basename(field_str(f.get("exe"))) or "-"
            emit("account", tool, "%s %s" % (op, target), res,
                 None if res == "success" else "failed account/group change")
        elif rec_type in SERVICE_RECORD_TYPES:
            unit = field_str(f.get("unit")) or "-"
            action = "started" if rec_type == "SERVICE_START" else "stopped"
            emit("service", "-", "%s %s" % (unit, action), res,
                 "audit service" if "audit" in unit.lower() else None)
        elif rec_type == "CONFIG_CHANGE":
            op = clean_val(f.get("op")) or "?"
            if op in ("add_rule", "remove_rule"):
                detail = clean_val(f.get("key")) or "(no key)"
            else:
                # e.g. "op=set audit_pid=1157 old=0" -- the changed field's name
                # varies (audit_pid, audit_backlog_limit, audit_failure, ...).
                changed = next((k for k in f if k not in
                               ("op", "old", "auid", "ses", "res") and k[:1].islower()),
                              None)
                detail = ("%s: %s -> %s" % (changed, clean_val(f.get("old", "?")),
                                            clean_val(f.get(changed)))
                          if changed else "-")
            result = "success" if res == "1" else "failed" if res == "0" else res
            # CONFIG_CHANGE *is* auditd's own configuration changing -- always
            # flag it, same as classify_danger() flags running auditctl itself.
            emit("config", "-", "%s: %s" % (op, detail), result, "audit config change")
        elif rec_type in ANOM_RECORD_TYPES:
            result = "success" if res == "1" else "failed" if res == "0" else res
            emit("anomaly", "-", describe_anomaly(rec_type, f), result, "anomaly")

    def flush_all(self):
        for key in list(self.pending):
            self._finalize(self.pending.pop(key))
        self._renumber()
        self._mark_failed_escalations()

    def flush_stale(self, age=2.0):
        now = time.time()
        for key, builder in list(self.pending.items()):
            if now - builder.last > age:
                self._finalize(self.pending.pop(key))
        self._renumber()
        self._mark_failed_escalations()

    def _mark_failed_escalations(self):
        """sudo/su/doas's own execve() succeeds no matter what password it
        then asks for and gets -- so a plain 'success' row for `sudo cmd` can
        look like the privileged action went through even when the password
        was wrong and it never did. Cross-reference by pid (the same process
        performs both the exec and, right after, its own PAM check) using the
        LAST USER_AUTH outcome for that pid, not just "was there ever a
        failure" -- sudo retries on a typo, and a failed-then-succeeded retry
        must not be reported as denied when the command actually ran.

        Reversible, not just additive: in --follow this runs (via
        flush_stale) before a retry's later success has necessarily arrived,
        so a row flagged on incomplete information must be un-flagged once
        that success shows up, rather than staying stuck. The "result" column
        text itself is left untouched here (see _result_display) so there is
        nothing to restore when un-flagging.
        """
        for e in self.events:
            if e.kind != "exec" or os.path.basename(e.exe) not in ESCALATION_TOOLS:
                continue
            outcome = self._pam_last.get(e.pid)
            should_flag = bool(outcome) and not outcome[1] and 0 <= outcome[0] - e.ts < 30
            flagged = "authentication failed" in e.danger
            if should_flag and not flagged:
                e.danger.append("authentication failed")
            elif flagged and not should_flag:
                e.danger.remove("authentication failed")

    def _renumber(self):
        """Keep # (arrival order) aligned with real timestamps. Account/service/
        config/anomaly rows are created the instant their one line is read, but
        an execve event's builder is only finalized once its records are all
        in (at flush time) -- without re-sorting, every such row would end up
        clustered before or after every execve row instead of interleaved."""
        self.events.sort(key=lambda e: e.ts)
        for i, e in enumerate(self.events):
            e.idx = i + 1

    def _finalize(self, builder):
        # A real execve event carries both SYSCALL and EXECVE records; require
        # SYSCALL so a partial fragment never yields a row with empty pid/uid.
        if "SYSCALL" not in builder.types:
            return
        sysf = builder.fields.get("SYSCALL", {})
        is_execve = ("EXECVE" in builder.types
                    or unq(sysf.get("syscall", "")) in EXECVE_SYSCALLS)
        # Not an execve, but explicitly tagged by one of the user's own audit
        # rules (-k identity/sudoers/cron/...) -- e.g. a file-integrity watch
        # on /etc/passwd or /etc/audit/. Untagged non-execve syscalls (which
        # would otherwise flood the table with incidental noise) are dropped.
        has_key = clean_val(sysf.get("key")) != ""
        if not is_execve and not has_key:
            return

        exf = builder.fields.get("EXECVE", {})
        ptf = builder.fields.get("PROCTITLE", {})

        exe = unq(sysf.get("exe", ""))
        cmd = build_cmdline(exf)
        if not cmd and ptf:
            cmd = audit_decode(ptf.get("proctitle", ""))
        if not exe:
            exe = cmd.split(" ", 1)[0] if cmd else unq(sysf.get("comm", ""))
        if not cmd:
            cmd = unq(sysf.get("comm", ""))

        key = unq(sysf.get("key", "")).replace("\x01", ", ")   # audit rule key(s)
        ses_num, ses_s = parse_ses(sysf.get("ses"))
        pid = to_int(sysf.get("pid"))
        ppid = to_int(sysf.get("ppid"))
        uid_num = to_int(unq(sysf.get("uid", "")), default=-1)
        _, uid_name = id_label(sysf, "uid", "u")
        parent = self.proc_map.get(ppid)
        pcomm, pexe = parent if parent else ("", "")
        result = fmt_result(sysf.get("success"), sysf.get("exit"))

        event = Event(len(self.events) + 1, builder.ts,
                     exe=exe, cmd=cmd, key=key or "-", ses_num=ses_num, ses_s=ses_s,
                     pid=pid, ppid=ppid, uid_num=uid_num, uid_name=uid_name,
                     pcomm=pcomm, pexe=pexe, result=result,
                     detail=builder.fields, raw=builder.raw,
                     kind="exec" if is_execve else "watch")
        self.events.append(event)

        comm = unq(sysf.get("comm", "")) or os.path.basename(event.exe)
        if pid:
            self.proc_map[pid] = (comm, event.exe)

    # -- parent seeding --------------------------------------------------- #

    def seed_from_proc(self):
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            comm = exe = ""
            try:
                with open("/proc/%s/comm" % entry) as fh:
                    comm = fh.read().strip()
            except OSError:
                pass
            try:
                exe = os.readlink("/proc/%s/exe" % entry)
            except OSError:
                pass
            if comm or exe:
                self.proc_map[int(entry)] = (comm, exe)


# --------------------------------------------------------------------------- #
# Input files
# --------------------------------------------------------------------------- #

def _rotation_key(path):
    m = re.search(r"\.(\d+)(?:\.gz)?$", path)
    return (0, -int(m.group(1))) if m else (1, 0)


def resolve_paths(patterns):
    result = []
    for pattern in patterns:
        if pattern == "-":
            result.append("-")
            continue
        hits = sorted(glob.glob(pattern), key=_rotation_key)
        if hits:
            result.extend(hits)
        elif os.path.exists(pattern):
            result.append(pattern)
        else:
            sys.stderr.write("auditd-log-parser.py: no match for %r\n" % pattern)
    return result


def load_files(model, paths):
    for path in paths:
        if path == "-":
            for line in sys.stdin:
                model.feed(line)
        else:
            opener = gzip.open if path.endswith(".gz") else open
            try:
                with opener(path, "rt", errors="replace") as fh:
                    for line in fh:
                        model.feed(line)
            except OSError as exc:
                sys.stderr.write("auditd-log-parser.py: %s\n" % exc)
    model.flush_all()


class Follower:
    def __init__(self, model, path):
        self.model = model
        self.path = path
        self.buf = ""
        self.fh = None
        self.ino = None
        self.pos = 0
        self._open(seek_end=True)

    def close(self):
        if self.fh:
            try:
                self.fh.close()
            except OSError:
                pass
        self.fh = None

    def _open(self, seek_end=False):
        self.close()
        try:
            self.fh = open(self.path, "r", errors="replace")
        except OSError:
            self.fh = None
            return
        st = os.fstat(self.fh.fileno())
        self.ino = st.st_ino
        if seek_end:
            self.fh.seek(0, os.SEEK_END)
        self.pos = self.fh.tell()

    def poll(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return
        if self.fh is None or st.st_ino != self.ino or st.st_size < self.pos:
            self._open()
        if self.fh is None:
            return
        self.fh.seek(self.pos)
        data = self.fh.read()
        self.pos = self.fh.tell()
        if data:
            self.buf += data
            lines = self.buf.split("\n")
            self.buf = lines.pop()
            for line in lines:
                self.model.feed(line)
        self.model.flush_stale()


# --------------------------------------------------------------------------- #
# Columns
# --------------------------------------------------------------------------- #

def _result_display(e):
    """The 'result' column's text -- annotated for a sudo/su/doas exec whose
    own execve() succeeded but whose password check ultimately didn't (see
    Model._mark_failed_escalations). Kept out of Event.result itself so
    un-flagging (a later retry succeeds) has nothing to restore."""
    if e.kind == "exec" and "authentication failed" in e.danger:
        return e.result + " (auth failed)"
    return e.result


# (name, width, sort key char, sort key fn, display fn). The sort-key char is
# explicit (not positional) so inserting "type" doesn't renumber the others.
COLUMNS = [
    ("#",              8,  "1", lambda e: e.idx,
     lambda e: ("! " + str(e.idx)) if e.danger else str(e.idx)),
    ("type",           9,  "[", lambda e: e.kind,        lambda e: e.kind),
    ("time",           19, "2", lambda e: e.ts,           lambda e: e.time_s),
    ("exe",            30, "3", lambda e: e.exe.lower(),  lambda e: e.exe or "-"),
    ("commandline",    46, "4", lambda e: e.cmd.lower(),  lambda e: e.cmd or "-"),
    ("ses",            10, "5", lambda e: e.ses_num,      lambda e: e.ses_s),
    ("key",            18, "6", lambda e: e.key.lower(),  lambda e: e.key),
    ("result",         22, "7", lambda e: e.result,       _result_display),
    ("uid",            20, "8", lambda e: (e.uid_num, e.uid_name), lambda e: e.uid_s),
    ("parent command", 20, "9", lambda e: e.pcomm.lower(), lambda e: e.pcomm or "-"),
    ("parent exe",     28, "0", lambda e: e.pexe.lower(), lambda e: e.pexe or "-"),
    ("pid",            10, "-", lambda e: e.pid,          lambda e: str(e.pid)),
    ("ppid",           10, "=", lambda e: e.ppid,         lambda e: str(e.ppid)),
]
SEP = " | "
KEY_TO_COL = {c[2]: i for i, c in enumerate(COLUMNS)}
# semantic role of each column, for colouring
COL_ROLE = {
    "#": "meta", "type": "meta", "time": "meta", "exe": "main", "commandline": "main",
    "ses": "seskey", "key": "meta", "parent command": "meta",
    "parent exe": "meta", "pid": "meta", "ppid": "meta",
}


def cell(text, width):
    text = str(text).replace("\t", " ").replace("\n", " ")
    if len(text) > width:
        return text[: width - 1] + "…" if width > 1 else text[:width]
    return text.ljust(width)


def cell_role(name, event):
    if name == "result":
        r = event.result
        return "ok" if r == "success" else "bad" if r.startswith("failed") else "meta"
    if name == "uid":
        return "warn" if event.uid_num == 0 else "main"
    return COL_ROLE.get(name, "main")


def _service_cmd_cells(event, width):
    """Split a service row's padded 'unit action' text into two coloured
    pieces -- the unit name (accent) and the action (ok=started, dim=stopped)
    -- instead of one flat cell, so the two things that matter stand out."""
    padded = cell(event.cmd or "-", width)
    stripped = padded.rstrip()
    pad = padded[len(stripped):]
    unit, sep, action = stripped.rpartition(" ")
    if not sep:
        return [(padded, "main")]
    action_role = "ok" if action == "started" else "meta"
    return [(unit, "seskey"), (sep, "main"), (action, action_role), (pad, "main")]


def row_cells(event):
    """Yield (text, role) for every column and separator of one row."""
    last = len(COLUMNS) - 1
    for i, (name, w, _, _, disp) in enumerate(COLUMNS):
        if name == "commandline" and event.kind == "service":
            for piece in _service_cmd_cells(event, w):
                yield piece
        else:
            yield cell(disp(event), w), cell_role(name, event)
        if i != last:
            yield SEP, "sep"


def header_cells(sort_col, reverse):
    """Yield (text, active) for every column header, with its sort key in brackets."""
    last = len(COLUMNS) - 1
    for i, (name, w, sym, _, _) in enumerate(COLUMNS):
        label = "%s [%s]" % (name, sym)
        if i == sort_col:
            label += " v" if reverse else " ^"
        yield cell(label, w), i == sort_col
        if i != last:
            yield SEP, False


def total_width():
    return sum(w for _, w, _, _, _ in COLUMNS) + len(SEP) * (len(COLUMNS) - 1)


# --------------------------------------------------------------------------- #
# Plain (non-interactive) output
# --------------------------------------------------------------------------- #

def run_plain(model, sort_name, reverse, full, color="auto", flagged_only=False):
    events = list(model.events)
    if flagged_only:
        # ses_num == -1 means "no session" (systemd/kernel-owned rows mostly),
        # not one shared session -- expanding on it would sweep in every
        # unrelated sessionless row instead of just the actually-flagged ones.
        hot = {e.ses_num for e in events if e.danger and e.ses_num >= 0}
        events = [e for e in events if e.danger or e.ses_num in hot]
    if sort_name:
        idx = [c[0] for c in COLUMNS].index(sort_name)
        events.sort(key=COLUMNS[idx][3], reverse=reverse)

    use_color = (color != "off"
                 and os.environ.get("NO_COLOR") is None
                 and sys.stdout.isatty())

    widths = [w for _, w, _, _, _ in COLUMNS]
    if full:
        for i, (_, _, _, _, disp) in enumerate(COLUMNS):
            longest = max([len(disp(e)) for e in events] + [widths[i]])
            widths[i] = longest

    def line(cells):
        return SEP.join(c.ljust(widths[i]) if full else cell(c, widths[i])
                        for i, c in enumerate(cells))

    print(line([c[0] for c in COLUMNS]))
    print("-" * (sum(widths) + len(SEP) * (len(COLUMNS) - 1)))
    for e in events:
        text = line([disp(e) for _, _, _, _, disp in COLUMNS])
        if use_color and e.danger:
            text = "\033[1;31m%s\033[0m" % text
        print(text)
    flagged = sum(1 for e in events if e.danger)
    if flagged and not flagged_only:
        sys.stderr.write("auditd-log-parser.py: %d flagged (potentially dangerous) event(s)\n"
                         % flagged)
    if model.auth_failures:
        sys.stderr.write("auditd-log-parser.py: %d authentication failure(s) -- "
                         "open the TUI and press 's'\n" % len(model.auth_failures))
    if not events:
        sys.stderr.write("auditd-log-parser.py: no %sevents found\n"
                         % ("flagged " if flagged_only else "execve "))


# --------------------------------------------------------------------------- #
# TUI
# --------------------------------------------------------------------------- #

#   THEME["cell"][(role, v)]  -> attr for a data cell (v = session shade 0/1)
#   THEME["rowbg"][v]         -> attr for blank padding on a row
#   THEME["title|header|header_active|status|help|sel|danger|danger_sel"]
THEME = {}
_ROLES = ("main", "meta", "seskey", "ok", "bad", "warn")


def reset_theme():
    THEME.clear()
    THEME.update(
        title=curses.A_REVERSE, header=curses.A_UNDERLINE,
        header_active=curses.A_REVERSE | curses.A_BOLD,
        status=curses.A_REVERSE, help=curses.A_NORMAL,
        sel=curses.A_REVERSE, danger=curses.A_BOLD,
        danger_sel=curses.A_REVERSE | curses.A_BOLD,
        rowbg=[curses.A_NORMAL, curses.A_NORMAL],
        cell={},
    )
    mono = {"main": curses.A_NORMAL, "meta": curses.A_DIM,
            "seskey": curses.A_BOLD, "ok": curses.A_NORMAL,
            "bad": curses.A_BOLD, "warn": curses.A_BOLD}
    for role in _ROLES:
        for v in (0, 1):
            THEME["cell"][(role, v)] = mono[role]


reset_theme()


# calm, low-contrast palettes (xterm-256).  fg -1 = terminal default.
_PALETTE = {
    "dark": dict(main=-1, meta=245, seskey=110, ok=108, bad=174, warn=179,
                 shade=237, title=(252, 238), header=110, status=(250, 236),
                 sel=(231, 24), danger=(180, 52), danger_sel=(52, 180)),
    "light": dict(main=-1, meta=241, seskey=25, ok=29, bad=124, warn=130,
                  shade=254, title=(238, 253), header=25, status=(238, 252),
                  sel=(235, 152), danger=(88, 224), danger_sel=(224, 88)),
}


def init_theme(mode):
    """mode: 'auto' | 'dark' | 'light' | 'off'."""
    reset_theme()
    if mode == "off" or not curses.has_colors():
        return
    try:
        curses.start_color()
        curses.use_default_colors()
    except curses.error:
        return

    if mode == "auto":
        tail = os.environ.get("COLORFGBG", "").split(";")[-1].strip()
        mode = "light" if tail in ("7", "15") else "dark"

    if curses.COLORS < 256:
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_RED, -1)
        curses.init_pair(3, curses.COLOR_CYAN, -1)
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_CYAN)
        for v in (0, 1):
            THEME["cell"][("ok", v)] = curses.color_pair(1)
            THEME["cell"][("bad", v)] = curses.color_pair(2)
            THEME["cell"][("warn", v)] = curses.color_pair(2) | curses.A_BOLD
            THEME["cell"][("seskey", v)] = curses.color_pair(3) | curses.A_BOLD
        THEME.update(
            header=curses.color_pair(3) | curses.A_BOLD | curses.A_UNDERLINE,
            header_active=curses.color_pair(3) | curses.A_REVERSE | curses.A_BOLD,
            sel=curses.color_pair(4),
            danger=curses.color_pair(2) | curses.A_BOLD,
            danger_sel=curses.color_pair(2) | curses.A_REVERSE | curses.A_BOLD,
        )
        return

    p = _PALETTE[mode]
    bgs = (-1, p["shade"])
    pair = 1
    for role in _ROLES:
        for v, bg in enumerate(bgs):
            curses.init_pair(pair, p[role], bg)
            attr = curses.color_pair(pair)
            if role == "seskey":
                attr |= curses.A_BOLD
            THEME["cell"][(role, v)] = attr
            pair += 1
    curses.init_pair(pair, -1, bgs[0]); rb0 = curses.color_pair(pair); pair += 1
    curses.init_pair(pair, -1, bgs[1]); rb1 = curses.color_pair(pair); pair += 1
    curses.init_pair(pair, *p["title"]); c_title = curses.color_pair(pair); pair += 1
    curses.init_pair(pair, p["header"], -1); c_head = curses.color_pair(pair); pair += 1
    curses.init_pair(pair, *p["status"]); c_status = curses.color_pair(pair); pair += 1
    curses.init_pair(pair, *p["sel"]); c_sel = curses.color_pair(pair); pair += 1
    curses.init_pair(pair, *p["danger"]); c_dng = curses.color_pair(pair); pair += 1
    curses.init_pair(pair, *p["danger_sel"]); c_dngsel = curses.color_pair(pair); pair += 1
    THEME.update(
        title=c_title | curses.A_BOLD,
        header=c_head | curses.A_UNDERLINE,
        header_active=c_head | curses.A_BOLD | curses.A_UNDERLINE,
        status=c_status,
        help=THEME["cell"][("meta", 0)],
        sel=c_sel | curses.A_BOLD,
        danger=c_dng | curses.A_BOLD,
        danger_sel=c_dngsel | curses.A_BOLD,
        rowbg=[rb0, rb1],
    )


# Row kinds shown in the main table (everything auditd logs except login
# sessions/auth, which stay in the 's' view) and their menu labels.
KIND_LABELS = {
    "exec": "process executions (execve)",
    "watch": "file / rule-tagged syscalls (identity, cron, sudoers, ...)",
    "account": "account & group changes",
    "service": "service start / stop",
    "config": "auditd rule & parameter changes",
    "anomaly": "kernel-flagged anomalies",
}


class Tui:
    def __init__(self, model, follower):
        self.model = model
        self.follower = follower
        self.sort_col = 0
        self.reverse = True
        self.filt = ""
        self.only_flagged = False
        self.kinds = ("exec", "watch", "account", "service", "config", "anomaly")
        # service/config/anomaly default off -- a single boot can add hundreds
        # of them; the 'm' menu turns them back on when actually wanted.
        self.enabled_kinds = {"exec", "watch", "account"}
        self.top = 0
        self.cur = 0
        self.hoff = 0
        self.stick = True
        self.rows = []

    # -- data ----------------------------------------------------------- #

    def refresh_rows(self):
        rows = [e for e in self.model.events if e.kind in self.enabled_kinds]
        if self.only_flagged:
            # ses_num == -1 means "no session" (systemd/kernel-owned rows
            # mostly), not one shared session -- expanding on it would sweep
            # in every unrelated sessionless row, not just the flagged ones.
            hot = {e.ses_num for e in rows if e.danger and e.ses_num >= 0}
            rows = [e for e in rows if e.danger or e.ses_num in hot]
        if self.filt:
            needle = self.filt.lower()
            rows = [e for e in rows if needle in e.blob]
        rows = sorted(rows, key=COLUMNS[self.sort_col][3], reverse=self.reverse)
        self.rows = rows
        if self.stick and self.follower:
            # newest row sits at whichever end the current sort direction
            # puts it at (top when reversed, since idx descending -> newest first)
            self.cur = 0 if self.reverse else len(rows) - 1
        self.cur = max(0, min(self.cur, len(rows) - 1))

    # -- drawing ------------------------------------------------------- #

    def draw(self, scr):
        h, w = scr.getmaxyx()
        scr.erase()
        body = h - 4

        follow_tag = "  [FOLLOW]" if self.follower else ""
        flagged = sum(1 for e in self.rows if e.danger)
        flag_tag = "   !%d flagged" % flagged if flagged else ""
        nfail = len(self.model.auth_failures)
        fail_tag = "   %d auth failures (s)" % nfail if nfail else ""
        title = "auditd-log-parser  --  %d records%s%s%s" % (
            len(self.model.events), follow_tag, flag_tag, fail_tag)
        self._put(scr, 0, 0, title.ljust(w), THEME["title"])

        segs = [(t, (THEME["header_active"] if act else THEME["header"]))
                for t, act in header_cells(self.sort_col, self.reverse)]
        self._put_segments(scr, 1, w, segs, THEME["header"])

        if self.cur < self.top:
            self.top = self.cur
        elif self.cur >= self.top + body:
            self.top = self.cur - body + 1
        self.top = max(0, self.top)

        for i in range(body):
            ridx = self.top + i
            if ridx >= len(self.rows):
                break
            ev = self.rows[ridx]
            v = ev.ses_num & 1                       # session shade (same ses -> same bg)
            if ridx == self.cur:
                whole = THEME["danger_sel"] if ev.danger else THEME["sel"]
            elif ev.danger:
                whole = THEME["danger"]
            else:
                whole = None
            if whole is not None:
                segs = [(t, whole) for t, _ in row_cells(ev)]
                pad = whole
            else:
                segs = [(t, THEME["cell"][(role if role != "sep" else "meta", v)])
                        for t, role in row_cells(ev)]
                pad = THEME["rowbg"][v]
            self._put_segments(scr, 2 + i, w, segs, pad)

        sort_name = COLUMNS[self.sort_col][0]
        status = "sort: %s %s   rows: %d/%d" % (
            sort_name, "desc" if self.reverse else "asc",
            len(self.rows), len(self.model.events))
        if self.only_flagged:
            status += "   [FLAGGED SESSIONS]"
        if self.filt:
            status += "   filter: %r" % self.filt
        if self.enabled_kinds != set(self.kinds):
            status += "   types: %s" % (
                ",".join(k for k in self.kinds if k in self.enabled_kinds) or "(none)")
        self._put(scr, h - 2, 0, status.ljust(w), THEME["status"])

        keys = ("up/dn PgUp/PgDn Home/End | <-/-> scroll | 1-0 - = [ sort | / filter "
                "| ! flagged | m types | s sessions | Enter detail | f follow "
                "| g reseed | q quit")
        self._put(scr, h - 1, 0, keys[:w], THEME["help"])
        scr.refresh()

    @staticmethod
    def _put(scr, y, x, text, attr=curses.A_NORMAL):
        h, w = scr.getmaxyx()
        if y >= h:
            return
        try:
            scr.addnstr(y, x, text, max(0, w - x - 1), attr)
        except (curses.error, UnicodeError):
            pass

    def _put_segments(self, scr, y, w, segments, pad_attr):
        """Render (text, attr) pieces on row y, honouring the horizontal offset."""
        h = scr.getmaxyx()[0]
        if y >= h:
            return
        skip = self.hoff
        x = 0
        limit = w - 1
        for text, attr in segments:
            if x >= limit:
                break
            if skip >= len(text):
                skip -= len(text)
                continue
            if skip:
                text = text[skip:]
                skip = 0
            piece = text[:limit - x]
            try:
                scr.addnstr(y, x, piece, len(piece), attr)
            except (curses.error, UnicodeError):
                pass
            x += len(piece)
        if x < limit:
            try:
                scr.addnstr(y, x, " " * (limit - x), limit - x, pad_attr)
            except (curses.error, UnicodeError):
                pass

    # -- full-screen pagers ----------------------------------------- #

    def _pager(self, scr, header, lines):
        """Scroll a list of (text, attr) rows until q/Enter/Esc. Left/right
        scroll horizontally too, for lines wider than the terminal."""
        off = 0
        hoff = 0
        longest = max((len(text) for text, _ in lines), default=0)
        while True:
            h, w = scr.getmaxyx()
            page = max(1, h - 3)
            scr.erase()
            self._put(scr, 0, 0, header.ljust(w), THEME["title"])
            for i in range(h - 1):
                if off + i >= len(lines):
                    break
                text, attr = lines[off + i]
                self._put(scr, 1 + i, 0, text[hoff:hoff + w - 1], attr)
            scr.refresh()
            ch = scr.getch()
            bottom = max(0, len(lines) - (h - 1))
            right = max(0, longest - (w - 1))
            if ch in (ord("q"), 27, 10, 13, curses.KEY_ENTER):
                return
            elif ch in (curses.KEY_DOWN, ord("j")):
                off = min(off + 1, bottom)
            elif ch in (curses.KEY_UP, ord("k")):
                off = max(0, off - 1)
            elif ch == curses.KEY_NPAGE:
                off = min(off + page, bottom)
            elif ch == curses.KEY_PPAGE:
                off = max(0, off - page)
            elif ch == curses.KEY_HOME:
                off = 0
            elif ch == curses.KEY_END:
                off = bottom
            elif ch == curses.KEY_LEFT:
                hoff = max(0, hoff - 8)
            elif ch == curses.KEY_RIGHT:
                hoff = min(right, hoff + 8)

    def show_detail(self, scr, event):
        norm = curses.A_NORMAL
        lines = [("#%d   %s" % (event.idx, event.time_s), curses.A_BOLD), ("", norm)]
        if event.danger:
            lines.append(("! flagged       : %s" % ", ".join(event.danger),
                          THEME["danger"]))
            lines.append(("", norm))
        lines += [(t, norm) for t in (
            "exe             : %s" % event.exe,
            "commandline     : %s" % event.cmd,
            "key             : %s" % event.key,
            "ses             : %s" % event.ses_s,
        )]
        s = self.model.session_for(event.ses_num, event.ts)
        if s:
            lines.append(("  login session : %s" % session_summary(s), norm))
        lines += [(t, norm) for t in (
            "result          : %s" % _result_display(event),
            "pid / ppid      : %s / %s" % (event.pid, event.ppid),
            "uid             : %s" % event.uid_s,
            "parent command  : %s" % (event.pcomm or "-"),
            "parent exe      : %s" % (event.pexe or "-"),
        )]
        sysf = event.detail.get("SYSCALL", {})
        id_kind = {"auid": "u", "euid": "u", "suid": "u", "fsuid": "u",
                   "gid": "g", "egid": "g", "sgid": "g", "fsgid": "g"}
        for label, key in (("auid", "auid"), ("gid", "gid"), ("euid", "euid"),
                           ("egid", "egid"), ("tty", "tty"),
                           ("arch", "arch"), ("syscall", "syscall"),
                           ("comm", "comm"), ("exit", "exit")):
            if key in sysf:
                value = (denspawn(id_label(sysf, key, id_kind[key])[0])
                         if key in id_kind else unq(sysf[key]))
                lines.append(("%-16s: %s" % (label, value), norm))
        cwd = event.detail.get("CWD", {}).get("cwd")
        if cwd:
            lines.append(("%-16s: %s" % ("cwd", unq(cwd)), norm))
        lines.append(("", norm))
        lines.append(("--- raw records ---", curses.A_DIM))
        lines += [(r.replace(INTERP_SEP, "  "), curses.A_DIM) for r in event.raw]
        self._pager(scr, "detail #%d -- arrows scroll, q/Enter close" % event.idx,
                    lines)

    def show_sessions(self, scr):
        m = self.model
        norm, dim = curses.A_NORMAL, curses.A_DIM
        meta, warn = THEME["cell"][("meta", 0)], THEME["cell"][("warn", 0)]
        ordered = sorted(m.sessions, key=lambda s: s.get("start", 0))
        logins = [s for s in ordered
                  if s.get("login") or s.get("addr") or s.get("interactive")]
        derived = len(ordered) - len(logins)

        def table(headers, rows, row_attrs):
            body = render_table(headers, rows)
            if not isinstance(row_attrs, list):
                row_attrs = [row_attrs] * len(rows)
            return ([(body[0], THEME["header"]), (body[1], dim)]
                    + [(t, a) for t, a in zip(body[2:], row_attrs)])

        # group repeated logins (same user + source + tool) -- SSH forced-command
        # setups open a session per command, which would be hundreds of rows
        groups = {}
        for s in logins:
            k = (denspawn(s.get("user")) or "?", session_source(s),
                 s.get("via") or "-")
            g = groups.setdefault(k, {"n": 0, "first": None, "last": None})
            g["n"] += 1
            for t in (s.get("start"), s.get("end")):
                if t is None:
                    continue
                if g["first"] is None or t < g["first"]:
                    g["first"] = t
                if g["last"] is None or t > g["last"]:
                    g["last"] = t

        lines = [("LOGIN SESSIONS  (%d, from %d user/source pairs)"
                  % (len(logins), len(groups)), THEME["header"]), ("", norm)]
        if groups:
            rows, attrs = [], []
            for (user, src, via), g in sorted(groups.items(),
                                              key=lambda kv: kv[1]["first"] or 0):
                rows.append((user, src, via, g["n"], fmt_time(g["first"]),
                             fmt_time(g["last"])
                             if g["last"] and g["last"] != g["first"] else ""))
                attrs.append(meta if user.startswith("nspawn:")
                             else warn if user == "root" else norm)
            lines += table(("user", "from", "via", "count", "first", "last"),
                           rows, attrs)
        else:
            lines.append(("  (no interactive / credential-checked logins in this log)",
                          dim))
        if derived:
            lines += [("", norm),
                      ("  + %d service / PAM-only sessions (systemd, su, sudo)"
                       % derived, dim)]

        # group auth failures too -- a brute-force is one line, not 200
        fgroups = {}
        for a in m.auth_failures:
            k = (a["acct"], a["addr"] or a["host"] or "-", a["via"], a["reason"])
            g = fgroups.setdefault(k, {"n": 0, "first": a["ts"], "last": a["ts"]})
            g["n"] += 1
            g["first"] = min(g["first"], a["ts"])
            g["last"] = max(g["last"], a["ts"])

        lines += [("", norm),
                  ("AUTH FAILURES  (%d, from %d sources)"
                   % (len(m.auth_failures), len(fgroups)), THEME["header"]),
                  ("", norm)]
        if fgroups:
            rows = []
            for (acct, src, via, reason), g in sorted(
                    fgroups.items(), key=lambda kv: -kv[1]["n"]):
                rows.append((acct, src, via, reason, g["n"], fmt_time(g["first"]),
                             fmt_time(g["last"])
                             if g["last"] != g["first"] else ""))
            lines += table(("acct", "from", "via", "reason", "count", "first", "last"),
                           rows, THEME["danger"])
        else:
            lines.append(("  (none)", dim))
        self._pager(scr, "sessions & logins -- arrows scroll, q/Enter close", lines)

    def show_type_menu(self, scr):
        """Checkbox menu: which row kinds appear in the main table."""
        cur = 0
        while True:
            h, w = scr.getmaxyx()
            scr.erase()
            self._put(scr, 0, 0, "record types shown in the main window".ljust(w),
                     THEME["title"])
            for i, k in enumerate(self.kinds):
                mark = "x" if k in self.enabled_kinds else " "
                text = "  [%s] %-8s %s" % (mark, k, KIND_LABELS.get(k, ""))
                attr = THEME["sel"] if i == cur else curses.A_NORMAL
                self._put(scr, 2 + i, 0, text.ljust(w), attr)
            self._put(scr, 3 + len(self.kinds), 0,
                     "up/dn move | space toggle | a all | n none | Enter/q close"[:w],
                     THEME["help"])
            scr.refresh()
            ch = scr.getch()
            if ch in (ord("q"), 27, 10, 13, curses.KEY_ENTER):
                return
            elif ch in (curses.KEY_DOWN, ord("j")):
                cur = min(len(self.kinds) - 1, cur + 1)
            elif ch in (curses.KEY_UP, ord("k")):
                cur = max(0, cur - 1)
            elif ch == ord(" "):
                k = self.kinds[cur]
                if k in self.enabled_kinds:
                    self.enabled_kinds.discard(k)
                else:
                    self.enabled_kinds.add(k)
            elif ch == ord("a"):
                self.enabled_kinds = set(self.kinds)
            elif ch == ord("n"):
                self.enabled_kinds = set()

    # -- filter prompt ---------------------------------------------- #

    def prompt_filter(self, scr):
        curses.echo()
        curses.curs_set(1)
        h, w = scr.getmaxyx()
        self._put(scr, h - 1, 0, " " * (w - 1))
        self._put(scr, h - 1, 0, "filter: ")
        scr.refresh()
        try:
            value = scr.getstr(h - 1, 8, max(1, w - 10)).decode("utf-8", "replace")
        except curses.error:
            value = ""
        curses.noecho()
        curses.curs_set(0)
        self.filt = value.strip()
        self.cur = 0
        self.top = 0

    # -- main loop ------------------------------------------------- #

    def run(self, scr):
        curses.curs_set(0)
        init_theme(getattr(self, "_color_mode", "auto"))
        scr.timeout(500 if self.follower else -1)
        while True:
            if self.follower:
                self.follower.poll()
            self.refresh_rows()
            self.draw(scr)
            ch = scr.getch()
            if ch == -1:
                if not self.follower:
                    return  # blocking read returned EOF (input not a terminal)
                continue
            page = max(1, scr.getmaxyx()[0] - 6)
            if ch in (ord("q"), ord("Q")):
                return
            elif ch in (curses.KEY_DOWN, ord("j")):
                self.cur += 1
                self.stick = False
            elif ch in (curses.KEY_UP, ord("k")):
                self.cur -= 1
                self.stick = False
            elif ch == curses.KEY_NPAGE:
                self.cur += page
                self.stick = False
            elif ch == curses.KEY_PPAGE:
                self.cur -= page
                self.stick = False
            elif ch == curses.KEY_HOME:
                self.cur = 0
                self.stick = self.reverse
            elif ch == curses.KEY_END:
                self.cur = len(self.rows) - 1
                self.stick = not self.reverse
            elif ch == curses.KEY_LEFT:
                self.hoff = max(0, self.hoff - 8)
            elif ch == curses.KEY_RIGHT:
                self.hoff = min(max(0, total_width() - 20), self.hoff + 8)
            elif ch == ord("/"):
                self.prompt_filter(scr)
            elif ch == ord("!"):
                self.only_flagged = not self.only_flagged
                self.cur = 0
                self.top = 0
            elif ch in (ord("s"), ord("S")):
                self.show_sessions(scr)
                scr.timeout(500 if self.follower else -1)
            elif ch in (ord("m"), ord("M")):
                self.show_type_menu(scr)
                self.cur = 0
                self.top = 0
                scr.timeout(500 if self.follower else -1)
            elif ch in (10, 13, curses.KEY_ENTER):
                if self.rows:
                    self.show_detail(scr, self.rows[self.cur])
                    scr.timeout(500 if self.follower else -1)
            elif ch == ord("f"):
                self._toggle_follow(scr)
            elif ch == ord("g"):
                if self.follower:
                    try:
                        self.model.seed_from_proc()
                    except OSError:
                        pass
            elif 0 <= ch < 256 and chr(ch) in KEY_TO_COL:
                col = KEY_TO_COL[chr(ch)]
                if col == self.sort_col:
                    self.reverse = not self.reverse
                else:
                    self.sort_col = col
                    self.reverse = False
            self.cur = max(0, min(self.cur, max(0, len(self.rows) - 1)))

    def _toggle_follow(self, scr):
        if self.follower:
            self.follower.close()
            self.follower = None
            scr.timeout(-1)
            return
        paths = resolve_paths(self._patterns) if hasattr(self, "_patterns") else []
        target = paths[-1] if paths else None
        if target:
            self.follower = Follower(self.model, target)
            self.stick = True
            scr.timeout(500)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def main(argv=None):
    try:                                       # `--plain | head` shouldn't traceback
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (AttributeError, ValueError, OSError):
        pass
    try:
        locale.setlocale(locale.LC_ALL, "")   # let curses encode wide chars
    except locale.Error:
        pass
    parser = argparse.ArgumentParser(
        description="Browse auditd execve events as a sortable table.")
    parser.add_argument("paths", nargs="*", default=["/var/log/audit/audit.log"],
                        help="audit log file(s) or globs (default: /var/log/audit/audit.log; '-' = stdin)")
    parser.add_argument("-f", "--follow", action="store_true",
                        help="keep reading the newest log file for new events")
    parser.add_argument("--plain", action="store_true",
                        help="print an aligned table to stdout and exit")
    parser.add_argument("--sort", metavar="COL",
                        choices=[c[0] for c in COLUMNS],
                        help="plain mode: sort by this column")
    parser.add_argument("-r", "--reverse", action="store_true",
                        help="plain mode: reverse sort order")
    parser.add_argument("--full", action="store_true",
                        help="plain mode: do not truncate long columns")
    parser.add_argument("--flagged", action="store_true",
                        help="show only sessions that contain a flagged (dangerous) command")
    parser.add_argument("--color", choices=("auto", "dark", "light", "off"),
                        default="auto",
                        help="TUI colour theme (default: auto-detect from COLORFGBG)")
    args = parser.parse_args(argv)
    if os.environ.get("NO_COLOR") is not None and args.color == "auto":
        args.color = "off"

    patterns = args.paths if args.paths else ["/var/log/audit/audit.log"]
    paths = resolve_paths(patterns)
    if not paths:
        sys.stderr.write("auditd-log-parser.py: no readable log files\n")
        return 1

    model = Model()
    if args.follow and not args.plain:
        try:
            model.seed_from_proc()
        except OSError:
            pass
    load_files(model, paths)

    if args.plain:
        run_plain(model, args.sort, args.reverse, args.full, args.color, args.flagged)
        return 0

    follower = None
    if args.follow:
        target = paths[-1] if paths[-1] != "-" else None
        if target:
            follower = Follower(model, target)

    tui = Tui(model, follower)
    tui._patterns = patterns
    tui._color_mode = args.color
    tui.only_flagged = args.flagged
    try:
        curses.wrapper(tui.run)
    except KeyboardInterrupt:
        pass
    except curses.error as exc:
        sys.stderr.write("auditd-log-parser.py: cannot start the TUI (%s); use --plain\n" % exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
