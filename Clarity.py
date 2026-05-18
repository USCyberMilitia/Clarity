"""

Author: US CYBER MILITIA
Clarity: Audio & Video Case Analysis & Review Workstation

A GUI workstation for bodycam/video/audio/report evidence.
The app uses real media metadata, optional real Whisper transcription engines, sidecar/attached transcripts,
speaker diarization through sidecar RTTM or pyannote.audio, force-moment rules,
inconsistency examples with source quotes, case audit logs, and exports.

Important tabs:
    Live Analysis              verbose progress, Whisper settings, CPU threads
    Evidence Manager           import/analyze/hash/notes
    Media Review               metadata, audio analysis, transcript output
    Transcripts / Documents    real extracted text and attached transcripts
    Speakers / Diarization     speaker segments and speaker renaming (may have issues)
    Unified Timeline           timestamped event review
    Force Moment               earliest actual force event and context
    Inconsistencies / Issues   exact triggering examples and review workflow (may have issues)

Run:
    python Clarity.py

Checks:
    python Clarity.py --self-test
    python Clarity.py --dependency-check
"""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import html
import importlib.util
import json
import logging
import math
import mimetypes
import os
import platform
import queue
import re
import shutil
import shlex
import sqlite3
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import traceback
import uuid
import wave
import webbrowser
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog
import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

APP_NAME = "Clarity: Evidence & Case Analysis Workstation"
APP_VERSION = "8.2.0-live-analysis-restored-speaker-progress"

VIDEO_EXT = {".mp4", ".mov", ".avi", ".mkv", ".m4v", ".wmv", ".webm", ".mpg", ".mpeg", ".3gp"}
AUDIO_EXT = {".wav", ".mp3", ".m4a", ".flac", ".aac", ".ogg", ".wma", ".opus", ".aiff", ".aif"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp", ".gif"}
DOCUMENT_EXT = {".txt", ".md", ".csv", ".json", ".pdf", ".docx", ".rtf", ".log"}
TRANSCRIPT_EXT = {".srt", ".vtt"}

SEVERITY_LEVELS = ["Info", "Low", "Medium", "High", "Critical"]
SEVERITY_SCORE = {name: idx for idx, name in enumerate(SEVERITY_LEVELS)}
REVIEW_STATUSES = ["AI/rules-detected", "Human-confirmed", "Dismissed", "Needs attorney review", "Disputed", "Needs source verification"]

DEFAULT_SETTINGS = {
    # Case/evidence behavior
    "copy_evidence_into_case_folder": "1",
    "auto_analyze_on_import": "0",
    "store_nonflag_transcript_lines": "1",
    "hash_algorithm": "sha256",

    # FAST real transcription defaults. These are intentionally fast and safe.
    "transcribe_media": "1",
    "whisper_engine": "auto",          # auto, faster-whisper, openai-whisper, whisper-cli, disabled
    "whisper_model": "tiny",           # tiny is fastest; base/small/medium/large are slower
    "whisper_device": "cpu",           # safe default; set cuda only if your local stack is stable
    "whisper_compute_type": "int8",     # faster-whisper: int8 on CPU is usually fastest/stable
    "whisper_cpu_threads": str(max(1, (os.cpu_count() or 4) - 1)),
    "whisper_beam_size": "1",
    "whisper_language": "en",          # blank for autodetect; en is faster for English bodycam audio
    "whisper_cli_path": "whisper",
    "whisper_timeout_seconds": "7200",
    "extract_audio_before_whisper": "1",
    "reuse_cached_audio_for_whisper": "1",
    "fast_transcription_first": "1",

    # Audio-level analysis is useful, but for huge videos it can slow first output.
    "audio_analysis_enabled": "0",
    "audio_window_seconds": "1.0",
    "audio_peak_count": "12",
    "audio_silence_min_seconds": "2.0",

    # Speaker diarization. Uses real pyannote or sidecar RTTM only. No fake speaker labels.
    "speaker_diarization_enabled": "auto",   # auto, 1, 0
    "speaker_diarization_engine": "pyannote", # pyannote, sidecar-rttm, disabled
    "pyannote_model": "pyannote/speaker-diarization-3.1",
    "pyannote_auth_token": "",
    "diarization_device": "cpu",
    "diarization_preload_audio": "1",  # bypasses pyannote AudioDecoder/TorchCodec path failures
    "diarization_min_speakers": "0",
    "diarization_max_speakers": "0",
    "diarization_num_speakers": "0",
    "diarization_merge_gap": "0.45",
    "diarization_min_segment_seconds": "0.20",
    "diarization_boundary_padding": "0.30",
    "speaker_overwrite_existing_labels": "1",

    # Review/export/UI
    "analysis_window_seconds": "10",
    "redact_public_exports": "1",
    "open_exports_after_creation": "0",
    "reviewer_name": "",
    "font_size": "10",
    "export_folder": "",
}

DEFAULT_RULES = [
    {
        "name": "Actual moment of force / physical force",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(taser\s+(?:deployed|deployment|applied)|deployed\s+(?:my\s+)?taser|tased\b|drive\s*stun|pepper\s+spray\s+(?:deployed|applied|used)|oc\s+spray\s+(?:deployed|applied|used)|sprayed\s+(?:him|her|them|subject)|baton\s+(?:strike|used)|struck\b|strike\b|punched\b|kicked\b|knee\s+strike|take\s*down\b|takedown\b|less\s*lethal\s+(?:fired|deployed)|bean\s*bag\s+(?:fired|deployed)|shots?\s+fired|fired\s+(?:my\s+)?weapon|shot\s+(?:him|her|them|the\s+subject)|physical\s+force\s+(?:used|applied)|hands\s+on\b|use(?:d)?\s+force)\b",
        "category": "Use of Force",
        "severity": "Critical",
        "tags": "force,moment-of-force,physical-force",
        "confidence": 93,
        "description": "Terms that usually indicate force was actually used, not merely warned."
    },
    {
        "name": "Pre-force warning / announcement",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(taser\s+taser|taser\s+warning|you(?:'|’)?re\s+going\s+to\s+get\s+tased|i(?:'|’)?m\s+going\s+to\s+tase\s+you|spray\s+you|less\s*lethal\s+ready|bean\s*bag\s+ready|do\s+not\s+make\s+me\s+use\s+force)\b",
        "category": "Force Warning",
        "severity": "High",
        "tags": "force-warning,pre-force",
        "confidence": 86,
        "description": "Announcements/warnings that may precede force but should not be treated as the force moment."
    },
    {
        "name": "Resistance claim",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(stop\s+resisting|quit\s+resisting|stop\s+fighting|don(?:'|’)?t\s+fight|you(?:'|’)?re\s+resisting|he(?:'|’)?s\s+resisting|she(?:'|’)?s\s+resisting|subject\s+resisting|active\s+resistance)\b",
        "category": "Resistance Claim",
        "severity": "High",
        "tags": "resistance-claim,command",
        "confidence": 86,
        "description": "Officer/radio/report statements claiming resistance."
    },
    {
        "name": "Resistance denial / detention dispute",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(i(?:'|’)?m\s+not\s+resisting|not\s+resisting|i(?:'|’)?m\s+not\s+fighting|i\s+did(?:n(?:'|’)?t|\s+not)\s+do\s+anything|what\s+did\s+i\s+do|why\s+am\s+i\s+being\s+detained|why\s+are\s+you\s+stopping\s+me)\b",
        "category": "Resistance Dispute",
        "severity": "High",
        "tags": "resistance-dispute,subject-statement",
        "confidence": 88,
        "description": "Subject/witness statements disputing resistance or detention."
    },
    {
        "name": "Medical distress",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(i\s+can(?:'|’)?t\s+breathe|can(?:'|’)?t\s+breathe|i\s+cannot\s+breathe|need(?:s)?\s+an\s+ambulance|call\s+an\s+ambulance|unconscious|not\s+breathing|bleeding|chest\s+pain|medical\s+attention|overdose|seizure|passed\s+out|difficulty\s+breathing)\b",
        "category": "Medical Distress",
        "severity": "Critical",
        "tags": "medical,distress,critical",
        "confidence": 93,
        "description": "Medical distress indicators."
    },
    {
        "name": "Weapon-related statement",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(gun|firearm|pistol|rifle|knife|weapon|armed|waistband|reaching|reached\s+for|object\s+in\s+hand|shots?\s+fired)\b",
        "category": "Weapon Claim",
        "severity": "High",
        "tags": "weapon,officer-safety,source-comparison",
        "confidence": 80,
        "description": "Weapon-related statements requiring source comparison."
    },
    {
        "name": "Command / compliance opportunity",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(get\s+on\s+the\s+ground|hands\s+up|show\s+me\s+your\s+hands|drop\s+it|turn\s+around|put\s+your\s+hands\s+behind|step\s+out|exit\s+the\s+vehicle|don(?:'|’)?t\s+move|stop\b|come\s+here|back\s+up|sit\s+down)\b",
        "category": "Command",
        "severity": "Medium",
        "tags": "command,compliance,timing",
        "confidence": 82,
        "description": "Commands relevant to timing and compliance opportunity."
    },
    {
        "name": "De-escalation language",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(calm\s+down|take\s+a\s+breath|talk\s+to\s+me|we(?:'|’)?re\s+here\s+to\s+help|let(?:'|’)?s\s+talk|nobody\s+wants\s+to\s+hurt\s+you|can\s+you\s+explain|slow\s+down|listen\s+to\s+me)\b",
        "category": "De-escalation",
        "severity": "Low",
        "tags": "de-escalation,context",
        "confidence": 78,
        "description": "Potential de-escalation attempts."
    },
    {
        "name": "Report narrative risk language",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(agitated|combative|furtive|non[-\s]?compliant|appeared\s+nervous|feared\s+for\s+(?:my|our|officer)\s+safety|high\s+crime\s+area|reached\s+for\s+waistband|unknown\s+object|aggressive|belligerent|threatening|furtive\s+movement)\b",
        "category": "Report Language",
        "severity": "Medium",
        "tags": "report-language,narrative-risk,source-comparison",
        "confidence": 77,
        "description": "Narrative wording that should be compared against source evidence."
    },
    {
        "name": "Rights / detention / search",
        "enabled": 1,
        "pattern_type": "regex",
        "pattern": r"\b(am\s+i\s+detained|am\s+i\s+free\s+to\s+go|why\s+am\s+i\s+being\s+detained|lawyer|attorney|warrant|search\s+my\s+car|probable\s+cause|reasonable\s+suspicion|consent\s+to\s+search)\b",
        "category": "Rights / Detention",
        "severity": "Medium",
        "tags": "rights,detention,legal-review",
        "confidence": 80,
        "description": "Detention/search/rights review language."
    },
]


def app_dir() -> Path:
    d = Path.home() / ".ai_case_review_workstation"
    d.mkdir(parents=True, exist_ok=True)
    return d


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def pretty_date(s: Optional[str]) -> str:
    if not s:
        return ""
    try:
        return dt.datetime.fromisoformat(s).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return s


def safe_name(s: str, fallback: str = "file") -> str:
    x = re.sub(r"[^A-Za-z0-9_. -]+", "_", s or "").strip(" .")
    return x or fallback


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    base = path.with_suffix("")
    ext = path.suffix
    for i in range(1, 10000):
        cand = Path(f"{base}_{i:03d}{ext}")
        if not cand.exists():
            return cand
    return Path(f"{base}_{uuid.uuid4().hex[:8]}{ext}")


def human_size(value: Any) -> str:
    try:
        n = int(value or 0)
    except Exception:
        return ""
    units = ["B", "KB", "MB", "GB", "TB"]
    f = float(n)
    for unit in units:
        if f < 1024 or unit == units[-1]:
            return f"{int(f)} B" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return str(n)


def classify(path: str | Path) -> str:
    p = Path(path)
    ext = p.suffix.lower()
    if ext in VIDEO_EXT:
        return "video"
    if ext in AUDIO_EXT:
        return "audio"
    if ext in IMAGE_EXT:
        return "image"
    if ext in TRANSCRIPT_EXT:
        return "transcript"
    if ext in DOCUMENT_EXT:
        return "document"
    mt = mimetypes.guess_type(str(path))[0] or ""
    if mt.startswith("video/"):
        return "video"
    if mt.startswith("audio/"):
        return "audio"
    if mt.startswith("image/"):
        return "image"
    if mt.startswith("text/"):
        return "document"
    return "other"


def hash_file(path: str | Path, algorithm: str = "sha256") -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def command_available(command: str) -> bool:
    if not command:
        return False
    if Path(command).exists():
        return True
    return shutil.which(command) is not None


def module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def seconds_from_timestamp(value: Any) -> Optional[float]:
    if value is None:
        return None
    s = str(value).strip().replace(",", ".")
    if not s:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", s):
        try:
            return float(s)
        except Exception:
            return None
    if not re.fullmatch(r"\d{1,2}(?::\d{1,2}){1,2}(?:\.\d+)?", s):
        return None
    parts = s.split(":")
    try:
        if len(parts) == 3:
            return int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2])
        if len(parts) == 2:
            return int(parts[0]) * 60 + float(parts[1])
    except Exception:
        return None
    return None


def fmt_time(value: Any) -> str:
    try:
        if value is None:
            return "--:--"
        v = max(0.0, float(value))
    except Exception:
        return "--:--"
    total = int(round(v))
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


def norm_text(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def severity_max(values: Iterable[str]) -> str:
    best = "Info"
    for v in values:
        if SEVERITY_SCORE.get(v, 0) > SEVERITY_SCORE.get(best, 0):
            best = v
    return best


def clamp_int(value: Any, default: int, lo: int, hi: int) -> int:
    try:
        n = int(value)
    except Exception:
        n = default
    return max(lo, min(hi, n))


def clamp_float(value: Any, default: float, lo: float, hi: float) -> float:
    try:
        n = float(value)
    except Exception:
        n = default
    return max(lo, min(hi, n))


def redact_public_text(text: str) -> str:
    if not text:
        return text
    s = text
    s = re.sub(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", "[REDACTED SSN]", s)
    s = re.sub(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "[REDACTED PHONE]", s)
    s = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "[REDACTED EMAIL]", s, flags=re.I)
    s = re.sub(r"\b(?:DOB|Date\s+of\s+Birth)\s*[:#-]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", "DOB: [REDACTED]", s, flags=re.I)
    s = re.sub(r"\b\d{1,6}\s+[A-Za-z0-9 .'-]{2,60}\s+(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Drive|Dr\.?|Lane|Ln\.?|Boulevard|Blvd\.?|Court|Ct\.?)\b", "[REDACTED ADDRESS]", s)
    return s


def split_plain_text_lines(text: str, max_len: int = 360) -> List[str]:
    """Return real text chunks without inventing structure."""
    lines: List[str] = []
    for raw in (text or "").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        if len(raw) <= max_len:
            lines.append(raw)
        else:
            parts = re.split(r"(?<=[.!?])\s+", raw)
            buf = ""
            for part in parts:
                if not part:
                    continue
                if len(buf) + len(part) + 1 <= max_len:
                    buf = (buf + " " + part).strip()
                else:
                    if buf:
                        lines.append(buf)
                    if len(part) <= max_len:
                        buf = part
                    else:
                        for i in range(0, len(part), max_len):
                            lines.append(part[i:i + max_len])
                        buf = ""
            if buf:
                lines.append(buf)
    if not lines and text.strip():
        t = text.strip()
        for i in range(0, len(t), max_len):
            lines.append(t[i:i + max_len])
    return lines


def parse_transcript(text: str) -> List[Dict[str, Any]]:
    """Parse timestamped transcript/SRT/VTT/Whisper-style text into rows.

    The parser never fabricates timestamps. If a line has no timestamp, its
    time_seconds value is None.
    """
    if not text:
        return []
    normalized_lines: List[str] = []
    pending_time: Optional[str] = None
    skip_headers = {"WEBVTT"}
    for raw in text.splitlines():
        line = raw.strip(" \t\ufeff")
        if not line:
            continue
        if line in skip_headers or re.fullmatch(r"\d+", line):
            continue
        if "-->" in line:
            start = line.split("-->", 1)[0].strip()
            pending_time = start
            continue
        if pending_time:
            normalized_lines.append(f"{pending_time} - {line}")
            pending_time = None
        else:
            normalized_lines.append(raw.rstrip())

    timestamp_patterns = [
        re.compile(r"^\s*\[?(?P<t>(?:\d{1,2}:)?\d{1,2}:\d{2}(?:[\.,]\d{1,3})?)\]?\s*(?:[-–—]+|:)\s*(?P<body>.*)$"),
        re.compile(r"^\s*(?P<t>\d+(?:\.\d+)?)\s*(?:s|sec|seconds)?\s*(?:[-–—]+|:)\s*(?P<body>.*)$", re.I),
        re.compile(r"^\s*<(?P<t>(?:\d{1,2}:)?\d{1,2}:\d{2}(?:[\.,]\d{1,3})?)>\s*(?P<body>.*)$"),
    ]
    rows: List[Dict[str, Any]] = []
    last_timestamped: Optional[Dict[str, Any]] = None
    for raw in normalized_lines:
        line = raw.strip()
        matched: Optional[Tuple[Optional[float], str]] = None
        for pat in timestamp_patterns:
            m = pat.match(line)
            if not m:
                continue
            sec = seconds_from_timestamp(m.group("t"))
            if sec is not None:
                matched = (sec, m.group("body").strip())
                break
        if matched:
            sec, body = matched
            speaker = ""
            text_body = body
            if ":" in body:
                maybe_speaker, rest = body.split(":", 1)
                if 0 < len(maybe_speaker.strip()) <= 50 and not re.search(r"\d", maybe_speaker):
                    speaker = maybe_speaker.strip().strip("[]")
                    text_body = rest.strip()
            row = {
                "time_seconds": sec,
                "time_text": fmt_time(sec),
                "speaker": speaker,
                "text": text_body.strip(" '\""),
                "raw": raw,
            }
            rows.append(row)
            last_timestamped = row
        else:
            # Continuation lines in SRT/VTT should belong to the previous timestamped cue.
            if last_timestamped and len(line) < 220 and not re.match(r"^[A-Z][A-Za-z ]{1,40}:\s+", line):
                last_timestamped["text"] = norm_text(f"{last_timestamped['text']} {line}")
                last_timestamped["raw"] = norm_text(f"{last_timestamped['raw']} {line}")
            else:
                speaker = ""
                text_body = line
                if ":" in line:
                    maybe_speaker, rest = line.split(":", 1)
                    if 0 < len(maybe_speaker.strip()) <= 50 and not re.search(r"\d", maybe_speaker):
                        speaker = maybe_speaker.strip().strip("[]")
                        text_body = rest.strip()
                rows.append({
                    "time_seconds": None,
                    "time_text": "--:--",
                    "speaker": speaker,
                    "text": text_body,
                    "raw": raw,
                })
                last_timestamped = None
    return rows


def open_path(path: str | Path) -> None:
    p = Path(path)
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(p))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(p)])
        else:
            subprocess.Popen(["xdg-open", str(p)])
    except Exception:
        try:
            webbrowser.open(p.resolve().as_uri())
        except Exception:
            pass


def short_json(data: Any, indent: int = 2, max_chars: int = 20000) -> str:
    try:
        s = json.dumps(data, indent=indent, ensure_ascii=False)
    except Exception:
        s = str(data)
    if len(s) > max_chars:
        return s[:max_chars] + "\n... [truncated for display]"
    return s


@dataclass
class Evidence:
    id: int
    path: str
    original_name: str
    display_name: str
    type: str
    size: int
    sha256: str
    imported_at: str
    status: str
    source_label: str
    notes: str
    metadata_json: str
    copied_path: str

    @property
    def analysis_path(self) -> str:
        return self.copied_path or self.path

    @property
    def metadata(self) -> Dict[str, Any]:
        try:
            return json.loads(self.metadata_json or "{}")
        except Exception:
            return {}


class DB:
    def __init__(self, case_dir: Path):
        self.case_dir = Path(case_dir)
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = self.case_dir / "evidence"
        self.exports_dir = self.case_dir / "exports"
        self.logs_dir = self.case_dir / "logs"
        self.cache_dir = self.case_dir / "cache"
        self.frames_dir = self.case_dir / "frames"
        for d in (self.evidence_dir, self.exports_dir, self.logs_dir, self.cache_dir, self.frames_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.path = self.case_dir / "case.sqlite"
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    def close(self) -> None:
        with self.lock:
            self.conn.commit()
            self.conn.close()

    def q(self, sql: str, params: Sequence[Any] = ()) -> List[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(sql, tuple(params)).fetchall()

    def x(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Cursor:
        with self.lock:
            cur = self.conn.execute(sql, tuple(params))
            self.conn.commit()
            return cur

    def scalar(self, sql: str, params: Sequence[Any] = (), default: Any = None) -> Any:
        rows = self.q(sql, params)
        if not rows:
            return default
        row = rows[0]
        return row[0] if len(row.keys()) else default

    def init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS case_info(
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS settings(
                key TEXT PRIMARY KEY,
                value TEXT
            );
            CREATE TABLE IF NOT EXISTS evidence(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                original_name TEXT,
                display_name TEXT,
                type TEXT,
                size INTEGER,
                sha256 TEXT,
                imported_at TEXT,
                status TEXT,
                source_label TEXT,
                notes TEXT,
                metadata_json TEXT,
                copied_path TEXT
            );
            CREATE TABLE IF NOT EXISTS transcripts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                content TEXT,
                created_at TEXT,
                engine TEXT,
                language TEXT,
                confidence REAL,
                source_kind TEXT,
                is_attached INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS media_analysis(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                kind TEXT,
                title TEXT,
                content_json TEXT,
                summary TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS speaker_segments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                start_seconds REAL,
                end_seconds REAL,
                start_text TEXT,
                end_text TEXT,
                speaker_label TEXT,
                role_label TEXT,
                confidence REAL,
                source TEXT,
                raw_json TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS timeline_events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                event_time_seconds REAL,
                event_time_text TEXT,
                source_name TEXT,
                speaker TEXT,
                category TEXT,
                severity TEXT,
                confidence REAL,
                description TEXT,
                tags TEXT,
                review_status TEXT,
                reviewer_notes TEXT,
                created_by TEXT,
                created_at TEXT,
                export_include INTEGER DEFAULT 1,
                raw_text TEXT
            );
            CREATE TABLE IF NOT EXISTS inconsistencies(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id INTEGER,
                related_event_id INTEGER,
                category TEXT,
                severity TEXT,
                confidence REAL,
                title TEXT,
                description TEXT,
                evidence_quote TEXT,
                recommendation TEXT,
                review_status TEXT,
                reviewer_notes TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS rules(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                enabled INTEGER,
                pattern_type TEXT,
                pattern TEXT,
                category TEXT,
                severity TEXT,
                tags TEXT,
                confidence REAL,
                description TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                detail TEXT,
                created_at TEXT,
                actor TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_evidence_type ON evidence(type);
            CREATE INDEX IF NOT EXISTS ix_timeline_time ON timeline_events(event_time_seconds);
            CREATE INDEX IF NOT EXISTS ix_timeline_category ON timeline_events(category);
            CREATE INDEX IF NOT EXISTS ix_timeline_severity ON timeline_events(severity);
            CREATE INDEX IF NOT EXISTS ix_issue_severity ON inconsistencies(severity);
            CREATE INDEX IF NOT EXISTS ix_speaker_segments_eid_time ON speaker_segments(evidence_id,start_seconds,end_seconds);
            """
        )
        self.conn.commit()
        self._ensure_column("transcripts", "is_attached", "INTEGER DEFAULT 0")
        self._ensure_column("media_analysis", "summary", "TEXT")
        self._ensure_column("speaker_segments", "role_label", "TEXT")
        self._ensure_column("speaker_segments", "confidence", "REAL")
        self._ensure_column("speaker_segments", "raw_json", "TEXT")
        for key, value in DEFAULT_SETTINGS.items():
            self.x("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (key, value))
        info_defaults = {
            "title": "Untitled Case",
            "agency": "",
            "incident_date": "",
            "location": "",
            "subject": "",
            "officers": "",
            "case_notes": "",
            "created_at": now(),
            "app_version": APP_VERSION,
        }
        for key, value in info_defaults.items():
            self.x("INSERT OR IGNORE INTO case_info(key,value) VALUES(?,?)", (key, value))
        if int(self.scalar("SELECT COUNT(*) FROM rules", default=0) or 0) == 0:
            self.reset_rules(audit=False)
        self.audit("Case opened", str(self.case_dir), actor="system")

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        rows = self.q(f"PRAGMA table_info({table})")
        if column not in {r["name"] for r in rows}:
            self.x(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def setting(self, key: str, default: str = "") -> str:
        rows = self.q("SELECT value FROM settings WHERE key=?", (key,))
        return str(rows[0]["value"]) if rows else default

    def settings(self) -> Dict[str, str]:
        data = {r["key"]: r["value"] for r in self.q("SELECT key,value FROM settings")}
        for k, v in DEFAULT_SETTINGS.items():
            data.setdefault(k, v)
        return data

    def update_settings(self, data: Dict[str, str]) -> None:
        for k, v in data.items():
            self.x("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
        self.audit("Settings updated", ", ".join(sorted(data)))

    def case_info(self) -> Dict[str, str]:
        return {r["key"]: r["value"] for r in self.q("SELECT key,value FROM case_info")}

    def update_case_info(self, data: Dict[str, str]) -> None:
        for k, v in data.items():
            self.x("INSERT INTO case_info(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
        self.x("INSERT INTO case_info(key,value) VALUES('updated_at',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (now(),))
        self.audit("Case info updated", ", ".join(sorted(data)))

    def audit(self, action: str, detail: str = "", actor: str = "") -> None:
        actor = actor or self.setting("reviewer_name", "") or "system"
        self.x("INSERT INTO audit_log(action,detail,created_at,actor) VALUES(?,?,?,?)", (action, detail, now(), actor))

    def audits(self, limit: int = 1000) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.q("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    def add_evidence(self, file_path: str | Path, copy_into_case: bool = True, source: str = "") -> int:
        p = Path(file_path)
        if not p.exists() or not p.is_file():
            raise FileNotFoundError(str(file_path))
        algorithm = self.setting("hash_algorithm", "sha256") or "sha256"
        sha = hash_file(p, algorithm)
        size = p.stat().st_size
        copied = ""
        if copy_into_case:
            dest = self.evidence_dir / safe_name(p.name)
            if dest.exists():
                try:
                    if hash_file(dest, algorithm) != sha:
                        dest = unique_path(dest)
                except Exception:
                    dest = unique_path(dest)
            if not dest.exists():
                shutil.copy2(p, dest)
            copied = str(dest)
        meta = {
            "imported_platform": platform.platform(),
            "extension": p.suffix.lower(),
            "mime": mimetypes.guess_type(str(p))[0] or "",
            "original_absolute_path": str(p.resolve()),
            "hash_algorithm": algorithm,
        }
        cur = self.x(
            """INSERT INTO evidence(path,original_name,display_name,type,size,sha256,imported_at,status,source_label,notes,metadata_json,copied_path)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (str(p), p.name, p.name, classify(p), size, sha, now(), "pending", source, "", json.dumps(meta, indent=2), copied),
        )
        eid = int(cur.lastrowid)
        self.audit("Evidence imported", f"#{eid} {p.name} | type={classify(p)} | size={human_size(size)} | sha256={sha}")
        return eid

    def evidence(self, eid: int) -> Optional[Evidence]:
        rows = self.q("SELECT * FROM evidence WHERE id=?", (eid,))
        return Evidence(**dict(rows[0])) if rows else None

    def evidences(self, types: Optional[Iterable[str]] = None) -> List[Evidence]:
        if types:
            typelist = list(types)
            marks = ",".join("?" for _ in typelist)
            rows = self.q(f"SELECT * FROM evidence WHERE type IN ({marks}) ORDER BY id", typelist)
        else:
            rows = self.q("SELECT * FROM evidence ORDER BY id")
        return [Evidence(**dict(r)) for r in rows]

    def update_evidence_status(self, eid: int, status: str) -> None:
        self.x("UPDATE evidence SET status=? WHERE id=?", (status, eid))

    def update_evidence_notes(self, eid: int, notes: str) -> None:
        self.x("UPDATE evidence SET notes=? WHERE id=?", (notes, eid))
        self.audit("Evidence notes updated", f"#{eid}")

    def update_evidence_metadata(self, eid: int, metadata: Dict[str, Any]) -> None:
        self.x("UPDATE evidence SET metadata_json=? WHERE id=?", (json.dumps(metadata, indent=2, ensure_ascii=False), eid))

    def remove_evidence(self, eid: int) -> None:
        ev = self.evidence(eid)
        if not ev:
            return
        self.x("DELETE FROM evidence WHERE id=?", (eid,))
        self.x("DELETE FROM transcripts WHERE evidence_id=?", (eid,))
        self.x("DELETE FROM media_analysis WHERE evidence_id=?", (eid,))
        self.x("DELETE FROM timeline_events WHERE evidence_id=?", (eid,))
        self.x("DELETE FROM inconsistencies WHERE evidence_id=?", (eid,))
        self.audit("Evidence removed", f"#{eid} {ev.display_name}")

    def verify_hash(self, eid: int) -> Tuple[bool, str, str]:
        ev = self.evidence(eid)
        if not ev:
            raise ValueError(f"Evidence #{eid} not found")
        path = Path(ev.analysis_path)
        if not path.exists():
            return False, ev.sha256, "MISSING"
        current = hash_file(path, self.setting("hash_algorithm", "sha256") or "sha256")
        return current == ev.sha256, ev.sha256, current

    def add_transcript(self, eid: int, content: str, engine: str, source_kind: str, confidence: float = 0.0, language: str = "", attached: bool = False) -> int:
        cur = self.x(
            "INSERT INTO transcripts(evidence_id,content,created_at,engine,language,confidence,source_kind,is_attached) VALUES(?,?,?,?,?,?,?,?)",
            (eid, content, now(), engine, language, float(confidence or 0), source_kind, 1 if attached else 0),
        )
        self.audit("Transcript added", f"#{eid} engine={engine} source={source_kind} attached={attached}")
        return int(cur.lastrowid)

    def latest_transcript(self, eid: int, include_attached: bool = True) -> Optional[Dict[str, Any]]:
        if include_attached:
            rows = self.q("SELECT * FROM transcripts WHERE evidence_id=? ORDER BY id DESC LIMIT 1", (eid,))
        else:
            rows = self.q("SELECT * FROM transcripts WHERE evidence_id=? AND is_attached=0 ORDER BY id DESC LIMIT 1", (eid,))
        return dict(rows[0]) if rows else None

    def attached_transcript(self, eid: int) -> Optional[Dict[str, Any]]:
        rows = self.q("SELECT * FROM transcripts WHERE evidence_id=? AND is_attached=1 ORDER BY id DESC LIMIT 1", (eid,))
        return dict(rows[0]) if rows else None

    def transcripts(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.q("SELECT * FROM transcripts ORDER BY id")]

    def add_media_analysis(self, eid: int, kind: str, title: str, data: Any, summary: str = "") -> int:
        cur = self.x(
            "INSERT INTO media_analysis(evidence_id,kind,title,content_json,summary,created_at) VALUES(?,?,?,?,?,?)",
            (eid, kind, title, json.dumps(data, indent=2, ensure_ascii=False), summary, now()),
        )
        return int(cur.lastrowid)

    def media_analysis(self, eid: Optional[int] = None) -> List[Dict[str, Any]]:
        if eid is None:
            rows = self.q("SELECT * FROM media_analysis ORDER BY evidence_id,id")
        else:
            rows = self.q("SELECT * FROM media_analysis WHERE evidence_id=? ORDER BY id", (eid,))
        return [dict(r) for r in rows]

    def add_speaker_segment(
        self,
        eid: int,
        start_seconds: float,
        end_seconds: float,
        speaker_label: str,
        role_label: str = "",
        confidence: float = 0.0,
        source: str = "",
        raw: Optional[Dict[str, Any]] = None,
    ) -> int:
        start = float(start_seconds or 0.0)
        end = float(end_seconds or start)
        label = speaker_label or "Speaker"
        cur = self.x(
            """INSERT INTO speaker_segments(evidence_id,start_seconds,end_seconds,start_text,end_text,speaker_label,role_label,confidence,source,raw_json,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (eid, start, end, fmt_time(start), fmt_time(end), label, role_label or label, float(confidence or 0.0), source, json.dumps(raw or {}, indent=2, ensure_ascii=False), now()),
        )
        return int(cur.lastrowid)

    def speaker_segments(self, eid: Optional[int] = None) -> List[Dict[str, Any]]:
        if eid is None:
            rows = self.q("SELECT * FROM speaker_segments ORDER BY evidence_id,start_seconds,id")
        else:
            rows = self.q("SELECT * FROM speaker_segments WHERE evidence_id=? ORDER BY start_seconds,id", (eid,))
        return [dict(r) for r in rows]

    def clear_speaker_segments(self, eid: int) -> None:
        self.x("DELETE FROM speaker_segments WHERE evidence_id=?", (eid,))
        self.audit("Speaker segments cleared", f"#{eid}")

    def update_speaker_role(self, eid: int, speaker_label: str, role_label: str) -> None:
        self.x("UPDATE speaker_segments SET role_label=? WHERE evidence_id=? AND speaker_label=?", (role_label, eid, speaker_label))
        self.audit("Speaker label renamed", f"#{eid} {speaker_label} -> {role_label}")

    def update_transcript_content(self, transcript_id: int, content: str, engine_suffix: str = "speaker-labeled") -> None:
        rows = self.q("SELECT engine FROM transcripts WHERE id=?", (transcript_id,))
        old_engine = rows[0]["engine"] if rows else ""
        engine = f"{old_engine}|{engine_suffix}" if old_engine and engine_suffix not in old_engine else old_engine or engine_suffix
        self.x("UPDATE transcripts SET content=?, engine=? WHERE id=?", (content, engine, transcript_id))
        self.audit("Transcript updated", f"#{transcript_id} {engine_suffix}")

    def clear_analysis(self, eid: int, keep_attached_transcripts: bool = True) -> None:
        if keep_attached_transcripts:
            self.x("DELETE FROM transcripts WHERE evidence_id=? AND COALESCE(is_attached,0)=0", (eid,))
        else:
            self.x("DELETE FROM transcripts WHERE evidence_id=?", (eid,))
        self.x("DELETE FROM media_analysis WHERE evidence_id=?", (eid,))
        self.x("DELETE FROM speaker_segments WHERE evidence_id=?", (eid,))
        self.x("DELETE FROM timeline_events WHERE evidence_id=? AND created_by!='human-reviewer'", (eid,))
        self.x("DELETE FROM inconsistencies WHERE evidence_id=?", (eid,))

    def clear_global_issues(self) -> None:
        self.x("DELETE FROM inconsistencies WHERE evidence_id IS NULL")

    def add_event(
        self,
        eid: Optional[int],
        time_seconds: Optional[float],
        source_name: str,
        speaker: str,
        category: str,
        severity: str,
        confidence: float,
        description: str,
        tags: str = "",
        review_status: str = "AI/rules-detected",
        reviewer_notes: str = "",
        created_by: str = "rules-engine",
        raw_text: str = "",
        export_include: int = 1,
    ) -> int:
        cur = self.x(
            """INSERT INTO timeline_events(evidence_id,event_time_seconds,event_time_text,source_name,speaker,category,severity,confidence,description,tags,review_status,reviewer_notes,created_by,created_at,export_include,raw_text)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                eid,
                None if time_seconds is None else float(time_seconds),
                fmt_time(time_seconds),
                source_name,
                speaker,
                category,
                severity,
                float(confidence or 0),
                description,
                tags,
                review_status,
                reviewer_notes,
                created_by,
                now(),
                int(export_include),
                raw_text or description,
            ),
        )
        return int(cur.lastrowid)

    def events(self, export_only: bool = False) -> List[Dict[str, Any]]:
        where = "WHERE export_include=1" if export_only else ""
        return [dict(r) for r in self.q(f"SELECT * FROM timeline_events {where} ORDER BY CASE WHEN event_time_seconds IS NULL THEN 1 ELSE 0 END, event_time_seconds, id")]

    def event(self, event_id: int) -> Optional[Dict[str, Any]]:
        rows = self.q("SELECT * FROM timeline_events WHERE id=?", (event_id,))
        return dict(rows[0]) if rows else None

    def update_event_review(self, event_id: int, status: str, notes: str = "") -> None:
        self.x("UPDATE timeline_events SET review_status=?, reviewer_notes=? WHERE id=?", (status, notes, event_id))
        self.audit("Timeline event reviewed", f"#{event_id} status={status}")

    def set_event_export(self, event_id: int, include: bool) -> None:
        self.x("UPDATE timeline_events SET export_include=? WHERE id=?", (1 if include else 0, event_id))
        self.audit("Timeline event export flag updated", f"#{event_id} include={include}")

    def add_issue(
        self,
        eid: Optional[int],
        category: str,
        severity: str,
        confidence: float,
        title: str,
        description: str,
        evidence_quote: str = "",
        recommendation: str = "",
        related_event_id: Optional[int] = None,
        review_status: str = "Needs source verification",
    ) -> int:
        cur = self.x(
            """INSERT INTO inconsistencies(evidence_id,related_event_id,category,severity,confidence,title,description,evidence_quote,recommendation,review_status,reviewer_notes,created_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (eid, related_event_id, category, severity, float(confidence or 0), title, description, evidence_quote, recommendation, review_status, "", now()),
        )
        return int(cur.lastrowid)

    def issues(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.q("SELECT * FROM inconsistencies ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, id DESC")]

    def update_issue_review(self, issue_id: int, status: str, notes: str = "") -> None:
        self.x("UPDATE inconsistencies SET review_status=?, reviewer_notes=? WHERE id=?", (status, notes, issue_id))
        self.audit("Issue reviewed", f"#{issue_id} status={status}")

    def rules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        where = "WHERE enabled=1" if enabled_only else ""
        return [dict(r) for r in self.q(f"SELECT * FROM rules {where} ORDER BY id")]

    def save_rule(self, data: Dict[str, Any], rid: Optional[int] = None) -> int:
        values = (
            data.get("name", "Custom Rule"),
            int(data.get("enabled", 1)),
            data.get("pattern_type", "regex"),
            data.get("pattern", ""),
            data.get("category", "Custom"),
            data.get("severity", "Medium"),
            data.get("tags", "custom"),
            float(data.get("confidence", 75)),
            data.get("description", ""),
        )
        if rid:
            self.x(
                "UPDATE rules SET name=?,enabled=?,pattern_type=?,pattern=?,category=?,severity=?,tags=?,confidence=?,description=? WHERE id=?",
                (*values, rid),
            )
            self.audit("Rule updated", f"#{rid} {data.get('name')}")
            return rid
        cur = self.x(
            "INSERT INTO rules(name,enabled,pattern_type,pattern,category,severity,tags,confidence,description,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (*values, now()),
        )
        rid2 = int(cur.lastrowid)
        self.audit("Rule created", f"#{rid2} {data.get('name')}")
        return rid2

    def delete_rule(self, rid: int) -> None:
        self.x("DELETE FROM rules WHERE id=?", (rid,))
        self.audit("Rule deleted", f"#{rid}")

    def reset_rules(self, audit: bool = True) -> None:
        self.x("DELETE FROM rules")
        for r in DEFAULT_RULES:
            self.save_rule(dict(r))
        if audit:
            self.audit("Rules reset", "Default rules restored")

    def stats(self) -> Dict[str, int]:
        def count(sql: str, params: Sequence[Any] = ()) -> int:
            return int(self.scalar(sql, params, 0) or 0)
        return {
            "evidence": count("SELECT COUNT(*) FROM evidence"),
            "analyzed": count("SELECT COUNT(*) FROM evidence WHERE status IN ('analyzed','analyzed-no-transcript','analyzed-limited')"),
            "pending": count("SELECT COUNT(*) FROM evidence WHERE status='pending'"),
            "failed": count("SELECT COUNT(*) FROM evidence WHERE status='failed'"),
            "transcripts": count("SELECT COUNT(*) FROM transcripts"),
            "media_analysis": count("SELECT COUNT(*) FROM media_analysis"),
            "speaker_segments": count("SELECT COUNT(*) FROM speaker_segments"),
            "events": count("SELECT COUNT(*) FROM timeline_events"),
            "issues": count("SELECT COUNT(*) FROM inconsistencies"),
            "critical_events": count("SELECT COUNT(*) FROM timeline_events WHERE severity='Critical'"),
            "high_events": count("SELECT COUNT(*) FROM timeline_events WHERE severity='High'"),
            "force_events": count("SELECT COUNT(*) FROM timeline_events WHERE category='Use of Force' OR tags LIKE '%moment-of-force%'"),
            "confirmed_events": count("SELECT COUNT(*) FROM timeline_events WHERE review_status='Human-confirmed'"),
        }

    def export_data(self) -> Dict[str, Any]:
        return {
            "app": {"name": APP_NAME, "version": APP_VERSION, "exported_at": now()},
            "case_info": self.case_info(),
            "settings": self.settings(),
            "evidence": [asdict(e) for e in self.evidences()],
            "transcripts": self.transcripts(),
            "media_analysis": self.media_analysis(),
            "speaker_segments": self.speaker_segments(),
            "timeline_events": self.events(),
            "issues": self.issues(),
            "rules": self.rules(),
            "audit_log": self.audits(100000),
        }


class TextExtractor:
    def __init__(self, log: Optional[Callable[[str], None]] = None):
        self.log = log or (lambda msg: None)

    def read_text(self, path: Path) -> str:
        for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
            try:
                return path.read_text(encoding=enc)
            except UnicodeDecodeError:
                continue
        return path.read_text(errors="replace")

    def extract_pdf(self, path: Path) -> Tuple[str, str]:
        # Try several real extractors. If none works, return an explicit error.
        try:
            if importlib.util.find_spec("pypdf"):
                from pypdf import PdfReader  # type: ignore
                reader = PdfReader(str(path))
                text = "\n\n".join((page.extract_text() or "") for page in reader.pages).strip()
                return text, "pypdf"
        except Exception as e:
            self.log(f"pypdf extraction failed for {path.name}: {e}")
        try:
            if importlib.util.find_spec("PyPDF2"):
                from PyPDF2 import PdfReader  # type: ignore
                reader = PdfReader(str(path))
                text = "\n\n".join((page.extract_text() or "") for page in reader.pages).strip()
                return text, "PyPDF2"
        except Exception as e:
            self.log(f"PyPDF2 extraction failed for {path.name}: {e}")
        try:
            if importlib.util.find_spec("pdfminer"):
                from pdfminer.high_level import extract_text  # type: ignore
                text = (extract_text(str(path)) or "").strip()
                return text, "pdfminer.six"
        except Exception as e:
            self.log(f"pdfminer extraction failed for {path.name}: {e}")
        if command_available("pdftotext"):
            try:
                out = subprocess.run(["pdftotext", "-layout", str(path), "-"], capture_output=True, text=True, timeout=120)
                if out.returncode == 0:
                    return out.stdout.strip(), "pdftotext"
                self.log(out.stderr.strip())
            except Exception as e:
                self.log(f"pdftotext extraction failed for {path.name}: {e}")
        return "", "PDF text extraction unavailable or no embedded text found. Install pypdf/PyPDF2/pdfminer or provide OCR/text transcript."

    def extract_docx(self, path: Path) -> Tuple[str, str]:
        try:
            with zipfile.ZipFile(path) as z:
                xml = z.read("word/document.xml").decode("utf-8", errors="replace")
            xml = re.sub(r"</w:p>", "\n", xml)
            text = html.unescape(re.sub(r"<[^>]+>", "", xml)).strip()
            return text, "docx-xml"
        except Exception as e:
            return "", f"DOCX extraction failed: {e}"

    def extract_rtf(self, path: Path) -> Tuple[str, str]:
        raw = self.read_text(path)
        raw = re.sub(r"\\'[0-9a-fA-F]{2}", " ", raw)
        raw = re.sub(r"\\[a-zA-Z]+-?\d* ?", " ", raw)
        text = norm_text(raw.replace("{", " ").replace("}", " "))
        return text, "basic-rtf-stripper"

    def extract(self, path: str | Path) -> Tuple[str, str, bool]:
        p = Path(path)
        ext = p.suffix.lower()
        try:
            if ext in {".txt", ".md", ".csv", ".json", ".log", ".srt", ".vtt"}:
                return self.read_text(p), "text-file", True
            if ext == ".pdf":
                text, engine = self.extract_pdf(p)
                return text, engine, bool(text.strip())
            if ext == ".docx":
                text, engine = self.extract_docx(p)
                return text, engine, bool(text.strip())
            if ext == ".rtf":
                text, engine = self.extract_rtf(p)
                return text, engine, bool(text.strip())
            return "", f"Unsupported text extraction format: {ext or 'no extension'}", False
        except Exception as e:
            return "", f"Text extraction failed: {e}", False

    def sidecar_candidates(self, media_path: Path, original_path: Optional[Path] = None) -> List[Path]:
        roots = []
        for base in [media_path, original_path]:
            if base and base.exists():
                roots.append(base)
        out: List[Path] = []
        suffixes = [".txt", ".srt", ".vtt", ".md"]
        name_suffixes = [".transcript", "_transcript", ".Transcript", "_Transcript", ".captions", "_captions"]
        for base in roots:
            for suf in suffixes:
                out.append(base.with_suffix(suf))
            for middle in name_suffixes:
                for suf in suffixes:
                    out.append(base.parent / f"{base.stem}{middle}{suf}")
        seen = set()
        unique = []
        for p in out:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    def find_sidecar(self, media_path: Path, original_path: Optional[Path] = None) -> Optional[Path]:
        for p in self.sidecar_candidates(media_path, original_path):
            if p.exists() and p.is_file() and p.resolve() != media_path.resolve():
                return p
        return None


class MediaTools:
    def __init__(self, db: DB, log: Optional[Callable[[str], None]] = None):
        self.db = db
        self.log = log or (lambda msg: None)

    def settings(self) -> Dict[str, str]:
        return self.db.settings()

    def ffprobe_cmd(self) -> str:
        return self.db.setting("ffprobe_path", "ffprobe") or "ffprobe"

    def ffmpeg_cmd(self) -> str:
        return self.db.setting("ffmpeg_path", "ffmpeg") or "ffmpeg"

    def ffprobe_available(self) -> bool:
        return command_available(self.ffprobe_cmd())

    def ffmpeg_available(self) -> bool:
        return command_available(self.ffmpeg_cmd())

    def probe(self, path: Path) -> Tuple[Dict[str, Any], str]:
        if not self.ffprobe_available():
            basic = {
                "file_name": path.name,
                "size_bytes": path.stat().st_size if path.exists() else None,
                "error": "ffprobe is not available. Install ffmpeg or set ffprobe_path in Settings for stream/duration metadata.",
            }
            return basic, "basic-file-metadata"
        cmd = [self.ffprobe_cmd(), "-v", "error", "-show_format", "-show_streams", "-print_format", "json", str(path)]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if out.returncode != 0:
                return {"error": out.stderr.strip() or "ffprobe failed", "command": cmd}, "ffprobe-error"
            data = json.loads(out.stdout or "{}")
            data["file_name"] = path.name
            data["size_bytes"] = path.stat().st_size if path.exists() else None
            return data, "ffprobe"
        except Exception as e:
            return {"error": str(e), "command": cmd}, "ffprobe-exception"

    def summarize_probe(self, data: Dict[str, Any]) -> str:
        if not data:
            return "No metadata."
        if data.get("error"):
            return str(data.get("error"))
        fmt = data.get("format", {}) if isinstance(data.get("format"), dict) else {}
        streams = data.get("streams", []) if isinstance(data.get("streams"), list) else []
        dur = fmt.get("duration")
        size = fmt.get("size") or data.get("size_bytes")
        lines = []
        if dur:
            try:
                lines.append(f"Duration: {fmt_time(float(dur))} ({float(dur):.2f} seconds)")
            except Exception:
                lines.append(f"Duration: {dur}")
        if size:
            lines.append(f"Size: {human_size(size)}")
        if fmt.get("format_name"):
            lines.append(f"Container: {fmt.get('format_name')}")
        for i, st in enumerate(streams):
            codec_type = st.get("codec_type", "stream")
            codec = st.get("codec_name", "unknown")
            detail = f"Stream {i}: {codec_type} / {codec}"
            if codec_type == "video":
                detail += f" / {st.get('width','?')}x{st.get('height','?')}"
                if st.get("avg_frame_rate"):
                    detail += f" / avg_frame_rate={st.get('avg_frame_rate')}"
            if codec_type == "audio":
                detail += f" / sample_rate={st.get('sample_rate','?')} / channels={st.get('channels','?')}"
            lines.append(detail)
        return "\n".join(lines) if lines else short_json(data, max_chars=2000)

    def has_audio_stream(self, probe_data: Dict[str, Any]) -> bool:
        streams = probe_data.get("streams", []) if isinstance(probe_data.get("streams"), list) else []
        return any(s.get("codec_type") == "audio" for s in streams)

    def duration_from_probe(self, probe_data: Dict[str, Any]) -> Optional[float]:
        try:
            return float(probe_data.get("format", {}).get("duration"))
        except Exception:
            return None

    def extract_audio_wav(self, path: Path, eid: int) -> Tuple[Optional[Path], str]:
        """Extract/reuse a mono 16 kHz WAV. Logs ffmpeg progress so huge video files do not look frozen."""
        ext = path.suffix.lower()
        if ext == ".wav":
            self.log(f"Audio extraction skipped: evidence #{eid} is already WAV.")
            return path, "original-wav"
        if not self.ffmpeg_available():
            return None, "ffmpeg is not available; cannot extract audio. Install ffmpeg or set ffmpeg_path in Settings."
        dest = self.db.cache_dir / f"evidence_{eid}_audio_mono16k.wav"
        reuse = self.db.setting("reuse_cached_audio_for_whisper", "1") == "1"
        if reuse and dest.exists() and dest.stat().st_size > 44:
            self.log(f"PASS cached audio exists for evidence #{eid}: {dest} ({human_size(dest.stat().st_size)})")
            return dest, "cached-ffmpeg-mono-16k"
        cmd = [self.ffmpeg_cmd(), "-y", "-i", str(path), "-vn", "-ac", "1", "-ar", "16000", "-sample_fmt", "s16", str(dest)]
        self.log("Starting ffmpeg audio extraction: " + " ".join(map(str, cmd)))
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
            stderr_lines: List[str] = []
            last_log = dt.datetime.now()
            while True:
                line = proc.stderr.readline() if proc.stderr else ""
                if line:
                    clean = line.strip()
                    stderr_lines.append(clean)
                    if "time=" in clean or "speed=" in clean or "Duration:" in clean:
                        self.log(f"ffmpeg: {clean}")
                if proc.poll() is not None:
                    # drain remaining stderr
                    if proc.stderr:
                        rest = proc.stderr.read() or ""
                        for clean in [x.strip() for x in rest.splitlines() if x.strip()]:
                            stderr_lines.append(clean)
                    break
                if (dt.datetime.now() - last_log).total_seconds() >= 10:
                    self.log(f"ffmpeg heartbeat: extracting audio for evidence #{eid}; output so far={human_size(dest.stat().st_size) if dest.exists() else '0 B'}")
                    last_log = dt.datetime.now()
                self._sleep_short()
            if proc.returncode != 0 or not dest.exists() or dest.stat().st_size <= 44:
                msg = "\n".join(stderr_lines[-25:]) or "ffmpeg audio extraction failed"
                return None, msg
            self.log(f"PASS ffmpeg audio extraction complete for evidence #{eid}: {dest} ({human_size(dest.stat().st_size)})")
            return dest, "ffmpeg-extracted-mono-16k"
        except Exception as e:
            return None, f"ffmpeg audio extraction failed: {e}"

    def _sleep_short(self) -> None:
        try:
            threading.Event().wait(0.05)
        except Exception:
            pass

    def analyze_wav_levels(self, wav_path: Path, window_seconds: float = 1.0) -> Tuple[Dict[str, Any], str]:
        if not wav_path.exists():
            return {}, "WAV file missing."
        try:
            with wave.open(str(wav_path), "rb") as wf:
                channels = wf.getnchannels()
                sampwidth = wf.getsampwidth()
                rate = wf.getframerate()
                total_frames = wf.getnframes()
                duration = total_frames / float(rate) if rate else 0.0
                if sampwidth not in (1, 2, 4):
                    return {}, f"Unsupported WAV sample width: {sampwidth} bytes."
                frames_per_window = max(1, int(rate * window_seconds))
                windows = []
                index = 0
                while True:
                    raw = wf.readframes(frames_per_window)
                    if not raw:
                        break
                    count_samples = len(raw) // sampwidth
                    if count_samples <= 0:
                        break
                    if sampwidth == 1:
                        vals = [(b - 128) / 128.0 for b in raw]
                    elif sampwidth == 2:
                        vals = [x / 32768.0 for x in struct.unpack("<" + "h" * (len(raw) // 2), raw)]
                    else:
                        vals = [x / 2147483648.0 for x in struct.unpack("<" + "i" * (len(raw) // 4), raw)]
                    # Downmix by treating all channel samples together. ffmpeg extraction is mono.
                    if not vals:
                        break
                    rms = math.sqrt(sum(v * v for v in vals) / len(vals))
                    peak = max(abs(v) for v in vals)
                    dbfs = 20 * math.log10(max(rms, 1e-12))
                    start = index * window_seconds
                    windows.append({
                        "index": index,
                        "start_seconds": start,
                        "time_text": fmt_time(start),
                        "rms": rms,
                        "peak": peak,
                        "dbfs": dbfs,
                    })
                    index += 1
            if not windows:
                return {"duration_seconds": duration, "sample_rate": rate, "channels": channels, "windows": []}, "No audio samples read."
            rms_values = [w["rms"] for w in windows]
            max_rms = max(rms_values)
            mean_rms = statistics.mean(rms_values)
            median_rms = statistics.median(rms_values)
            noise_floor = statistics.quantiles(rms_values, n=20)[0] if len(rms_values) >= 20 else min(rms_values)
            data = {
                "wav_path": str(wav_path),
                "duration_seconds": duration,
                "duration_text": fmt_time(duration),
                "sample_rate": rate,
                "channels": channels,
                "sample_width_bytes": sampwidth,
                "window_seconds": window_seconds,
                "window_count": len(windows),
                "max_rms": max_rms,
                "mean_rms": mean_rms,
                "median_rms": median_rms,
                "estimated_noise_floor_rms": noise_floor,
                "windows": windows,
            }
            return data, "ok"
        except wave.Error as e:
            return {}, f"WAV parse failed: {e}"
        except Exception as e:
            return {}, f"Audio level analysis failed: {e}"

    def top_audio_peaks(self, data: Dict[str, Any], count: int) -> List[Dict[str, Any]]:
        windows = data.get("windows", []) if isinstance(data.get("windows"), list) else []
        # Select local-ish peaks by sorting; suppress adjacent windows to avoid duplicates.
        sorted_windows = sorted(windows, key=lambda w: w.get("rms", 0), reverse=True)
        selected: List[Dict[str, Any]] = []
        min_gap = max(1.0, float(data.get("window_seconds", 1.0)) * 2)
        for w in sorted_windows:
            t = float(w.get("start_seconds", 0.0))
            if any(abs(t - float(s.get("start_seconds", 0.0))) < min_gap for s in selected):
                continue
            selected.append(w)
            if len(selected) >= count:
                break
        return sorted(selected, key=lambda w: w.get("start_seconds", 0.0))

    def silence_ranges(self, data: Dict[str, Any], min_seconds: float) -> List[Dict[str, Any]]:
        windows = data.get("windows", []) if isinstance(data.get("windows"), list) else []
        if not windows:
            return []
        max_rms = max((w.get("rms", 0.0) for w in windows), default=0.0)
        median_rms = float(data.get("median_rms", 0.0) or 0.0)
        threshold = max(0.003, min(0.02, max_rms * 0.04, median_rms * 0.35))
        win = float(data.get("window_seconds", 1.0) or 1.0)
        ranges: List[Dict[str, Any]] = []
        start: Optional[float] = None
        last: Optional[float] = None
        for w in windows:
            t = float(w.get("start_seconds", 0.0))
            if float(w.get("rms", 0.0) or 0.0) <= threshold:
                if start is None:
                    start = t
                last = t + win
            else:
                if start is not None and last is not None and last - start >= min_seconds:
                    ranges.append({"start_seconds": start, "end_seconds": last, "duration_seconds": last - start, "threshold_rms": threshold})
                start = None
                last = None
        if start is not None and last is not None and last - start >= min_seconds:
            ranges.append({"start_seconds": start, "end_seconds": last, "duration_seconds": last - start, "threshold_rms": threshold})
        return ranges

    def extract_frame(self, ev: Evidence, time_seconds: float) -> Tuple[Optional[Path], str]:
        if ev.type != "video":
            return None, "Frame extraction requires video evidence."
        if not self.ffmpeg_available():
            return None, "ffmpeg is not available; cannot extract video frame."
        source = Path(ev.analysis_path)
        out = self.db.frames_dir / f"evidence_{ev.id}_{int(time_seconds):06d}s.jpg"
        out = unique_path(out)
        cmd = [self.ffmpeg_cmd(), "-y", "-ss", str(max(0.0, float(time_seconds))), "-i", str(source), "-frames:v", "1", "-q:v", "2", str(out)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if proc.returncode == 0 and out.exists():
                self.db.audit("Frame extracted", f"#{ev.id} {fmt_time(time_seconds)} -> {out}")
                return out, "ok"
            return None, proc.stderr.strip() or "ffmpeg frame extraction failed"
        except Exception as e:
            return None, f"Frame extraction failed: {e}"


class Transcriber:
    def __init__(self, db: DB, log: Optional[Callable[[str], None]] = None):
        self.db = db
        self.log = log or (lambda msg: None)
        self.text = TextExtractor(self.log)
        self.media = MediaTools(db, self.log)

    def transcribe(self, ev: Evidence) -> Tuple[str, str, float, str, bool]:
        """Return (text, engine, confidence, language, ok). No fake fallback."""
        attached = self.db.attached_transcript(ev.id)
        if attached and (attached.get("content") or "").strip():
            self.log(f"PASS using attached transcript for evidence #{ev.id}; no Whisper needed.")
            return attached["content"], f"attached:{attached.get('engine','manual')}", float(attached.get("confidence") or 95), attached.get("language") or "", True

        path = Path(ev.analysis_path)
        original = Path(ev.path) if ev.path else None
        sidecar = self.text.find_sidecar(path, original)
        if sidecar:
            self.log(f"PASS using sidecar transcript for evidence #{ev.id}: {sidecar}")
            text, engine, ok = self.text.extract(sidecar)
            if ok and text.strip():
                return text, f"sidecar:{engine}:{sidecar.name}", 95.0, "", True
            return "", f"sidecar-found-but-unreadable:{sidecar.name}:{engine}", 0.0, "", False

        settings = self.db.settings()
        if settings.get("transcribe_media", "1") != "1" or settings.get("whisper_engine", "auto") == "disabled":
            self.log("WARN transcription disabled by Settings.")
            return "", "transcription-disabled", 0.0, "", False

        input_path = path
        if settings.get("extract_audio_before_whisper", "1") == "1" and ev.type in {"video", "audio"}:
            self.log("Preparing fast Whisper input: extracting/reusing mono 16 kHz WAV before transcription.")
            wav_path, wav_engine = self.media.extract_audio_wav(path, ev.id)
            if wav_path:
                input_path = wav_path
                self.log(f"PASS Whisper will use {wav_engine}: {input_path}")
            else:
                self.log(f"WARN could not prepare WAV for Whisper; trying original media file. Details: {wav_engine}")

        engine_pref = settings.get("whisper_engine", "auto") or "auto"
        model_name = settings.get("whisper_model", "tiny") or "tiny"
        engines = [engine_pref] if engine_pref != "auto" else ["faster-whisper", "openai-whisper", "whisper-cli"]
        last_error = ""
        self.log(f"Transcription plan: engines={engines}, model={model_name}, input={input_path.name}, threads={settings.get('whisper_cpu_threads')}, beam={settings.get('whisper_beam_size')}, language={settings.get('whisper_language') or 'auto'}")
        for engine in engines:
            started = dt.datetime.now()
            self.log(f"START transcription engine={engine} for evidence #{ev.id}")
            if engine == "faster-whisper":
                text, label, conf, lang, ok, err = self._faster_whisper(input_path, model_name, settings)
            elif engine == "openai-whisper":
                text, label, conf, lang, ok, err = self._openai_whisper(input_path, model_name, settings)
            elif engine == "whisper-cli":
                text, label, conf, lang, ok, err = self._whisper_cli(input_path, model_name, settings)
            else:
                text, label, conf, lang, ok, err = "", engine, 0.0, "", False, f"Unknown transcription engine: {engine}"
            elapsed = (dt.datetime.now() - started).total_seconds()
            if ok and text.strip():
                line_count = len(parse_transcript(text))
                self.log(f"PASS transcription complete via {label}: {len(text):,} chars, parsed_lines={line_count}, elapsed={elapsed:.1f}s")
                return text, label, conf, lang, True
            last_error = err or label
            self.log(f"FAIL transcription engine {engine} did not produce text after {elapsed:.1f}s: {last_error}")
        return "", f"no-real-transcript:{last_error or 'no engine available'}", 0.0, "", False

    def _thread_count(self, settings: Dict[str, str]) -> int:
        return clamp_int(settings.get("whisper_cpu_threads", str(os.cpu_count() or 4)), max(1, (os.cpu_count() or 4) - 1), 1, 256)

    def _beam_size(self, settings: Dict[str, str]) -> int:
        return clamp_int(settings.get("whisper_beam_size", "1"), 1, 1, 10)

    def _language(self, settings: Dict[str, str]) -> Optional[str]:
        v = (settings.get("whisper_language", "") or "").strip()
        return v or None

    def _device(self, settings: Dict[str, str]) -> str:
        dev = (settings.get("whisper_device", "cpu") or "cpu").strip().lower()
        # Safe default: auto resolves to CPU. CUDA must be explicitly requested.
        return "cpu" if dev in {"", "auto"} else dev

    def _set_thread_env(self, settings: Dict[str, str]) -> Dict[str, str]:
        threads = self._thread_count(settings)
        env = os.environ.copy()
        for key in ["OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "VECLIB_MAXIMUM_THREADS", "NUMEXPR_NUM_THREADS"]:
            env[key] = str(threads)
            os.environ[key] = str(threads)
        try:
            if importlib.util.find_spec("torch"):
                import torch  # type: ignore
                torch.set_num_threads(threads)
        except Exception as e:
            self.log(f"WARN could not set torch CPU thread count: {e}")
        return env

    def _faster_whisper(self, path: Path, model_name: str, settings: Dict[str, str]) -> Tuple[str, str, float, str, bool, str]:
        if not module_available("faster_whisper"):
            return "", "faster-whisper", 0.0, "", False, "faster_whisper package not installed in this Python"
        try:
            from faster_whisper import WhisperModel  # type: ignore
            device = self._device(settings)
            compute_type = (settings.get("whisper_compute_type", "int8") or "int8").strip()
            threads = self._thread_count(settings)
            beam = self._beam_size(settings)
            language = self._language(settings)
            self._set_thread_env(settings)
            self.log(f"Loading faster-whisper model={model_name} device={device} compute_type={compute_type} cpu_threads={threads}")
            model = WhisperModel(model_name, device=device, compute_type=compute_type, cpu_threads=threads)
            self.log(f"PASS faster-whisper model loaded. Decoding now: {path}")
            kwargs: Dict[str, Any] = {"beam_size": beam, "vad_filter": True}
            if language:
                kwargs["language"] = language
            segments, info = model.transcribe(str(path), **kwargs)
            lines = []
            chars = 0
            last_log = dt.datetime.now()
            for idx, seg in enumerate(segments, 1):
                start = float(getattr(seg, "start", 0.0) or 0.0)
                end = float(getattr(seg, "end", start) or start)
                text = str(getattr(seg, "text", "") or "").strip()
                if text:
                    line = f"{fmt_time(start)} - Speaker: {text}"
                    lines.append(line)
                    chars += len(text)
                    if idx <= 10 or idx % 10 == 0 or (dt.datetime.now() - last_log).total_seconds() > 8:
                        self.log(f"faster-whisper segment {idx}: {fmt_time(start)}-{fmt_time(end)} | {text[:160]}")
                        last_log = dt.datetime.now()
            language_out = str(getattr(info, "language", "") or language or "")
            return "\n".join(lines), f"faster-whisper:{model_name}", 88.0, language_out, bool(lines), ""
        except Exception:
            return "", f"faster-whisper:{model_name}", 0.0, "", False, traceback.format_exc()

    def _openai_whisper(self, path: Path, model_name: str, settings: Dict[str, str]) -> Tuple[str, str, float, str, bool, str]:
        if not importlib.util.find_spec("whisper"):
            return "", "openai-whisper", 0.0, "", False, "whisper module not installed in this Python. Install with: python -m pip install -U openai-whisper"
        try:
            import whisper  # type: ignore
            if not hasattr(whisper, "load_model"):
                return "", "openai-whisper", 0.0, "", False, "A module named 'whisper' is installed, but it is not OpenAI Whisper because it lacks load_model(). Run: python -m pip uninstall -y whisper && python -m pip install -U openai-whisper"
            device = self._device(settings)
            language = self._language(settings)
            self._set_thread_env(settings)
            self.log(f"Loading openai-whisper model={model_name} device={device}")
            model = whisper.load_model(model_name, device=device)
            kwargs: Dict[str, Any] = {"verbose": False}
            if language:
                kwargs["language"] = language
            if device == "cpu":
                kwargs["fp16"] = False
            self.log(f"PASS openai-whisper model loaded. Decoding now: {path}")
            result = model.transcribe(str(path), **kwargs)
            lines = []
            for idx, seg in enumerate(result.get("segments", []) or [], 1):
                start = float(seg.get("start", 0.0) or 0.0)
                end = float(seg.get("end", start) or start)
                text = str(seg.get("text", "") or "").strip()
                if text:
                    lines.append(f"{fmt_time(start)} - Speaker: {text}")
                    if idx <= 10 or idx % 10 == 0:
                        self.log(f"openai-whisper segment {idx}: {fmt_time(start)}-{fmt_time(end)} | {text[:160]}")
            language_out = str(result.get("language", "") or language or "")
            return "\n".join(lines), f"openai-whisper:{model_name}", 87.0, language_out, bool(lines), ""
        except Exception:
            return "", f"openai-whisper:{model_name}", 0.0, "", False, traceback.format_exc()

    def _whisper_cli(self, path: Path, model_name: str, settings: Dict[str, str]) -> Tuple[str, str, float, str, bool, str]:
        cli_raw = settings.get("whisper_cli_path", "whisper") or "whisper"
        cli_parts = shlex.split(cli_raw, posix=not sys.platform.startswith("win"))
        if not cli_parts:
            cli_parts = ["whisper"]
        executable = cli_parts[0]
        if not command_available(executable):
            return "", "whisper-cli", 0.0, "", False, f"Whisper CLI not found: {executable}. Set Settings/live whisper_cli_path to the exact command that works in your terminal."
        timeout = clamp_int(settings.get("whisper_timeout_seconds", "7200"), 7200, 30, 86400)
        device = self._device(settings)
        language = self._language(settings)
        with tempfile.TemporaryDirectory() as td:
            out_dir = Path(td)
            cmd = cli_parts + [str(path), "--model", model_name, "--output_format", "srt", "--output_dir", str(out_dir), "--verbose", "True"]
            if language:
                cmd += ["--language", language]
            if device:
                cmd += ["--device", device]
            if device == "cpu":
                cmd += ["--fp16", "False"]
            env = self._set_thread_env(settings)
            self.log("Starting Whisper CLI command: " + " ".join(map(str, cmd)))
            self.log(f"CLI environment thread hints: OMP_NUM_THREADS={env.get('OMP_NUM_THREADS')} timeout={timeout}s")
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", env=env)
                q: "queue.Queue[Tuple[str, str]]" = queue.Queue()

                def reader(name: str, pipe: Any) -> None:
                    try:
                        for line in iter(pipe.readline, ""):
                            if line:
                                q.put((name, line.rstrip()))
                    except Exception as e:
                        q.put((name, f"reader error: {e}"))

                threads = []
                for name, pipe in [("stdout", proc.stdout), ("stderr", proc.stderr)]:
                    if pipe:
                        t = threading.Thread(target=reader, args=(name, pipe), daemon=True)
                        t.start()
                        threads.append(t)
                started = dt.datetime.now()
                last_log = started
                output_lines: List[str] = []
                while proc.poll() is None:
                    try:
                        while True:
                            stream, line = q.get_nowait()
                            if line.strip():
                                output_lines.append(f"{stream}: {line}")
                                # Whisper CLI prints segment lines/progress to stderr.
                                self.log(f"whisper-cli {stream}: {line[:300]}")
                    except queue.Empty:
                        pass
                    elapsed = (dt.datetime.now() - started).total_seconds()
                    if elapsed > timeout:
                        proc.kill()
                        return "", f"whisper-cli:{model_name}", 0.0, "", False, f"Whisper CLI timed out after {timeout}s. Last output:\n" + "\n".join(output_lines[-40:])
                    if (dt.datetime.now() - last_log).total_seconds() >= 10:
                        self.log(f"whisper-cli heartbeat: still running, elapsed={elapsed:.0f}s, output_dir={out_dir}")
                        last_log = dt.datetime.now()
                    threading.Event().wait(0.15)
                # drain
                try:
                    while True:
                        stream, line = q.get_nowait()
                        if line.strip():
                            output_lines.append(f"{stream}: {line}")
                            self.log(f"whisper-cli {stream}: {line[:300]}")
                except queue.Empty:
                    pass
                if proc.returncode != 0:
                    return "", f"whisper-cli:{model_name}", 0.0, "", False, f"Whisper CLI failed returncode={proc.returncode}. Last output:\n" + "\n".join(output_lines[-80:])
                srt_files = list(out_dir.glob("*.srt"))
                if not srt_files:
                    return "", f"whisper-cli:{model_name}", 0.0, "", False, "Whisper CLI did not create SRT output. Last output:\n" + "\n".join(output_lines[-80:])
                text = srt_files[0].read_text(encoding="utf-8", errors="replace")
                return text, f"whisper-cli:{model_name}", 86.0, language or "", bool(text.strip()), ""
            except Exception:
                return "", f"whisper-cli:{model_name}", 0.0, "", False, traceback.format_exc()


class SpeakerDiarizer:
    """Real speaker diarization helper.

    Supported real inputs:
    - sidecar RTTM files next to evidence
    - pyannote.audio with a Hugging Face token

    It never invents names. It creates labels such as Speaker 1 / Speaker 2
    and lets the reviewer rename them in the Speakers tab.
    """
    def __init__(self, db: DB, log: Optional[Callable[[str], None]] = None):
        self.db = db
        self.log = log or (lambda msg: None)
        self.media = MediaTools(db, self.log)

    def enabled(self) -> bool:
        value = (self.db.setting("speaker_diarization_enabled", "auto") or "auto").lower()
        return value not in {"0", "false", "no", "disabled"}

    def sidecar_candidates(self, ev: Evidence) -> List[Path]:
        paths = []
        for base in [Path(ev.analysis_path), Path(ev.path) if ev.path else None]:
            if base:
                paths.extend([
                    base.with_suffix(".rttm"),
                    base.parent / f"{base.stem}.diarization.rttm",
                    base.parent / f"{base.stem}_diarization.rttm",
                    base.parent / f"{base.stem}.speakers.rttm",
                    base.parent / f"{base.stem}_speakers.rttm",
                ])
        seen = set()
        out = []
        for p in paths:
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    def find_sidecar_rttm(self, ev: Evidence) -> Optional[Path]:
        for p in self.sidecar_candidates(ev):
            if p.exists() and p.is_file():
                return p
        return None

    def parse_rttm(self, path: Path) -> List[Dict[str, Any]]:
        segments: List[Dict[str, Any]] = []
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 8 or parts[0].upper() != "SPEAKER":
                continue
            try:
                start = float(parts[3])
                dur = float(parts[4])
            except Exception:
                continue
            spk = parts[7]
            segments.append({
                "start_seconds": start,
                "end_seconds": start + dur,
                "speaker_label": spk,
                "role_label": spk,
                "confidence": 90.0,
                "source": f"sidecar-rttm:{path.name}",
                "raw": {"rttm": raw},
            })
        return self._normalize_segments(segments)

    def diarize(self, ev: Evidence) -> Tuple[List[Dict[str, Any]], str, bool]:
        if ev.type not in {"video", "audio"}:
            return [], "speaker diarization applies only to video/audio evidence", False
        if not self.enabled():
            return [], "speaker diarization disabled", False
        self.db.clear_speaker_segments(ev.id)
        rttm = self.find_sidecar_rttm(ev)
        if rttm:
            self.log(f"PASS found sidecar RTTM for evidence #{ev.id}: {rttm}")
            segments = self.parse_rttm(rttm)
            self._save_segments(ev.id, segments)
            return segments, f"sidecar-rttm:{rttm.name}", bool(segments)
        engine = (self.db.setting("speaker_diarization_engine", "pyannote") or "pyannote").lower()
        if engine in {"disabled", "0", "none", "sidecar-rttm"}:
            return [], "no sidecar RTTM found and pyannote disabled", False
        return self._pyannote(ev)

    def _token(self) -> str:
        return (self.db.setting("pyannote_auth_token", "") or os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN") or "").strip()

    def _load_waveform_tensor(self, wav_path: Path) -> Tuple[Any, int]:
        if not module_available("torch"):
            raise RuntimeError("torch is not installed")
        import torch  # type: ignore
        with wave.open(str(wav_path), "rb") as wf:
            channels = wf.getnchannels()
            sampwidth = wf.getsampwidth()
            rate = wf.getframerate()
            raw = wf.readframes(wf.getnframes())
        if sampwidth != 2:
            raise RuntimeError(f"Expected 16-bit PCM WAV from ffmpeg, got sample_width={sampwidth}")
        samples = struct.unpack("<" + "h" * (len(raw) // 2), raw)
        # ffmpeg extraction should be mono; if not, downmix by taking every channel frame average.
        if channels > 1:
            frames = []
            for i in range(0, len(samples), channels):
                frames.append(sum(samples[i:i+channels]) / float(channels))
            vals = [v / 32768.0 for v in frames]
        else:
            vals = [v / 32768.0 for v in samples]
        tensor = torch.tensor(vals, dtype=torch.float32).unsqueeze(0)
        return tensor, rate

    def _pyannote(self, ev: Evidence) -> Tuple[List[Dict[str, Any]], str, bool]:
        if not module_available("pyannote.audio"):
            return [], "pyannote.audio not installed. Install with: python -m pip install -U pyannote.audio torch", False
        token = self._token()
        if not token:
            return [], "pyannote Hugging Face token missing. Put it in Settings → pyannote_auth_token or HF_TOKEN.", False
        try:
            from pyannote.audio import Pipeline  # type: ignore
            import torch  # type: ignore
            model_name = self.db.setting("pyannote_model", "pyannote/speaker-diarization-3.1") or "pyannote/speaker-diarization-3.1"
            self.log(f"Loading pyannote pipeline: {model_name}")
            try:
                pipeline = Pipeline.from_pretrained(model_name, token=token)
            except TypeError:
                pipeline = Pipeline.from_pretrained(model_name, use_auth_token=token)
            device = self.db.setting("diarization_device", "cpu") or "cpu"
            try:
                pipeline.to(torch.device(device))
                self.log(f"PASS pyannote pipeline moved to device={device}")
            except Exception as e:
                self.log(f"WARN pyannote pipeline device move failed; continuing on default device: {e}")
            source_path = Path(ev.analysis_path)
            wav_path, wav_engine = self.media.extract_audio_wav(source_path, ev.id)
            if not wav_path:
                return [], f"pyannote audio extraction failed: {wav_engine}", False
            kwargs: Dict[str, Any] = {}
            num = clamp_int(self.db.setting("diarization_num_speakers", "0"), 0, 0, 50)
            mn = clamp_int(self.db.setting("diarization_min_speakers", "0"), 0, 0, 50)
            mx = clamp_int(self.db.setting("diarization_max_speakers", "0"), 0, 0, 50)
            if num > 0:
                kwargs["num_speakers"] = num
            else:
                if mn > 0:
                    kwargs["min_speakers"] = mn
                if mx > 0:
                    kwargs["max_speakers"] = mx
            self.log(f"Starting pyannote diarization; preload={self.db.setting('diarization_preload_audio','1')} kwargs={kwargs}")
            if self.db.setting("diarization_preload_audio", "1") == "1":
                waveform, sample_rate = self._load_waveform_tensor(wav_path)
                diarization = pipeline({"waveform": waveform, "sample_rate": sample_rate}, **kwargs)
            else:
                diarization = pipeline(str(wav_path), **kwargs)
            segments: List[Dict[str, Any]] = []
            for turn, _, speaker in diarization.itertracks(yield_label=True):
                start = float(getattr(turn, "start", 0.0) or 0.0)
                end = float(getattr(turn, "end", start) or start)
                segments.append({
                    "start_seconds": start,
                    "end_seconds": end,
                    "speaker_label": str(speaker),
                    "role_label": str(speaker),
                    "confidence": 80.0,
                    "source": f"pyannote:{model_name}",
                    "raw": {"start": start, "end": end, "speaker": str(speaker)},
                })
            segments = self._normalize_segments(segments)
            self._save_segments(ev.id, segments)
            self.log(f"PASS speaker diarization complete: {len(segments)} speaker segments")
            return segments, f"pyannote:{model_name}", bool(segments)
        except Exception:
            return [], "pyannote runtime failure:\n" + traceback.format_exc(), False

    def _normalize_segments(self, segments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not segments:
            return []
        pad = clamp_float(self.db.setting("diarization_boundary_padding", "0.30"), 0.30, 0.0, 5.0)
        min_len = clamp_float(self.db.setting("diarization_min_segment_seconds", "0.20"), 0.20, 0.0, 30.0)
        merge_gap = clamp_float(self.db.setting("diarization_merge_gap", "0.45"), 0.45, 0.0, 10.0)
        cleaned = []
        for seg in sorted(segments, key=lambda x: (float(x.get("start_seconds") or 0.0), float(x.get("end_seconds") or 0.0))):
            start = max(0.0, float(seg.get("start_seconds") or 0.0) - pad)
            end = max(start, float(seg.get("end_seconds") or start) + pad)
            if end - start < min_len:
                continue
            item = dict(seg)
            item["start_seconds"] = start
            item["end_seconds"] = end
            cleaned.append(item)
        merged: List[Dict[str, Any]] = []
        for seg in cleaned:
            if merged and seg.get("speaker_label") == merged[-1].get("speaker_label") and float(seg["start_seconds"]) - float(merged[-1]["end_seconds"]) <= merge_gap:
                merged[-1]["end_seconds"] = max(float(merged[-1]["end_seconds"]), float(seg["end_seconds"]))
            else:
                merged.append(seg)
        # Map arbitrary pyannote labels to stable Speaker 1, Speaker 2 unless the RTTM already uses readable labels.
        label_map: Dict[str, str] = {}
        for seg in merged:
            lab = str(seg.get("speaker_label") or "Speaker")
            if lab not in label_map:
                label_map[lab] = lab if re.match(r"^(Speaker|Officer|Subject|Civilian|Dispatch)\b", lab, re.I) else f"Speaker {len(label_map)+1}"
            seg["speaker_label"] = label_map[lab]
            seg["role_label"] = seg.get("role_label") or label_map[lab]
        return merged

    def _save_segments(self, eid: int, segments: List[Dict[str, Any]]) -> None:
        self.db.clear_speaker_segments(eid)
        for seg in segments:
            self.db.add_speaker_segment(
                eid,
                float(seg.get("start_seconds") or 0.0),
                float(seg.get("end_seconds") or 0.0),
                str(seg.get("speaker_label") or "Speaker"),
                str(seg.get("role_label") or seg.get("speaker_label") or "Speaker"),
                float(seg.get("confidence") or 0.0),
                str(seg.get("source") or "diarization"),
                seg.get("raw") if isinstance(seg.get("raw"), dict) else {"raw": seg.get("raw")},
            )

    def speaker_at(self, eid: int, t: Optional[float]) -> str:
        if t is None:
            return ""
        segments = self.db.speaker_segments(eid)
        best = ""
        tt = float(t)
        for seg in segments:
            if float(seg.get("start_seconds") or 0.0) <= tt <= float(seg.get("end_seconds") or 0.0):
                return str(seg.get("role_label") or seg.get("speaker_label") or "")
            # nearest within 0.75s
            dist = min(abs(tt - float(seg.get("start_seconds") or 0.0)), abs(tt - float(seg.get("end_seconds") or 0.0)))
            if dist <= 0.75 and not best:
                best = str(seg.get("role_label") or seg.get("speaker_label") or "")
        return best

    def label_transcript_text(self, eid: int, text: str) -> str:
        rows = parse_transcript(text)
        if not rows or not self.db.speaker_segments(eid):
            return text
        out: List[str] = []
        overwrite = self.db.setting("speaker_overwrite_existing_labels", "1") == "1"
        for row in rows:
            t = row.get("time_seconds")
            label = self.speaker_at(eid, t)
            existing = row.get("speaker") or ""
            speaker = label if label and (overwrite or not existing or existing.lower() == "speaker") else existing
            if t is not None:
                prefix = f"{fmt_time(t)} - "
            else:
                prefix = ""
            out.append(f"{prefix}{speaker + ': ' if speaker else ''}{row.get('text','')}")
        return "\n".join(out)



class RuleMatcher:
    def __init__(self, rules: Sequence[Dict[str, Any]]):
        self.rules: List[Tuple[Dict[str, Any], Optional[re.Pattern[str]]]] = []
        for rule in rules:
            if int(rule.get("enabled", 1) or 0) != 1:
                continue
            compiled: Optional[re.Pattern[str]] = None
            if rule.get("pattern_type", "regex") == "regex":
                try:
                    compiled = re.compile(str(rule.get("pattern", "")), re.I)
                except re.error:
                    compiled = None
            self.rules.append((rule, compiled))

    def match(self, text: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        low = (text or "").lower()
        for rule, compiled in self.rules:
            pattern = str(rule.get("pattern", "") or "")
            typ = rule.get("pattern_type", "regex") or "regex"
            ok = False
            excerpt = ""
            if typ == "regex" and compiled:
                m = compiled.search(text or "")
                ok = m is not None
                excerpt = m.group(0) if m else ""
            elif typ == "keywords":
                for kw in [x.strip().lower() for x in re.split(r"[,;\n]+", pattern) if x.strip()]:
                    if kw in low:
                        ok = True
                        excerpt = kw
                        break
            elif typ == "literal":
                ok = pattern.lower() in low
                excerpt = pattern if ok else ""
            if ok:
                item = dict(rule)
                item["excerpt"] = excerpt
                out.append(item)
        return out


class Analyzer:
    def __init__(self, db: DB, log: Optional[Callable[[str], None]] = None):
        self.db = db
        self.log = log or (lambda msg: None)
        self.text = TextExtractor(self.log)
        self.media = MediaTools(db, self.log)
        self.transcriber = Transcriber(db, self.log)
        self.diarizer = SpeakerDiarizer(db, self.log)

    def analyze(self, eid: int, refresh_global: bool = True) -> None:
        ev = self.db.evidence(eid)
        if not ev:
            raise ValueError(f"Evidence #{eid} not found")
        source_path = Path(ev.analysis_path)
        if not source_path.exists():
            self.db.update_evidence_status(eid, "failed")
            raise FileNotFoundError(f"Evidence file missing: {source_path}")
        self.log(f"Analyzing evidence #{eid}: {ev.display_name}")
        self.db.update_evidence_status(eid, "analyzing")
        self.db.clear_analysis(eid, keep_attached_transcripts=True)
        try:
            if ev.type in {"video", "audio"}:
                self._analyze_media(ev)
            elif ev.type in {"document", "transcript"}:
                self._analyze_document(ev)
            elif ev.type == "image":
                self._analyze_image(ev)
            else:
                self._analyze_other(ev)
            ok, old, current = self.db.verify_hash(eid)
            if not ok:
                self.db.add_issue(eid, "Evidence Integrity", "Critical", 99, "Evidence hash changed", "Current case evidence hash does not match the import-time hash.", f"Expected: {old}\nCurrent: {current}", "Use the original file or document exactly why the case-copy changed.")
            if self.db.latest_transcript(eid) is None and ev.type in {"video", "audio"}:
                self.db.update_evidence_status(eid, "analyzed-no-transcript")
            else:
                self.db.update_evidence_status(eid, "analyzed")
            self.db.audit("Evidence analyzed", f"#{eid} {ev.display_name}")
            if refresh_global:
                self.global_analysis()
        except Exception:
            self.db.update_evidence_status(eid, "failed")
            self.db.audit("Evidence analysis failed", f"#{eid} {ev.display_name}\n{traceback.format_exc()}")
            raise

    def _analyze_media(self, ev: Evidence) -> None:
        path = Path(ev.analysis_path)
        self.log(f"Media analysis start for evidence #{ev.id}: {ev.display_name}")
        probe_data, probe_engine = self.media.probe(path)
        self.db.add_media_analysis(ev.id, "metadata", f"Media metadata ({probe_engine})", probe_data, self.media.summarize_probe(probe_data))
        meta = ev.metadata
        meta["latest_probe_engine"] = probe_engine
        meta["latest_probe"] = probe_data
        self.db.update_evidence_metadata(ev.id, meta)
        summary = self.media.summarize_probe(probe_data)
        self.db.add_event(ev.id, None, ev.display_name, "", "Media Metadata", "Info", 90, summary, "media,metadata,real-data", created_by="media-probe", raw_text=summary, export_include=0)

        has_audio = ev.type == "audio" or self.media.has_audio_stream(probe_data)
        if ev.type == "video" and not has_audio:
            self.db.add_issue(ev.id, "Media Analysis", "Low", 70, "No audio stream detected", "ffprobe did not find an audio stream in this video. Transcript and audio-level analysis cannot be produced from this file.", self.media.summarize_probe(probe_data), "Verify the correct media file was imported or attach a transcript if audio exists elsewhere.")

        def run_transcription_and_speakers() -> None:
            if not has_audio:
                self.log(f"Skipping transcription for evidence #{ev.id}: no audio stream detected.")
                return
            self.log("Step 1/3: transcription/sidecar/attached transcript lookup.")
            text, engine, conf, language, ok = self.transcriber.transcribe(ev)
            if ok and text.strip():
                # Diarize before storing/timelining so transcript/timeline can include speakers.
                diarized_text = text
                if self.diarizer.enabled():
                    self.log("Step 2/3: speaker diarization. This uses sidecar RTTM or real pyannote only.")
                    segments, d_engine, d_ok = self.diarizer.diarize(ev)
                    if d_ok and segments:
                        self.db.add_media_analysis(ev.id, "speaker-diarization", f"Speaker diarization ({d_engine})", segments, f"{len(segments)} speaker segments detected/labeled.")
                        diarized_text = self.diarizer.label_transcript_text(ev.id, text)
                        self.log(f"PASS speaker labels applied to transcript: {len(segments)} segments")
                    else:
                        self.log(f"WARN speaker diarization unavailable/not applied: {d_engine}")
                        self.db.add_issue(ev.id, "Speaker Diarization", "Low", 60, "Speaker diarization unavailable/not applied", "Transcript was produced, but speaker diarization did not run successfully. Transcript text remains usable, but speaker turns may not be separated.", d_engine, "Install/configure pyannote.audio + token, fix dependency errors, or provide a sidecar RTTM file.")
                tid = self.db.add_transcript(ev.id, diarized_text, engine, ev.type, conf, language, attached=False)
                self.log(f"Transcript stored as record #{tid}; building timeline from real transcript.")
                self.timeline_from_text(ev, diarized_text, ev.type)
            else:
                self.db.add_issue(ev.id, "Transcription", "High" if ev.type == "video" else "Medium", 75, "No real transcript generated", "The media file was analyzed for real metadata/audio levels, but no transcript text was produced. No speech-content findings can be made from this media until a real transcript is attached or a local Whisper engine is installed/enabled.", engine, "Use Evidence → Attach Transcript to Selected, place a .txt/.srt/.vtt sidecar next to the media, or install/configure faster-whisper/openai-whisper/Whisper CLI.")

        def run_audio_levels() -> None:
            if not has_audio:
                return
            if self.db.setting("audio_analysis_enabled", "0") != "1":
                self.log("Audio-level waveform analysis skipped by setting audio_analysis_enabled=0. This keeps huge video analysis fast.")
                return
            self.log("Step 3/3: real audio-level / peak analysis.")
            wav_path, engine = self.media.extract_audio_wav(path, ev.id)
            if wav_path:
                window = clamp_float(self.db.setting("audio_window_seconds", "1.0"), 1.0, 0.1, 10.0)
                audio_data, msg = self.media.analyze_wav_levels(wav_path, window)
                if audio_data:
                    audio_data["audio_extraction_engine"] = engine
                    self.db.add_media_analysis(ev.id, "audio-levels", "Audio level / peak analysis", audio_data, self._audio_summary(audio_data))
                    self._timeline_from_audio_levels(ev, audio_data)
                    self.log(f"PASS audio-level analysis complete: {audio_data.get('window_count')} windows")
                else:
                    self.db.add_issue(ev.id, "Audio Analysis", "Medium", 70, "Audio level analysis failed", msg, engine, "Check whether the file contains readable audio and whether ffmpeg can decode it.")
                    self.log(f"FAIL audio-level analysis: {msg}")
            else:
                self.db.add_issue(ev.id, "Audio Analysis", "Medium", 70, "Audio extraction unavailable", engine, "", "Install ffmpeg or set the correct ffmpeg_path in Settings.")
                self.log(f"FAIL audio extraction unavailable: {engine}")

        if self.db.setting("fast_transcription_first", "1") == "1":
            run_transcription_and_speakers()
            run_audio_levels()
        else:
            run_audio_levels()
            run_transcription_and_speakers()
        self.log(f"Media analysis finished for evidence #{ev.id}: {ev.display_name}")

    def _audio_summary(self, data: Dict[str, Any]) -> str:
        duration = data.get("duration_text") or fmt_time(data.get("duration_seconds"))
        lines = [
            f"Duration: {duration}",
            f"Sample rate: {data.get('sample_rate')} Hz",
            f"Analysis window: {data.get('window_seconds')} seconds",
            f"Windows analyzed: {data.get('window_count')}",
            f"Max RMS: {data.get('max_rms'):.6f}" if isinstance(data.get("max_rms"), (int, float)) else "Max RMS: n/a",
            f"Median RMS: {data.get('median_rms'):.6f}" if isinstance(data.get("median_rms"), (int, float)) else "Median RMS: n/a",
        ]
        return "\n".join(lines)

    def _timeline_from_audio_levels(self, ev: Evidence, data: Dict[str, Any]) -> None:
        peak_count = clamp_int(self.db.setting("audio_peak_count", "12"), 12, 0, 100)
        peaks = self.media.top_audio_peaks(data, peak_count)
        max_rms = float(data.get("max_rms", 0.0) or 0.0)
        median = float(data.get("median_rms", 0.0) or 0.0)
        for p in peaks:
            rms = float(p.get("rms", 0.0) or 0.0)
            ratio = rms / max(max_rms, 1e-12)
            severity = "Medium" if ratio >= 0.70 and rms > median * 2 else "Low"
            desc = f"Audio peak at {p.get('time_text')} | RMS={rms:.6f} | peak={float(p.get('peak',0.0)):.6f} | dBFS={float(p.get('dbfs',-999.0)):.1f}. This is a real audio-level event, not a force conclusion."
            self.db.add_event(ev.id, p.get("start_seconds"), ev.display_name, "", "Audio Peak", severity, 72, desc, "audio,peak,real-data", created_by="audio-analysis", raw_text=desc, export_include=0)
        min_silence = clamp_float(self.db.setting("audio_silence_min_seconds", "2.0"), 2.0, 0.5, 60.0)
        for rng in self.media.silence_ranges(data, min_silence)[:25]:
            desc = f"Low-audio/silence interval from {fmt_time(rng['start_seconds'])} to {fmt_time(rng['end_seconds'])} ({rng['duration_seconds']:.1f}s)."
            self.db.add_event(ev.id, rng["start_seconds"], ev.display_name, "", "Audio Silence", "Info", 70, desc, "audio,silence,real-data", created_by="audio-analysis", raw_text=desc, export_include=0)

    def _analyze_document(self, ev: Evidence) -> None:
        text, engine, ok = self.text.extract(Path(ev.analysis_path))
        if not ok or not text.strip():
            self.db.add_issue(ev.id, "Document Extraction", "High", 80, "No document text extracted", f"Extractor result: {engine}", "", "Provide a text/OCR version, install the needed extractor, or attach a transcript/report as TXT/SRT/VTT.")
            raise RuntimeError(f"No text extracted from {ev.display_name}: {engine}")
        kind = "transcript" if ev.type == "transcript" else "document"
        self.db.add_transcript(ev.id, text, engine, kind, 90 if ev.type == "transcript" else 85)
        self.timeline_from_text(ev, text, kind)
        self.report_analysis(ev, text)

    def _analyze_image(self, ev: Evidence) -> None:
        path = Path(ev.analysis_path)
        meta = {
            "file_name": path.name,
            "size_bytes": path.stat().st_size if path.exists() else None,
            "mime": mimetypes.guess_type(str(path))[0] or "",
        }
        try:
            if importlib.util.find_spec("PIL"):
                from PIL import Image  # type: ignore
                with Image.open(path) as im:
                    meta["format"] = im.format
                    meta["width"] = im.width
                    meta["height"] = im.height
                    meta["mode"] = im.mode
        except Exception as e:
            meta["image_metadata_error"] = str(e)
        self.db.add_media_analysis(ev.id, "image-metadata", "Image metadata", meta, short_json(meta, max_chars=3000))
        desc = f"Image metadata extracted: {short_json(meta, max_chars=1200)}"
        self.db.add_event(ev.id, None, ev.display_name, "", "Image Metadata", "Info", 90, desc, "image,metadata,real-data", created_by="image-analysis", raw_text=desc, export_include=0)
        # Optional real OCR only if libraries are installed.
        try:
            if importlib.util.find_spec("pytesseract") and importlib.util.find_spec("PIL"):
                from PIL import Image  # type: ignore
                import pytesseract  # type: ignore
                with Image.open(path) as im:
                    ocr_text = pytesseract.image_to_string(im)
                if ocr_text.strip():
                    self.db.add_transcript(ev.id, ocr_text, "pytesseract", "image-ocr", 70)
                    self.timeline_from_text(ev, ocr_text, "image-ocr")
                else:
                    self.db.add_issue(ev.id, "Image OCR", "Low", 60, "OCR produced no text", "pytesseract ran but did not extract text from the image.", "", "Manually review the image or attach a text note if needed.")
            else:
                self.db.add_issue(ev.id, "Image OCR", "Low", 50, "Image OCR not installed", "Image metadata was extracted, but OCR requires Pillow + pytesseract + Tesseract installed on the system.", "", "Install OCR dependencies if text extraction from images is required.")
        except Exception as e:
            self.db.add_issue(ev.id, "Image OCR", "Medium", 60, "Image OCR failed", str(e), "", "Check the image and Tesseract installation.")

    def _analyze_other(self, ev: Evidence) -> None:
        path = Path(ev.analysis_path)
        info = {
            "file_name": path.name,
            "size_bytes": path.stat().st_size if path.exists() else None,
            "extension": path.suffix,
            "mime": mimetypes.guess_type(str(path))[0] or "",
        }
        self.db.add_media_analysis(ev.id, "file-metadata", "File metadata", info, short_json(info, max_chars=2000))
        desc = "File metadata/hash recorded. This file type has no built-in automated extractor."
        self.db.add_event(ev.id, None, ev.display_name, "", "Evidence Metadata", "Info", 80, desc, "metadata,real-data", created_by="file-analysis", raw_text=short_json(info), export_include=0)

    def timeline_from_text(self, ev: Evidence, content: str, source_kind: str) -> None:
        matcher = RuleMatcher(self.db.rules(enabled_only=True))
        rows = parse_transcript(content)
        if not rows:
            rows = [{"time_seconds": None, "time_text": "--:--", "speaker": "", "text": chunk, "raw": chunk} for chunk in split_plain_text_lines(content)]
        store_all = self.db.setting("store_nonflag_transcript_lines", "1") == "1"
        priority = ["Use of Force", "Medical Distress", "Force Warning", "Resistance Dispute", "Resistance Claim", "Weapon Claim", "Rights / Detention", "Command", "Report Language", "De-escalation"]
        for row in rows:
            text = norm_text(str(row.get("text", "")))
            if not text:
                continue
            matches = matcher.match(text)
            if not matches and not store_all:
                continue
            categories = [m.get("category", "Transcript") for m in matches] or (["Document Text"] if source_kind in {"document", "image-ocr"} else ["Transcript"])
            category = next((p for p in priority if p in categories), categories[0])
            severity = severity_max([m.get("severity", "Info") for m in matches] or ["Info"])
            confidence = max([float(m.get("confidence", 70)) for m in matches], default=72)
            tags = sorted({tok.strip() for m in matches for tok in str(m.get("tags", "")).split(",") if tok.strip()})
            if not tags:
                tags = [source_kind, "real-text"]
            desc = text
            if category == "Use of Force":
                desc = "POSSIBLE MOMENT OF FORCE: " + text
            elif category in {"Medical Distress", "Resistance Claim", "Resistance Dispute", "Weapon Claim", "Force Warning", "Rights / Detention"}:
                desc = f"{category}: {text}"
            self.db.add_event(
                ev.id,
                row.get("time_seconds"),
                ev.display_name,
                str(row.get("speaker", "") or ""),
                category,
                severity,
                confidence,
                desc,
                ",".join(tags),
                created_by="rules-engine" if matches else "transcript-loader",
                raw_text=str(row.get("raw", text)),
                export_include=1 if matches else 0,
            )

    def report_analysis(self, ev: Evidence, text: str) -> None:
        low = text.lower()
        loaded = sorted(set(re.findall(r"\b(agitated|combative|furtive|non[-\s]?compliant|appeared\s+nervous|feared\s+for\s+(?:my|our|officer)\s+safety|high\s+crime\s+area|reached\s+for\s+waistband|unknown\s+object|aggressive|belligerent|threatening|furtive\s+movement)\b", low)))
        if loaded:
            self.db.add_issue(ev.id, "Report Language", "Medium", 77, "Report contains narrative-risk language", "The document uses conclusion-heavy or subjective terms that should be compared against objective audio/video evidence before being treated as established.", ", ".join(loaded), "Compare each term against timestamped source media and mark it confirmed, disputed, or unsupported.")
        if re.search(r"\b(force\s+(?:was\s+)?(?:required|used|applied)|used\s+force|physical\s+force|taser\s+was\s+deployed|deployed\s+(?:my\s+)?taser|less\s*lethal\s+deployed)\b", low):
            force = self.force_moment()
            if force:
                self.db.add_issue(ev.id, "Report vs Timeline", "High", 84, "Report force claim should be checked against detected force moment", f"The report references force. Earliest detected force moment currently appears at {force.get('event_time_text')} from {force.get('source_name')}.", self.excerpt(text, ["force", "taser", "physical", "less lethal"]), "Open the Force Moment tab and confirm the exact source timestamp/frame/audio context.", force.get("id"))
            else:
                self.db.add_issue(ev.id, "Report vs Timeline", "High", 80, "Report references force but no timestamped force event is detected", "The document references force, but the timeline does not yet contain a matching timestamped force event from media/transcript evidence.", self.excerpt(text, ["force", "taser", "physical", "less lethal"]), "Attach/import timestamped transcript, analyze media with real transcription, or manually mark the force moment.")
        if re.search(r"\b(reached\s+for\s+waistband|gun|firearm|knife|weapon|armed)\b", low):
            self.db.add_issue(ev.id, "Weapon Claim Review", "High", 80, "Weapon-related report claim needs source comparison", "The report contains weapon-related language. It should be checked against 911 audio, radio traffic, bodycam, and recovered-evidence documentation.", self.excerpt(text, ["weapon", "gun", "firearm", "knife", "waistband", "armed"]), "Compare certainty level in the report against source statements such as 'think', 'maybe', 'unknown', and recovered evidence.")

    def excerpt(self, text: str, terms: Sequence[str], radius: int = 220) -> str:
        low = text.lower()
        positions = [low.find(t.lower()) for t in terms if low.find(t.lower()) >= 0]
        pos = min(positions) if positions else 0
        return norm_text(text[max(0, pos - radius):pos + radius])

    def force_moment(self) -> Optional[Dict[str, Any]]:
        actual_force_pattern = re.compile(DEFAULT_RULES[0]["pattern"], re.I)
        candidates: List[Dict[str, Any]] = []
        for event in self.db.events():
            category = str(event.get("category") or "").strip().lower()
            tags = {tok.strip().lower() for tok in str(event.get("tags") or "").split(",") if tok.strip()}
            desc = str(event.get("description") or "")
            is_actual_force = (
                category == "use of force"
                or "moment-of-force" in tags
                or "physical-force" in tags
                or ("force" in tags and "force-warning" not in tags and "pre-force" not in tags)
                or bool(actual_force_pattern.search(desc))
            )
            if category == "force warning" or "force-warning" in tags or "pre-force" in tags:
                # A warning can be context but is not the physical force moment.
                if not ("moment-of-force" in tags or "physical-force" in tags):
                    is_actual_force = False
            if is_actual_force:
                candidates.append(event)
        if not candidates:
            return None
        candidates.sort(key=lambda e: (999999999 if e.get("event_time_seconds") is None else float(e.get("event_time_seconds")), int(e.get("id") or 0)))
        return candidates[0]

    def global_analysis(self) -> None:
        self.db.clear_global_issues()
        events = self.db.events()
        force = self.force_moment()
        if force:
            self._force_context_analysis(force, events)
        else:
            report_text = "\n".join(t.get("content", "") for t in self.db.transcripts() if t.get("source_kind") == "document")
            if re.search(r"\b(force|taser|less\s*lethal|pepper\s+spray|baton|shots?\s+fired)\b", report_text, re.I):
                self.db.add_issue(None, "Global Force Review", "High", 78, "Force language exists but no force moment is detected", "At least one document/transcript contains force-related language, but the system has no timestamped actual-force event yet.", self.excerpt(report_text, ["force", "taser", "less lethal", "spray", "baton", "shots fired"]), "Attach/import timestamped media transcripts or manually mark the exact force moment.")
        self.cross_source_analysis()
        self.db.audit("Global analysis refreshed", "force context and cross-source checks")

    def _force_context_analysis(self, force: Dict[str, Any], events: List[Dict[str, Any]]) -> None:
        ft = force.get("event_time_seconds")
        if ft is None:
            self.db.add_issue(None, "Global Force Review", "High", 82, "Use-of-force event lacks timestamp", "A likely force event exists, but it has no precise timestamp.", force.get("description", ""), "Manually set the timestamp or attach a timestamped transcript.", force.get("id"))
            return
        ft = float(ft)
        window = clamp_float(self.db.setting("analysis_window_seconds", "10"), 10.0, 1.0, 120.0)
        before = [e for e in events if e.get("event_time_seconds") is not None and e.get("id") != force.get("id") and 0 <= ft - float(e.get("event_time_seconds")) <= window]
        after = [e for e in events if e.get("event_time_seconds") is not None and e.get("id") != force.get("id") and 0 <= float(e.get("event_time_seconds")) - ft <= window]
        commands = [e for e in before if e.get("category") == "Command"]
        warnings = [e for e in before if e.get("category") == "Force Warning"]
        claims = [e for e in before if e.get("category") == "Resistance Claim"]
        disputes = [e for e in before + after if e.get("category") == "Resistance Dispute"]
        medical = [e for e in after if e.get("category") == "Medical Distress"]
        if commands:
            first = min(commands, key=lambda e: float(e.get("event_time_seconds") or ft))
            delta = ft - float(first.get("event_time_seconds") or ft)
            severity = "Critical" if delta <= 3 else "High"
            self.db.add_issue(None, "Global Force Review", severity, 88, "Command-to-force timing needs review", f"Earliest detected actual force occurs about {delta:.1f} seconds after a command inside the configured {window:.0f}-second review window.", f"Command: {first.get('event_time_text')} {first.get('description')}\nForce: {force.get('event_time_text')} {force.get('description')}", "Review footage to assess whether there was a meaningful opportunity to comply and whether intervening facts justified escalation.", force.get("id"))
        if warnings:
            self.db.add_issue(None, "Global Force Review", "High", 86, "Pre-force warning detected before force", "A force warning/announcement appears shortly before the detected force moment.", "\n".join(f"{e.get('event_time_text')} {e.get('description')}" for e in warnings[:5]), "Confirm the warning, elapsed time, subject behavior, and whether the warning was audible/understandable.", force.get("id"))
        if claims and disputes:
            self.db.add_issue(None, "Global Force Review", "High", 87, "Resistance claim and denial near force", "A resistance claim and a denial/dispute occur near the detected force moment.", "\n".join(f"{e.get('event_time_text')} {e.get('description')}" for e in (claims[:3] + disputes[:3])), "Verify body position, hand visibility, commands, and report wording against the video.", force.get("id"))
        if medical:
            self.db.add_issue(None, "Global Force Review", "Critical", 91, "Medical distress follows force", "A medical distress indicator appears shortly after the detected force event.", "\n".join(f"{e.get('event_time_text')} {e.get('description')}" for e in medical[:5]), "Review restraint position, medical aid, EMS notification, and response time.", force.get("id"))
        context_bits = []
        for label, seq in [("commands before force", commands), ("warnings", warnings), ("resistance claims", claims), ("resistance disputes", disputes), ("medical distress after force", medical)]:
            if seq:
                context_bits.append(f"{label}: {len(seq)}")
        self.db.add_issue(None, "Global Force Review", "High", 93, "Earliest detected actual force moment", f"Earliest detected actual force event is {force.get('event_time_text')} in {force.get('source_name')}. " + ("; ".join(context_bits) if context_bits else "No nearby context flags found."), force.get("description", ""), "Human reviewer should confirm the exact frame/audio moment and add notes.", force.get("id"))

    def source_examples(self, terms: Sequence[str], source_filter: Optional[Iterable[str]] = None, limit: int = 8, radius: int = 180) -> str:
        filters = set(source_filter or [])
        examples: List[str] = []
        for tr in self.db.transcripts():
            if filters and tr.get("source_kind") not in filters:
                continue
            content = tr.get("content") or ""
            rows = parse_transcript(content)
            ev = self.db.evidence(int(tr.get("evidence_id") or 0)) if tr.get("evidence_id") else None
            source_name = ev.display_name if ev else f"Transcript #{tr.get('id')}"
            for row in rows or [{"text": chunk, "time_text": "--:--", "speaker": ""} for chunk in split_plain_text_lines(content)]:
                txt = str(row.get("text") or "")
                low = txt.lower()
                if any(t.lower() in low for t in terms):
                    speaker = (str(row.get("speaker") or "") + ": ") if row.get("speaker") else ""
                    examples.append(f"SOURCE: {source_name} ({tr.get('source_kind')}) @ {row.get('time_text') or '--:--'}\nQUOTE: {speaker}{txt}")
                    if len(examples) >= limit:
                        return "\n\n".join(examples)
            # fallback excerpt for nonparsed text
            if not rows:
                lowc = content.lower()
                positions = [lowc.find(t.lower()) for t in terms if lowc.find(t.lower()) >= 0]
                if positions:
                    pos = min(positions)
                    examples.append(f"SOURCE: {source_name} ({tr.get('source_kind')})\nQUOTE: {norm_text(content[max(0,pos-radius):pos+radius])}")
                    if len(examples) >= limit:
                        return "\n\n".join(examples)
        return "No exact source examples found after secondary scan."

    def cross_source_analysis(self) -> None:
        transcripts = self.db.transcripts()
        report_text = "\n".join(t.get("content", "") or "" for t in transcripts if t.get("source_kind") == "document").lower()
        media_text = "\n".join(t.get("content", "") or "" for t in transcripts if t.get("source_kind") in {"video", "audio", "transcript", "attached-transcript", "image-ocr"}).lower()
        all_text = "\n".join(t.get("content", "") or "" for t in transcripts).lower()
        uncertainty_terms = ["i think", "maybe", "possibly", "unknown", "not sure", "could be"]
        weapon_terms = ["gun", "weapon", "armed", "knife", "firearm"]
        if re.search(r"\b(i\s+think|maybe|possibly|unknown|not\s+sure|could\s+be)\b", all_text) and re.search(r"\b(gun|weapon|armed|knife|firearm)\b", all_text):
            examples = self.source_examples(uncertainty_terms + weapon_terms, limit=10)
            self.db.add_issue(None, "Cross-Source", "Medium", 76, "Uncertainty language appears near weapon information", "One or more sources include uncertainty language and weapon-related terms. Later narratives should not be treated as more certain without source support.", examples, "Compare caller/radio/bodycam certainty against report certainty and recovered evidence.")
        if report_text and media_text:
            if re.search(r"\b(agitated|combative|aggressive|belligerent|threatening)\b", report_text) and not re.search(r"\b(threaten|kill|hit\s+you|screaming|yelling|aggressive|belligerent)\b", media_text):
                report_examples = self.source_examples(["agitated", "combative", "aggressive", "belligerent", "threatening"], source_filter={"document"}, limit=5)
                media_examples = self.source_examples(["calm", "what did i do", "i'm not", "not resisting", "why"], source_filter={"video", "audio", "attached-transcript", "transcript"}, limit=5)
                self.db.add_issue(None, "Report vs Media", "High", 82, "Report aggression language not reflected in transcript keywords", "Report uses aggression-related language, but analyzed media transcript lacks common matching threat/aggression terms. This does not rule out nonverbal behavior, but it requires video review.", f"REPORT EXAMPLES:\n{report_examples}\n\nMEDIA SCAN EXAMPLES:\n{media_examples}", "Review actual video for nonverbal behavior before treating the report wording as supported.")
            if re.search(r"\b(non[-\s]?compliant|refused|would\s+not\s+comply)\b", report_text) and re.search(r"\b(what\s+did\s+i\s+do|why\s+am\s+i\s+being\s+detained|i(?:'|’)?m\s+not\s+resisting)\b", media_text):
                report_examples = self.source_examples(["non-compliant", "non compliant", "refused", "would not comply"], source_filter={"document"}, limit=5)
                media_examples = self.source_examples(["what did i do", "why am i being detained", "i'm not resisting", "not resisting"], source_filter={"video", "audio", "attached-transcript", "transcript"}, limit=8)
                self.db.add_issue(None, "Report vs Media", "High", 84, "Non-compliance narrative intersects with subject dispute", "Report/document non-compliance language appears while media transcript contains subject dispute/denial language.", f"REPORT EXAMPLES:\n{report_examples}\n\nMEDIA EXAMPLES:\n{media_examples}", "Compare commands, timing, audibility, and physical behavior in video.")


class SummaryBuilder:
    def __init__(self, db: DB):
        self.db = db

    def make(self, mode: str = "Internal Review") -> str:
        info = self.db.case_info()
        stats = self.db.stats()
        analyzer = Analyzer(self.db)
        force = analyzer.force_moment()
        issues = self.db.issues()
        lines = [
            mode,
            "=" * len(mode),
            f"Case: {info.get('title', 'Untitled Case')}",
            f"Agency: {info.get('agency', '')}",
            f"Incident date: {info.get('incident_date', '')}",
            f"Location: {info.get('location', '')}",
            f"Generated: {now()}",
            "",
            "Review-aid disclaimer: automated/rules-based findings are not final legal or factual conclusions. Human verification against source evidence is required.",
            "",
            "Case status",
            "-----------",
            f"Evidence files: {stats['evidence']} | analyzed: {stats['analyzed']} | pending: {stats['pending']} | failed: {stats['failed']}",
            f"Transcripts: {stats['transcripts']} | media analyses: {stats['media_analysis']} | speaker segments: {stats.get('speaker_segments', 0)} | timeline events: {stats['events']} | review issues: {stats['issues']}",
            f"High events: {stats['high_events']} | critical events: {stats['critical_events']} | force events: {stats['force_events']} | human-confirmed events: {stats['confirmed_events']}",
            "",
            "Detected moment of force",
            "------------------------",
        ]
        if force:
            lines.extend([
                f"Earliest detected actual force event: {force.get('event_time_text')} | Source: {force.get('source_name')} | Severity: {force.get('severity')} | Confidence: {force.get('confidence')}%",
                f"Description: {force.get('description')}",
                "Reviewer action: confirm the exact frame/audio moment and add notes.",
            ])
        else:
            lines.append("No actual force moment has been detected. Analyze timestamped transcripts or manually mark the exact force event.")
        lines.append("")
        lines.extend(["Top review issues", "-----------------"])
        if not issues:
            lines.append("No review issues recorded.")
        for idx, issue in enumerate(issues[:15], 1):
            lines.append(f"{idx}. [{issue.get('severity')}] {issue.get('title')} — {issue.get('description')}")
        lines.append("")
        lower = mode.lower()
        if "force" in lower:
            lines.extend(["Force context window", "--------------------"])
            if force and force.get("event_time_seconds") is not None:
                t = float(force["event_time_seconds"])
                nearby = [e for e in self.db.events() if e.get("event_time_seconds") is not None and abs(float(e["event_time_seconds"]) - t) <= 20]
                for e in nearby:
                    marker = " <-- DETECTED FORCE" if e.get("id") == force.get("id") else ""
                    lines.append(f"- {e.get('event_time_text')} [{e.get('category')}] {e.get('description')}{marker}")
            else:
                lines.append("No timestamped force context available.")
        elif "attorney" in lower:
            lines.extend([
                "Attorney review focus",
                "---------------------",
                "- Verify commands, timing, compliance opportunity, and intervening facts before force.",
                "- Compare report claims against source media and timestamped transcript excerpts.",
                "- Verify whether medical distress indicators were recognized and handled promptly.",
                "- Distinguish uncertain caller/radio claims from definitive report language.",
            ])
        elif "public" in lower:
            lines.extend(["Public-facing notes", "-------------------", "Use cautious wording: potential issue, apparent timing, requires verification, and source review."])
        else:
            lines.extend(["Timeline highlights", "-------------------"])
            highlights = [e for e in self.db.events() if SEVERITY_SCORE.get(e.get("severity", "Info"), 0) >= 3][:20]
            if not highlights:
                highlights = self.db.events()[:12]
            for e in highlights:
                lines.append(f"- {e.get('event_time_text')} [{e.get('severity')}] {e.get('category')}: {e.get('description')}")
        text = "\n".join(lines)
        if "public" in lower and self.db.setting("redact_public_exports", "1") == "1":
            text = redact_public_text(text)
        return text


class Exporter:
    def __init__(self, db: DB):
        self.db = db

    def _default_dir(self) -> Path:
        configured = self.db.setting("export_folder", "").strip()
        d = Path(configured).expanduser() if configured else self.db.exports_dir
        d.mkdir(parents=True, exist_ok=True)
        return d

    def default_path(self, suffix: str, label: str) -> Path:
        title = safe_name(self.db.case_info().get("title", "case"), "case")
        stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
        return self._default_dir() / f"{title}_{label}_{stamp}.{suffix}"

    def json_export(self, path: Path) -> Path:
        path.write_text(json.dumps(self.db.export_data(), indent=2, ensure_ascii=False), encoding="utf-8")
        self.db.audit("Export JSON", str(path))
        return path

    def timeline_csv(self, path: Path) -> Path:
        cols = ["id", "event_time_text", "event_time_seconds", "source_name", "speaker", "category", "severity", "confidence", "description", "tags", "review_status", "reviewer_notes", "created_by"]
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=cols)
            writer.writeheader()
            for row in self.db.events():
                writer.writerow({c: row.get(c, "") for c in cols})
        self.db.audit("Export timeline CSV", str(path))
        return path

    def issues_csv(self, path: Path) -> Path:
        cols = ["id", "category", "severity", "confidence", "title", "description", "evidence_quote", "recommendation", "review_status", "reviewer_notes", "related_event_id"]
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=cols)
            writer.writeheader()
            for row in self.db.issues():
                writer.writerow({c: row.get(c, "") for c in cols})
        self.db.audit("Export issues CSV", str(path))
        return path

    def summary_txt(self, path: Path, mode: str) -> Path:
        path.write_text(SummaryBuilder(self.db).make(mode), encoding="utf-8")
        self.db.audit("Export summary TXT", str(path))
        return path

    def _html_table(self, rows: Sequence[Dict[str, Any]], cols: Sequence[str], redact: bool = False) -> str:
        if not rows:
            return "<p><em>No rows.</em></p>"
        parts = ["<table><thead><tr>"]
        for col in cols:
            parts.append(f"<th>{html.escape(col.replace('_', ' ').title())}</th>")
        parts.append("</tr></thead><tbody>")
        for row in rows:
            parts.append("<tr>")
            for col in cols:
                value = str(row.get(col, ""))
                if redact:
                    value = redact_public_text(value)
                parts.append(f"<td>{html.escape(value)}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table>")
        return "\n".join(parts)

    def html_report(self, path: Path, mode: str = "Internal Review", public: bool = False) -> Path:
        info = self.db.case_info()
        stats = self.db.stats()
        title = info.get("title", "Untitled Case")
        if public:
            title = redact_public_text(title)
        evidence_rows = []
        for ev in self.db.evidences():
            evidence_rows.append({
                "id": ev.id,
                "display_name": ev.display_name,
                "type": ev.type,
                "size": human_size(ev.size),
                "sha256": ev.sha256,
                "imported_at": pretty_date(ev.imported_at),
                "status": ev.status,
            })
        summary = SummaryBuilder(self.db).make(mode)
        if public:
            summary = redact_public_text(summary)
        css = """
            body{font-family:Arial,Helvetica,sans-serif;margin:32px;line-height:1.45;color:#1f2937}
            table{border-collapse:collapse;width:100%;font-size:13px;margin:12px 0 24px}
            th,td{border:1px solid #cfd8e3;padding:6px;vertical-align:top}
            th{background:#eef2ff;text-align:left}
            pre{white-space:pre-wrap;background:#f8fafc;padding:12px;border:1px solid #e2e8f0;border-radius:6px}
            .note{background:#fff7ed;border:1px solid #fdba74;padding:12px;border-radius:6px}
            .small{color:#475569;font-size:12px}
        """
        doc = f"""<!doctype html><html><head><meta charset="utf-8"><title>{html.escape(title)}</title><style>{css}</style></head><body>
<h1>{html.escape(title)}</h1>
<p class="note"><b>Review-aid disclaimer:</b> Automated/rules-based findings require human verification against source evidence. This report does not make final legal or factual conclusions.</p>
<p class="small">Generated: {html.escape(now())} | App: {APP_NAME} {APP_VERSION} | Mode: {html.escape(mode)}</p>
<p>Evidence: {stats['evidence']} | Analyzed: {stats['analyzed']} | Transcripts: {stats['transcripts']} | Timeline events: {stats['events']} | Issues: {stats['issues']} | Force events: {stats['force_events']}</p>
<h2>Summary</h2><pre>{html.escape(summary)}</pre>
<h2>Evidence Manifest</h2>{self._html_table(evidence_rows, ['id','display_name','type','size','sha256','imported_at','status'], public)}
<h2>Unified Timeline</h2>{self._html_table(self.db.events(export_only=True), ['id','event_time_text','source_name','speaker','category','severity','confidence','description','tags','review_status','reviewer_notes'], public)}
<h2>Review Issues / Inconsistencies</h2>{self._html_table(self.db.issues(), ['id','category','severity','confidence','title','description','evidence_quote','recommendation','review_status','reviewer_notes'], public)}
<h2>Audit Log</h2>{self._html_table(self.db.audits(500), ['id','created_at','actor','action','detail'], public)}
</body></html>"""
        path.write_text(doc, encoding="utf-8")
        self.db.audit("Export HTML report", str(path))
        return path

    def zip_packet(self, path: Path, mode: str = "Attorney Review", public: bool = False) -> Path:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            self.json_export(tmp / "case_data.json")
            self.timeline_csv(tmp / "timeline.csv")
            self.issues_csv(tmp / "issues.csv")
            self.summary_txt(tmp / "summary.txt", mode)
            self.html_report(tmp / "report.html", mode, public)
            manifest = []
            for ev in self.db.evidences():
                manifest.append({
                    "id": ev.id,
                    "display_name": ev.display_name,
                    "original_path": ev.path,
                    "case_copy": ev.copied_path,
                    "sha256": ev.sha256,
                    "size": ev.size,
                    "status": ev.status,
                })
            (tmp / "evidence_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
                for item in tmp.iterdir():
                    z.write(item, item.name)
        self.db.audit("Export ZIP packet", str(path))
        return path


class RuleEditor(tk.Toplevel):
    def __init__(self, parent: tk.Widget, initial: Optional[Dict[str, Any]] = None):
        super().__init__(parent)
        self.title("Rule Editor")
        self.geometry("760x560")
        self.result: Optional[Dict[str, Any]] = None
        data = initial or {}
        self.vars = {
            "name": tk.StringVar(value=str(data.get("name", ""))),
            "enabled": tk.IntVar(value=int(data.get("enabled", 1) or 0)),
            "pattern_type": tk.StringVar(value=str(data.get("pattern_type", "regex"))),
            "category": tk.StringVar(value=str(data.get("category", "Custom"))),
            "severity": tk.StringVar(value=str(data.get("severity", "Medium"))),
            "tags": tk.StringVar(value=str(data.get("tags", "custom"))),
            "confidence": tk.StringVar(value=str(data.get("confidence", 75))),
        }
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill="both", expand=True)
        frame.columnconfigure(1, weight=1)
        row = 0
        for label, key in [("Name", "name"), ("Category", "category"), ("Tags CSV", "tags"), ("Confidence", "confidence")]:
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=3)
            ttk.Entry(frame, textvariable=self.vars[key]).grid(row=row, column=1, sticky="ew", pady=3, padx=5)
            row += 1
        ttk.Label(frame, text="Pattern Type").grid(row=row, column=0, sticky="w", pady=3)
        ttk.Combobox(frame, textvariable=self.vars["pattern_type"], values=["regex", "keywords", "literal"], state="readonly").grid(row=row, column=1, sticky="ew", pady=3, padx=5)
        row += 1
        ttk.Label(frame, text="Severity").grid(row=row, column=0, sticky="w", pady=3)
        ttk.Combobox(frame, textvariable=self.vars["severity"], values=SEVERITY_LEVELS, state="readonly").grid(row=row, column=1, sticky="ew", pady=3, padx=5)
        row += 1
        ttk.Checkbutton(frame, text="Enabled", variable=self.vars["enabled"]).grid(row=row, column=1, sticky="w", pady=3)
        row += 1
        ttk.Label(frame, text="Pattern").grid(row=row, column=0, sticky="nw", pady=3)
        self.pattern = scrolledtext.ScrolledText(frame, height=7, wrap="word")
        self.pattern.insert("1.0", str(data.get("pattern", "")))
        self.pattern.grid(row=row, column=1, sticky="nsew", pady=3, padx=5)
        frame.rowconfigure(row, weight=1)
        row += 1
        ttk.Label(frame, text="Description").grid(row=row, column=0, sticky="nw", pady=3)
        self.description = scrolledtext.ScrolledText(frame, height=5, wrap="word")
        self.description.insert("1.0", str(data.get("description", "")))
        self.description.grid(row=row, column=1, sticky="nsew", pady=3, padx=5)
        frame.rowconfigure(row, weight=1)
        row += 1
        buttons = ttk.Frame(frame)
        buttons.grid(row=row, column=1, sticky="e", pady=8)
        ttk.Button(buttons, text="Cancel", command=self.destroy).pack(side="right", padx=4)
        ttk.Button(buttons, text="Save", command=self.save).pack(side="right", padx=4)
        self.transient(parent)
        self.grab_set()
        self.wait_visibility()
        self.focus()

    def save(self) -> None:
        try:
            confidence = float(self.vars["confidence"].get())
        except Exception:
            messagebox.showerror("Invalid confidence", "Confidence must be a number.", parent=self)
            return
        pattern = self.pattern.get("1.0", "end").strip()
        if not self.vars["name"].get().strip() or not pattern:
            messagebox.showerror("Missing fields", "Rule name and pattern are required.", parent=self)
            return
        if self.vars["pattern_type"].get() == "regex":
            try:
                re.compile(pattern)
            except re.error as e:
                messagebox.showerror("Invalid regex", str(e), parent=self)
                return
        self.result = {
            "name": self.vars["name"].get().strip(),
            "enabled": int(self.vars["enabled"].get()),
            "pattern_type": self.vars["pattern_type"].get(),
            "pattern": pattern,
            "category": self.vars["category"].get().strip() or "Custom",
            "severity": self.vars["severity"].get(),
            "tags": self.vars["tags"].get().strip(),
            "confidence": confidence,
            "description": self.description.get("1.0", "end").strip(),
        }
        self.destroy()


class App(tk.Tk):
    def __init__(self, case_dir: Optional[Path] = None):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1500x950")
        self.minsize(1100, 700)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self.case_dir = case_dir or (app_dir() / "cases" / f"case_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.db = DB(self.case_dir)
        self.logger = self._setup_logger()
        self.running_threads = 0
        self.case_vars: Dict[str, tk.StringVar] = {}
        self.setting_vars: Dict[str, tk.StringVar] = {}
        self.filter_vars: Dict[str, tk.StringVar] = {}
        self.selected_event_id: Optional[int] = None
        self.selected_issue_id: Optional[int] = None
        self.selected_rule_id: Optional[int] = None
        self._setup_style()
        self._build_menu()
        self._build_toolbar()
        self._build_ui()
        self.refresh_all()
        self.after(150, self._poll_queue)

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger(f"{APP_NAME}-{id(self)}")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()
        log_path = self.db.logs_dir / "app.log"
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
        return logger

    def _setup_style(self) -> None:
        try:
            font_size = clamp_int(self.db.setting("font_size", "10"), 10, 8, 24)
            style = ttk.Style(self)
            style.configure("Treeview", rowheight=max(22, font_size + 12))
            style.configure("TButton", padding=4)
        except Exception:
            pass

    def _build_menu(self) -> None:
        menu = tk.Menu(self)

        file_menu = tk.Menu(menu, tearoff=0)
        file_menu.add_command(label="New Case", command=self.new_case)
        file_menu.add_command(label="Open Case Folder...", command=self.open_case)
        file_menu.add_separator()
        file_menu.add_command(label="Import Evidence...", command=self.import_evidence)
        file_menu.add_command(label="Attach Transcript to Selected Evidence...", command=self.attach_transcript_to_selected)
        file_menu.add_separator()
        file_menu.add_command(label="Save Case Info", command=self.save_case_info)
        file_menu.add_command(label="Open Current Case Folder", command=lambda: open_path(self.case_dir))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.close)
        menu.add_cascade(label="File", menu=file_menu)

        evidence_menu = tk.Menu(menu, tearoff=0)
        evidence_menu.add_command(label="Analyze Selected", command=self.analyze_selected)
        evidence_menu.add_command(label="Analyze All", command=self.analyze_all)
        evidence_menu.add_command(label="Refresh Global Analysis", command=self.refresh_global_analysis)
        evidence_menu.add_separator()
        evidence_menu.add_command(label="Open Original File", command=self.open_selected_original)
        evidence_menu.add_command(label="Open Case Copy", command=self.open_selected_copy)
        evidence_menu.add_command(label="Verify Selected Hash", command=self.verify_selected_hash)
        evidence_menu.add_command(label="Remove Selected Evidence", command=self.remove_selected_evidence)
        evidence_menu.add_separator()
        evidence_menu.add_command(label="Extract Video Frame at Time...", command=self.extract_frame_dialog)
        menu.add_cascade(label="Evidence", menu=evidence_menu)

        review_menu = tk.Menu(menu, tearoff=0)
        review_menu.add_command(label="Add Manual Timeline Event", command=self.add_manual_event)
        review_menu.add_command(label="Mark Manual Force Moment", command=self.mark_manual_force_moment)
        review_menu.add_separator()
        review_menu.add_command(label="Confirm Selected Timeline Event", command=lambda: self.review_selected_event("Human-confirmed"))
        review_menu.add_command(label="Dismiss Selected Timeline Event", command=lambda: self.review_selected_event("Dismissed"))
        review_menu.add_command(label="Send Selected Timeline Event to Attorney Review", command=lambda: self.review_selected_event("Needs attorney review"))
        review_menu.add_separator()
        review_menu.add_command(label="Confirm Selected Issue", command=lambda: self.review_selected_issue("Human-confirmed"))
        review_menu.add_command(label="Dismiss Selected Issue", command=lambda: self.review_selected_issue("Dismissed"))
        review_menu.add_command(label="Send Selected Issue to Attorney Review", command=lambda: self.review_selected_issue("Needs attorney review"))
        menu.add_cascade(label="Review", menu=review_menu)

        export_menu = tk.Menu(menu, tearoff=0)
        export_menu.add_command(label="Export HTML Report", command=lambda: self.export_report("html", public=False))
        export_menu.add_command(label="Export Redacted Public HTML", command=lambda: self.export_report("html", public=True))
        export_menu.add_command(label="Export Attorney ZIP Packet", command=lambda: self.export_report("zip", mode="Attorney Review", public=False))
        export_menu.add_command(label="Export Public ZIP Packet", command=lambda: self.export_report("zip", mode="Public Summary", public=True))
        export_menu.add_separator()
        export_menu.add_command(label="Export JSON", command=lambda: self.export_report("json"))
        export_menu.add_command(label="Export Timeline CSV", command=lambda: self.export_report("timeline_csv"))
        export_menu.add_command(label="Export Issues CSV", command=lambda: self.export_report("issues_csv"))
        export_menu.add_command(label="Export Summary TXT", command=lambda: self.export_report("summary_txt"))
        menu.add_cascade(label="Export", menu=export_menu)

        tools_menu = tk.Menu(menu, tearoff=0)
        tools_menu.add_command(label="Dependency Status", command=self.show_dependency_status)
        tools_menu.add_command(label="Open Exports Folder", command=lambda: open_path(self.db.exports_dir))
        tools_menu.add_command(label="Open Logs Folder", command=lambda: open_path(self.db.logs_dir))
        tools_menu.add_command(label="Open Frames Folder", command=lambda: open_path(self.db.frames_dir))
        tools_menu.add_separator()
        tools_menu.add_command(label="Reset Default Rules", command=self.reset_rules)
        tools_menu.add_command(label="Refresh All Views", command=self.refresh_all)
        menu.add_cascade(label="Tools", menu=tools_menu)

        settings_menu = tk.Menu(menu, tearoff=0)
        settings_menu.add_command(label="Open Settings Tab", command=lambda: self.tabs.select(self.settings_tab))
        settings_menu.add_command(label="Open Live Analysis Tab", command=lambda: self.tabs.select(self.live_tab))
        settings_menu.add_command(label="FASTEST Whisper Preset", command=self.fast_whisper_preset)
        settings_menu.add_command(label="Balanced Whisper Preset", command=self.balanced_whisper_preset)
        settings_menu.add_command(label="Use All CPU Cores", command=self.use_all_cores)
        settings_menu.add_separator()
        settings_menu.add_command(label="Run PASS/FAIL Dependency Check", command=self.show_dependency_status)
        menu.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(menu, tearoff=0)
        help_menu.add_command(label="About", command=self.about)
        help_menu.add_command(label="Real-Data Transcription Help", command=self.transcription_help)
        menu.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menu)

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self, padding=(8, 6))
        bar.pack(fill="x")
        buttons = [
            ("New", self.new_case),
            ("Open", self.open_case),
            ("Import Evidence", self.import_evidence),
            ("Attach Transcript", self.attach_transcript_to_selected),
            ("Analyze Selected", self.analyze_selected),
            ("Analyze All", self.analyze_all),
            ("Live Analysis", lambda: self.tabs.select(self.live_tab)),
            ("PASS/FAIL Deps", self.show_dependency_status),
            ("Settings", lambda: self.tabs.select(self.settings_tab)),
            ("Force Moment", lambda: self.tabs.select(self.force_tab)),
            ("Export", lambda: self.tabs.select(self.exports_tab)),
            ("Refresh", self.refresh_all),
        ]
        for text, cmd in buttons:
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=3)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bar, textvariable=self.status_var, anchor="e").pack(side="right", fill="x", expand=True)

    def _build_ui(self) -> None:
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self._build_dashboard_tab()
        self._build_evidence_tab()
        self._build_live_analysis_tab()
        self._build_media_tab()
        self._build_docs_tab()
        self._build_speakers_tab()
        self._build_timeline_tab()
        self._build_force_tab()
        self._build_issues_tab()
        self._build_rules_tab()
        self._build_exports_tab()
        self._build_settings_tab()
        self._build_logs_tab()

    def _text_box(self, parent: tk.Widget, height: int = 10, wrap: str = "word") -> scrolledtext.ScrolledText:
        box = scrolledtext.ScrolledText(parent, height=height, wrap=wrap, undo=True)
        return box

    def _build_dashboard_tab(self) -> None:
        self.dashboard_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.dashboard_tab, text="Dashboard / Case")
        left = ttk.LabelFrame(self.dashboard_tab, text="Case Information", padding=10)
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        left.columnconfigure(1, weight=1)
        fields = [
            ("Title", "title"),
            ("Agency", "agency"),
            ("Incident Date", "incident_date"),
            ("Location", "location"),
            ("Subject", "subject"),
            ("Officers", "officers"),
        ]
        row = 0
        for label, key in fields:
            ttk.Label(left, text=label).grid(row=row, column=0, sticky="w", pady=4)
            self.case_vars[key] = tk.StringVar()
            ttk.Entry(left, textvariable=self.case_vars[key]).grid(row=row, column=1, sticky="ew", pady=4, padx=6)
            row += 1
        ttk.Label(left, text="Case Notes").grid(row=row, column=0, sticky="nw", pady=4)
        self.case_notes = self._text_box(left, height=14)
        self.case_notes.grid(row=row, column=1, sticky="nsew", pady=4, padx=6)
        left.rowconfigure(row, weight=1)
        row += 1
        btns = ttk.Frame(left)
        btns.grid(row=row, column=1, sticky="e", pady=8)
        ttk.Button(btns, text="Save Case Info", command=self.save_case_info).pack(side="right", padx=4)
        ttk.Button(btns, text="Open Case Folder", command=lambda: open_path(self.case_dir)).pack(side="right", padx=4)

        right = ttk.LabelFrame(self.dashboard_tab, text="Status", padding=10)
        right.pack(side="right", fill="both", expand=True)
        self.stats_box = self._text_box(right, height=18)
        self.stats_box.pack(fill="both", expand=True)
        quick = ttk.Frame(right)
        quick.pack(fill="x", pady=8)
        ttk.Button(quick, text="Analyze All", command=self.analyze_all).pack(side="left", padx=3)
        ttk.Button(quick, text="Dependency Status", command=self.show_dependency_status).pack(side="left", padx=3)
        ttk.Button(quick, text="Export Attorney Packet", command=lambda: self.export_report("zip", mode="Attorney Review", public=False)).pack(side="left", padx=3)

    def _build_evidence_tab(self) -> None:
        self.evidence_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.evidence_tab, text="Evidence Manager")
        bar = ttk.Frame(self.evidence_tab)
        bar.pack(fill="x", pady=(0, 6))
        for text, cmd in [
            ("Import Files", self.import_evidence),
            ("Attach Transcript", self.attach_transcript_to_selected),
            ("Analyze Selected", self.analyze_selected),
            ("Analyze All", self.analyze_all),
            ("Open Original", self.open_selected_original),
            ("Open Copy", self.open_selected_copy),
            ("Verify Hash", self.verify_selected_hash),
            ("Remove", self.remove_selected_evidence),
            ("Refresh", self.refresh_evidence),
        ]:
            ttk.Button(bar, text=text, command=cmd).pack(side="left", padx=3)
        cols = ("id", "name", "type", "status", "size", "sha256", "imported", "source")
        self.evidence_tree = ttk.Treeview(self.evidence_tab, columns=cols, show="headings", selectmode="browse")
        headings = {"id": "ID", "name": "Name", "type": "Type", "status": "Status", "size": "Size", "sha256": "SHA-256", "imported": "Imported", "source": "Source"}
        widths = {"id": 55, "name": 260, "type": 90, "status": 140, "size": 90, "sha256": 260, "imported": 150, "source": 140}
        for col in cols:
            self.evidence_tree.heading(col, text=headings[col])
            self.evidence_tree.column(col, width=widths[col], anchor="w")
        self.evidence_tree.pack(fill="both", expand=True)
        self.evidence_tree.bind("<<TreeviewSelect>>", lambda e: self.on_evidence_select())
        bottom = ttk.PanedWindow(self.evidence_tab, orient="horizontal")
        bottom.pack(fill="both", expand=False, pady=(8, 0))
        notes_frame = ttk.LabelFrame(bottom, text="Selected Evidence Notes", padding=6)
        self.evidence_notes = self._text_box(notes_frame, height=6)
        self.evidence_notes.pack(fill="both", expand=True)
        ttk.Button(notes_frame, text="Save Notes", command=self.save_evidence_notes).pack(anchor="e", pady=4)
        meta_frame = ttk.LabelFrame(bottom, text="Selected Evidence Metadata", padding=6)
        self.evidence_meta = self._text_box(meta_frame, height=6, wrap="none")
        self.evidence_meta.pack(fill="both", expand=True)
        bottom.add(notes_frame, weight=1)
        bottom.add(meta_frame, weight=1)

    def _build_live_analysis_tab(self) -> None:
        self.live_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.live_tab, text="Live Analysis")
        self.live_setting_vars: Dict[str, tk.StringVar] = {}
        self.live_job_started_at: Optional[dt.datetime] = None
        self.cancel_requested = False

        top = ttk.Frame(self.live_tab)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Evidence").pack(side="left")
        self.live_evidence_var = tk.StringVar()
        self.live_evidence_combo = ttk.Combobox(top, textvariable=self.live_evidence_var, state="readonly", width=65)
        self.live_evidence_combo.pack(side="left", padx=6)
        for text, cmd in [
            ("Analyze Selected", self.analyze_live_selected),
            ("Analyze All", self.analyze_all),
            ("Cancel After Current Step", self.request_cancel_analysis),
            ("FASTEST tiny/CPU", self.fast_whisper_preset),
            ("Balanced", self.balanced_whisper_preset),
            ("Use All Cores", self.use_all_cores),
            ("PASS/FAIL Deps", self.show_dependency_status),
            ("Open Logs", lambda: open_path(self.db.logs_dir)),
            ("Clear Output", self.clear_live_output),
        ]:
            ttk.Button(top, text=text, command=cmd).pack(side="left", padx=3)

        status = ttk.LabelFrame(self.live_tab, text="Live Status / Progress", padding=8)
        status.pack(fill="x", pady=(0, 8))
        status.columnconfigure(1, weight=1)
        self.live_status_var = tk.StringVar(value="Ready")
        self.live_step_var = tk.StringVar(value="No analysis running")
        self.live_elapsed_var = tk.StringVar(value="Elapsed: 0s")
        self.live_threads_var = tk.StringVar(value=f"CPU threads setting: {self.db.setting('whisper_cpu_threads', str(os.cpu_count() or 1))}")
        ttk.Label(status, text="Status:").grid(row=0, column=0, sticky="w", padx=4, pady=2)
        ttk.Label(status, textvariable=self.live_status_var).grid(row=0, column=1, sticky="ew", padx=4, pady=2)
        ttk.Label(status, text="Step:").grid(row=1, column=0, sticky="w", padx=4, pady=2)
        ttk.Label(status, textvariable=self.live_step_var).grid(row=1, column=1, sticky="ew", padx=4, pady=2)
        ttk.Label(status, text="Elapsed:").grid(row=2, column=0, sticky="w", padx=4, pady=2)
        ttk.Label(status, textvariable=self.live_elapsed_var).grid(row=2, column=1, sticky="ew", padx=4, pady=2)
        ttk.Label(status, textvariable=self.live_threads_var).grid(row=0, column=2, sticky="e", padx=10)
        self.live_progress = ttk.Progressbar(status, mode="indeterminate")
        self.live_progress.grid(row=3, column=0, columnspan=3, sticky="ew", padx=4, pady=6)

        options = ttk.LabelFrame(self.live_tab, text="Fast Analysis Options — saved to Settings", padding=8)
        options.pack(fill="x", pady=(0, 8))
        option_defs = [
            ("whisper_engine", ["auto", "faster-whisper", "openai-whisper", "whisper-cli", "disabled"], "auto tries faster-whisper → openai-whisper → CLI"),
            ("whisper_model", ["tiny", "base", "small", "medium", "large-v3", "large"], "tiny is fastest; bigger is slower/more accurate"),
            ("whisper_device", ["cpu", "cuda", "auto"], "CPU is safest; CUDA only if your stack is stable"),
            ("whisper_compute_type", ["int8", "int8_float16", "float16", "float32"], "faster-whisper compute type"),
            ("whisper_cpu_threads", None, "CPU threads used by faster-whisper/OpenAI/CLI env"),
            ("whisper_beam_size", ["1", "2", "3", "5"], "1 is fastest"),
            ("whisper_language", None, "en is faster for English; blank = autodetect"),
            ("whisper_cli_path", None, "Exact whisper command/path that works in terminal"),
            ("audio_analysis_enabled", ["0", "1"], "0 skips waveform peak analysis for faster transcript output"),
            ("fast_transcription_first", ["0", "1"], "1 transcribes before audio peak analysis"),
            ("extract_audio_before_whisper", ["0", "1"], "1 extracts/reuses mono 16k WAV before Whisper"),
            ("reuse_cached_audio_for_whisper", ["0", "1"], "1 avoids re-decoding huge videos"),
            ("speaker_diarization_enabled", ["auto", "1", "0"], "auto uses sidecar RTTM or pyannote if configured"),
            ("diarization_preload_audio", ["0", "1"], "1 bypasses pyannote AudioDecoder/TorchCodec file-path issue"),
        ]
        for idx, (key, choices, hint) in enumerate(option_defs):
            r = idx // 2
            c = (idx % 2) * 3
            ttk.Label(options, text=key).grid(row=r, column=c, sticky="w", padx=4, pady=2)
            var = tk.StringVar(value=self.db.setting(key, DEFAULT_SETTINGS.get(key, "")))
            self.live_setting_vars[key] = var
            if choices:
                widget = ttk.Combobox(options, textvariable=var, values=choices, width=18, state="readonly")
            else:
                widget = ttk.Entry(options, textvariable=var, width=22)
            widget.grid(row=r, column=c+1, sticky="ew", padx=4, pady=2)
            ttk.Label(options, text=hint).grid(row=r, column=c+2, sticky="w", padx=4, pady=2)
        for c in range(6):
            options.columnconfigure(c, weight=1 if c in {1, 4} else 0)
        btnrow = ttk.Frame(options)
        btnrow.grid(row=(len(option_defs)+1)//2, column=0, columnspan=6, sticky="e", pady=6)
        ttk.Button(btnrow, text="Save Live Options", command=self.save_live_settings).pack(side="right", padx=3)
        ttk.Button(btnrow, text="Refresh Options From Settings", command=self.refresh_live_options).pack(side="right", padx=3)

        panes = ttk.PanedWindow(self.live_tab, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.PanedWindow(panes, orient="vertical")
        activity_frame = ttk.LabelFrame(left, text="Verbose Activity Log — exactly what the app is doing", padding=6)
        self.live_activity_box = self._text_box(activity_frame, height=18, wrap="none")
        self.live_activity_box.pack(fill="both", expand=True)
        raw_frame = ttk.LabelFrame(left, text="Raw Worker / ffmpeg / Whisper Output", padding=6)
        self.live_raw_box = self._text_box(raw_frame, height=10, wrap="none")
        self.live_raw_box.pack(fill="both", expand=True)
        left.add(activity_frame, weight=3)
        left.add(raw_frame, weight=1)
        transcript_frame = ttk.LabelFrame(panes, text="Live Transcript Snippets / Segment Output", padding=6)
        self.live_transcript_box = self._text_box(transcript_frame, height=30)
        self.live_transcript_box.pack(fill="both", expand=True)
        panes.add(left, weight=2)
        panes.add(transcript_frame, weight=1)

    def _build_speakers_tab(self) -> None:
        self.speakers_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.speakers_tab, text="Speakers / Diarization")
        top = ttk.Frame(self.speakers_tab)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Media Evidence").pack(side="left")
        self.speaker_var = tk.StringVar()
        self.speaker_combo = ttk.Combobox(top, textvariable=self.speaker_var, state="readonly", width=70)
        self.speaker_combo.pack(side="left", padx=6)
        self.speaker_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_speakers())
        for text, cmd in [
            ("Run Diarization", self.run_diarization_selected),
            ("Rename Selected Speaker", self.rename_selected_speaker),
            ("Clear Speaker Segments", self.clear_speaker_segments_selected),
            ("Refresh", self.refresh_speakers),
            ("PASS/FAIL Deps", self.show_dependency_status),
        ]:
            ttk.Button(top, text=text, command=cmd).pack(side="left", padx=3)
        cols = ("id", "start", "end", "speaker", "role", "confidence", "source")
        self.speaker_tree = ttk.Treeview(self.speakers_tab, columns=cols, show="headings", selectmode="browse")
        widths = {"id": 55, "start": 90, "end": 90, "speaker": 160, "role": 180, "confidence": 100, "source": 500}
        for col in cols:
            self.speaker_tree.heading(col, text=col.title())
            self.speaker_tree.column(col, width=widths[col], anchor="w")
        self.speaker_tree.pack(fill="both", expand=True)
        detail = ttk.LabelFrame(self.speakers_tab, text="Diagnostics / How to Configure", padding=6)
        detail.pack(fill="x", pady=(8, 0))
        self.speaker_detail = self._text_box(detail, height=9, wrap="none")
        self.speaker_detail.pack(fill="both", expand=True)

    def _build_media_tab(self) -> None:
        self.media_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.media_tab, text="Media Review")
        top = ttk.Frame(self.media_tab)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Media Evidence").pack(side="left")
        self.media_var = tk.StringVar()
        self.media_combo = ttk.Combobox(top, textvariable=self.media_var, state="readonly", width=70)
        self.media_combo.pack(side="left", padx=6)
        self.media_combo.bind("<<ComboboxSelected>>", lambda e: self.load_media_review())
        for text, cmd in [
            ("Load", self.load_media_review),
            ("Analyze", self.analyze_media_combo),
            ("Open File", self.open_media_combo),
            ("Attach Transcript", self.attach_transcript_to_media_combo),
            ("Extract Frame", self.extract_frame_dialog),
        ]:
            ttk.Button(top, text=text, command=cmd).pack(side="left", padx=3)
        panes = ttk.PanedWindow(self.media_tab, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.PanedWindow(panes, orient="vertical")
        meta_frame = ttk.LabelFrame(left, text="Real Media Metadata / Probe", padding=6)
        self.media_meta_box = self._text_box(meta_frame, height=14, wrap="none")
        self.media_meta_box.pack(fill="both", expand=True)
        audio_frame = ttk.LabelFrame(left, text="Real Audio-Level Analysis", padding=6)
        self.media_audio_box = self._text_box(audio_frame, height=14, wrap="none")
        self.media_audio_box.pack(fill="both", expand=True)
        left.add(meta_frame, weight=1)
        left.add(audio_frame, weight=1)
        transcript_frame = ttk.LabelFrame(panes, text="Transcript Attached / Generated from Real Engine", padding=6)
        self.media_transcript_box = self._text_box(transcript_frame, height=30)
        self.media_transcript_box.pack(fill="both", expand=True)
        panes.add(left, weight=1)
        panes.add(transcript_frame, weight=1)

    def _build_docs_tab(self) -> None:
        self.docs_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.docs_tab, text="Transcripts / Documents")
        top = ttk.Frame(self.docs_tab)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text="Evidence").pack(side="left")
        self.doc_var = tk.StringVar()
        self.doc_combo = ttk.Combobox(top, textvariable=self.doc_var, state="readonly", width=70)
        self.doc_combo.pack(side="left", padx=6)
        self.doc_combo.bind("<<ComboboxSelected>>", lambda e: self.load_doc_text())
        ttk.Button(top, text="Load Text", command=self.load_doc_text).pack(side="left", padx=3)
        ttk.Button(top, text="Analyze", command=self.analyze_doc_combo).pack(side="left", padx=3)
        ttk.Button(top, text="Save as Attached Transcript", command=self.save_doc_box_as_attached).pack(side="left", padx=3)
        ttk.Label(top, text="Search").pack(side="left", padx=(16, 2))
        self.doc_search_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.doc_search_var, width=24).pack(side="left")
        ttk.Button(top, text="Find", command=self.search_doc_box).pack(side="left", padx=3)
        self.doc_text_box = self._text_box(self.docs_tab, height=35)
        self.doc_text_box.pack(fill="both", expand=True)

    def _build_timeline_tab(self) -> None:
        self.timeline_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.timeline_tab, text="Unified Timeline")
        filters = ttk.Frame(self.timeline_tab)
        filters.pack(fill="x", pady=(0, 6))
        self.filter_vars["search"] = tk.StringVar()
        self.filter_vars["severity"] = tk.StringVar(value="All")
        self.filter_vars["category"] = tk.StringVar(value="All")
        self.filter_vars["status"] = tk.StringVar(value="All")
        ttk.Label(filters, text="Search").pack(side="left")
        ttk.Entry(filters, textvariable=self.filter_vars["search"], width=24).pack(side="left", padx=4)
        ttk.Label(filters, text="Severity").pack(side="left", padx=(8, 0))
        ttk.Combobox(filters, textvariable=self.filter_vars["severity"], values=["All"] + SEVERITY_LEVELS, state="readonly", width=12).pack(side="left", padx=4)
        ttk.Label(filters, text="Category").pack(side="left", padx=(8, 0))
        self.category_combo = ttk.Combobox(filters, textvariable=self.filter_vars["category"], values=["All"], state="readonly", width=24)
        self.category_combo.pack(side="left", padx=4)
        ttk.Label(filters, text="Status").pack(side="left", padx=(8, 0))
        ttk.Combobox(filters, textvariable=self.filter_vars["status"], values=["All"] + REVIEW_STATUSES, state="readonly", width=22).pack(side="left", padx=4)
        ttk.Button(filters, text="Apply", command=self.refresh_timeline).pack(side="left", padx=4)
        ttk.Button(filters, text="Clear", command=self.clear_timeline_filters).pack(side="left", padx=4)
        ttk.Button(filters, text="Manual Event", command=self.add_manual_event).pack(side="right", padx=3)
        ttk.Button(filters, text="Mark Force", command=self.mark_manual_force_moment).pack(side="right", padx=3)
        cols = ("id", "time", "source", "speaker", "category", "severity", "confidence", "description", "status")
        self.timeline_tree = ttk.Treeview(self.timeline_tab, columns=cols, show="headings", selectmode="browse")
        widths = {"id": 55, "time": 80, "source": 180, "speaker": 110, "category": 150, "severity": 90, "confidence": 90, "description": 520, "status": 160}
        for col in cols:
            self.timeline_tree.heading(col, text=col.title())
            self.timeline_tree.column(col, width=widths[col], anchor="w")
        self.timeline_tree.pack(fill="both", expand=True)
        self.timeline_tree.bind("<<TreeviewSelect>>", lambda e: self.on_timeline_select())
        details = ttk.LabelFrame(self.timeline_tab, text="Selected Timeline Event", padding=6)
        details.pack(fill="x", pady=(8, 0))
        self.timeline_detail = self._text_box(details, height=7)
        self.timeline_detail.pack(fill="both", expand=True)
        buttons = ttk.Frame(details)
        buttons.pack(fill="x", pady=4)
        for text, status in [("Confirm", "Human-confirmed"), ("Dismiss", "Dismissed"), ("Attorney Review", "Needs attorney review"), ("Dispute", "Disputed")]:
            ttk.Button(buttons, text=text, command=lambda s=status: self.review_selected_event(s)).pack(side="left", padx=3)
        ttk.Button(buttons, text="Toggle Export Include", command=self.toggle_selected_event_export).pack(side="left", padx=3)

    def _build_force_tab(self) -> None:
        self.force_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.force_tab, text="Force Moment")
        top = ttk.Frame(self.force_tab)
        top.pack(fill="x", pady=(0, 8))
        ttk.Button(top, text="Refresh Force Analysis", command=self.refresh_force).pack(side="left", padx=3)
        ttk.Button(top, text="Manual Mark Force Moment", command=self.mark_manual_force_moment).pack(side="left", padx=3)
        ttk.Button(top, text="Extract Frame at Force Time", command=self.extract_force_frame).pack(side="left", padx=3)
        self.force_summary = self._text_box(self.force_tab, height=8)
        self.force_summary.pack(fill="x", pady=(0, 8))
        cols = ("id", "time", "source", "category", "severity", "description", "status")
        self.force_context_tree = ttk.Treeview(self.force_tab, columns=cols, show="headings", selectmode="browse")
        for col in cols:
            self.force_context_tree.heading(col, text=col.title())
            self.force_context_tree.column(col, width={"id": 55, "time": 80, "source": 190, "category": 140, "severity": 90, "description": 700, "status": 150}[col], anchor="w")
        self.force_context_tree.pack(fill="both", expand=True)
        self.force_context_tree.bind("<<TreeviewSelect>>", lambda e: self.on_force_context_select())

    def _build_issues_tab(self) -> None:
        self.issues_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.issues_tab, text="Inconsistencies / Issues")
        top = ttk.Frame(self.issues_tab)
        top.pack(fill="x", pady=(0, 6))
        ttk.Button(top, text="Refresh", command=self.refresh_issues).pack(side="left", padx=3)
        ttk.Button(top, text="Refresh Global Analysis", command=self.refresh_global_analysis).pack(side="left", padx=3)
        for text, status in [("Confirm", "Human-confirmed"), ("Dismiss", "Dismissed"), ("Attorney Review", "Needs attorney review"), ("Dispute", "Disputed")]:
            ttk.Button(top, text=text, command=lambda s=status: self.review_selected_issue(s)).pack(side="left", padx=3)
        cols = ("id", "severity", "category", "title", "confidence", "status")
        self.issues_tree = ttk.Treeview(self.issues_tab, columns=cols, show="headings", selectmode="browse")
        widths = {"id": 55, "severity": 90, "category": 160, "title": 600, "confidence": 100, "status": 180}
        for col in cols:
            self.issues_tree.heading(col, text=col.title())
            self.issues_tree.column(col, width=widths[col], anchor="w")
        self.issues_tree.pack(fill="both", expand=True)
        self.issues_tree.bind("<<TreeviewSelect>>", lambda e: self.on_issue_select())
        detail_frame = ttk.LabelFrame(self.issues_tab, text="Selected Issue", padding=6)
        detail_frame.pack(fill="x", pady=(8, 0))
        self.issue_detail = self._text_box(detail_frame, height=8)
        self.issue_detail.pack(fill="both", expand=True)

    def _build_rules_tab(self) -> None:
        self.rules_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.rules_tab, text="Rules Engine")
        bar = ttk.Frame(self.rules_tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Add Rule", command=self.add_rule).pack(side="left", padx=3)
        ttk.Button(bar, text="Edit Rule", command=self.edit_rule).pack(side="left", padx=3)
        ttk.Button(bar, text="Delete Rule", command=self.delete_rule).pack(side="left", padx=3)
        ttk.Button(bar, text="Reset Defaults", command=self.reset_rules).pack(side="left", padx=3)
        ttk.Button(bar, text="Test Rule Text", command=self.test_rules_text).pack(side="left", padx=3)
        cols = ("id", "enabled", "name", "category", "severity", "confidence", "pattern_type", "tags")
        self.rules_tree = ttk.Treeview(self.rules_tab, columns=cols, show="headings", selectmode="browse")
        widths = {"id": 55, "enabled": 80, "name": 300, "category": 160, "severity": 90, "confidence": 100, "pattern_type": 110, "tags": 250}
        for col in cols:
            self.rules_tree.heading(col, text=col.title())
            self.rules_tree.column(col, width=widths[col], anchor="w")
        self.rules_tree.pack(fill="both", expand=True)
        self.rules_tree.bind("<<TreeviewSelect>>", lambda e: self.on_rule_select())
        self.rule_detail = self._text_box(self.rules_tab, height=8)
        self.rule_detail.pack(fill="x", pady=(8, 0))

    def _build_exports_tab(self) -> None:
        self.exports_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.exports_tab, text="Exports")
        top = ttk.LabelFrame(self.exports_tab, text="Export Options", padding=10)
        top.pack(fill="x")
        ttk.Label(top, text="Summary/Report Mode").grid(row=0, column=0, sticky="w", pady=4)
        self.export_mode_var = tk.StringVar(value="Internal Review")
        ttk.Combobox(top, textvariable=self.export_mode_var, values=["Internal Review", "Attorney Review", "Public Summary", "Use-of-Force Review"], state="readonly", width=28).grid(row=0, column=1, sticky="w", padx=6, pady=4)
        self.export_public_var = tk.IntVar(value=0)
        ttk.Checkbutton(top, text="Redacted public export", variable=self.export_public_var).grid(row=0, column=2, sticky="w", padx=8)
        buttons = ttk.Frame(top)
        buttons.grid(row=1, column=0, columnspan=3, sticky="w", pady=8)
        for text, kind in [("HTML", "html"), ("ZIP Packet", "zip"), ("JSON", "json"), ("Timeline CSV", "timeline_csv"), ("Issues CSV", "issues_csv"), ("Summary TXT", "summary_txt")]:
            ttk.Button(buttons, text=f"Export {text}", command=lambda k=kind: self.export_report(k, mode=self.export_mode_var.get(), public=bool(self.export_public_var.get()))).pack(side="left", padx=3)
        ttk.Button(buttons, text="Open Exports Folder", command=lambda: open_path(self.db.exports_dir)).pack(side="left", padx=12)
        self.export_log = self._text_box(self.exports_tab, height=28)
        self.export_log.pack(fill="both", expand=True, pady=(8, 0))

    def _build_settings_tab(self) -> None:
        self.settings_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.settings_tab, text="Settings")
        canvas = tk.Canvas(self.settings_tab, highlightthickness=0)
        scroll = ttk.Scrollbar(self.settings_tab, orient="vertical", command=canvas.yview)
        frame = ttk.Frame(canvas)
        frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        frame.columnconfigure(1, weight=1)
        row = 0
        help_text = {
            "transcribe_media": "Uses only real local engines/sidecars/attached transcripts. No fake transcript fallback.",
            "whisper_engine": "auto, faster-whisper, openai-whisper, whisper-cli, or disabled.",
            "ffmpeg_path": "Required for non-WAV audio extraction and video frame extraction.",
            "ffprobe_path": "Required for duration/stream metadata.",
        }
        for key, default in DEFAULT_SETTINGS.items():
            ttk.Label(frame, text=key).grid(row=row, column=0, sticky="w", pady=4, padx=4)
            self.setting_vars[key] = tk.StringVar()
            if key in {"copy_evidence_into_case_folder", "auto_analyze_on_import", "store_nonflag_transcript_lines", "transcribe_media", "audio_analysis_enabled", "redact_public_exports", "open_exports_after_creation", "extract_audio_before_whisper", "reuse_cached_audio_for_whisper", "fast_transcription_first", "diarization_preload_audio", "speaker_overwrite_existing_labels"}:
                widget = ttk.Combobox(frame, textvariable=self.setting_vars[key], values=["0", "1"], state="readonly", width=12)
            elif key == "whisper_engine":
                widget = ttk.Combobox(frame, textvariable=self.setting_vars[key], values=["auto", "faster-whisper", "openai-whisper", "whisper-cli", "disabled"], state="readonly", width=24)
            elif key == "whisper_model":
                widget = ttk.Combobox(frame, textvariable=self.setting_vars[key], values=["tiny", "base", "small", "medium", "large-v3", "large"], state="readonly", width=24)
            elif key == "whisper_device":
                widget = ttk.Combobox(frame, textvariable=self.setting_vars[key], values=["cpu", "cuda", "auto"], state="readonly", width=24)
            elif key == "whisper_compute_type":
                widget = ttk.Combobox(frame, textvariable=self.setting_vars[key], values=["int8", "int8_float16", "float16", "float32"], state="readonly", width=24)
            elif key == "speaker_diarization_enabled":
                widget = ttk.Combobox(frame, textvariable=self.setting_vars[key], values=["auto", "1", "0"], state="readonly", width=24)
            elif key == "speaker_diarization_engine":
                widget = ttk.Combobox(frame, textvariable=self.setting_vars[key], values=["pyannote", "sidecar-rttm", "disabled"], state="readonly", width=24)
            else:
                widget = ttk.Entry(frame, textvariable=self.setting_vars[key])
            widget.grid(row=row, column=1, sticky="ew", pady=4, padx=6)
            ttk.Label(frame, text=help_text.get(key, "")).grid(row=row, column=2, sticky="w", padx=6)
            row += 1
        btns = ttk.Frame(frame)
        btns.grid(row=row, column=1, sticky="e", pady=10)
        ttk.Button(btns, text="Save Settings", command=self.save_settings).pack(side="right", padx=4)
        ttk.Button(btns, text="Dependency Status", command=self.show_dependency_status).pack(side="right", padx=4)

    def _build_logs_tab(self) -> None:
        self.logs_tab = ttk.Frame(self.tabs, padding=10)
        self.tabs.add(self.logs_tab, text="Audit / Logs")
        top = ttk.Frame(self.logs_tab)
        top.pack(fill="x", pady=(0, 6))
        ttk.Button(top, text="Refresh", command=self.refresh_logs).pack(side="left", padx=3)
        ttk.Button(top, text="Open Logs Folder", command=lambda: open_path(self.db.logs_dir)).pack(side="left", padx=3)
        ttk.Button(top, text="Clear Display", command=lambda: self.runtime_log.delete("1.0", "end")).pack(side="left", padx=3)
        panes = ttk.PanedWindow(self.logs_tab, orient="vertical")
        panes.pack(fill="both", expand=True)
        audit_frame = ttk.LabelFrame(panes, text="Audit Log", padding=6)
        cols = ("id", "created_at", "actor", "action", "detail")
        self.audit_tree = ttk.Treeview(audit_frame, columns=cols, show="headings")
        widths = {"id": 55, "created_at": 170, "actor": 120, "action": 220, "detail": 800}
        for col in cols:
            self.audit_tree.heading(col, text=col.title())
            self.audit_tree.column(col, width=widths[col], anchor="w")
        self.audit_tree.pack(fill="both", expand=True)
        log_frame = ttk.LabelFrame(panes, text="Runtime Log", padding=6)
        self.runtime_log = self._text_box(log_frame, height=12, wrap="none")
        self.runtime_log.pack(fill="both", expand=True)
        panes.add(audit_frame, weight=2)
        panes.add(log_frame, weight=1)

    # ---------- utility / selection helpers ----------

    def log(self, message: str) -> None:
        line = f"[{dt.datetime.now().strftime('%H:%M:%S')}] {message}"
        self.logger.info(message)
        try:
            self.runtime_log.insert("end", line + "\n")
            self.runtime_log.see("end")
        except Exception:
            pass
        try:
            if hasattr(self, "live_activity_box"):
                self.live_activity_box.insert("end", line + "\n")
                self.live_activity_box.see("end")
            lower = message.lower()
            if hasattr(self, "live_raw_box") and any(k in lower for k in ["ffmpeg", "whisper", "pyannote", "command", "stderr", "stdout", "heartbeat", "traceback", "fail", "warn"]):
                self.live_raw_box.insert("end", line + "\n")
                self.live_raw_box.see("end")
            if hasattr(self, "live_transcript_box") and ("segment" in lower and "|" in message):
                self.live_transcript_box.insert("end", message.split("|", 1)[-1].strip() + "\n")
                self.live_transcript_box.see("end")
            if hasattr(self, "live_status_var"):
                self.live_status_var.set(message[:240])
            if hasattr(self, "live_elapsed_var") and self.live_job_started_at:
                elapsed = (dt.datetime.now() - self.live_job_started_at).total_seconds()
                self.live_elapsed_var.set(f"Elapsed: {elapsed:.0f}s")
        except Exception:
            pass
        self.status_var.set(message)
        try:
            self.update_idletasks()
        except Exception:
            pass

    def post(self, kind: str, payload: Any = None) -> None:
        self.queue.put((kind, payload))

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "analysis_start":
                    self.live_job_started_at = dt.datetime.now()
                    if hasattr(self, "live_progress"):
                        self.live_progress.start(12)
                    if hasattr(self, "live_step_var"):
                        self.live_step_var.set(str(payload or "Analysis started"))
                    self.log(str(payload or "Analysis started"))
                elif kind == "analysis_step":
                    if hasattr(self, "live_step_var"):
                        self.live_step_var.set(str(payload))
                    self.log(str(payload))
                elif kind == "log":
                    self.log(str(payload))
                elif kind == "error":
                    self.running_threads = max(0, self.running_threads - 1)
                    if hasattr(self, "live_progress"):
                        self.live_progress.stop()
                    self.live_job_started_at = None
                    self.log("Error: " + str(payload))
                    messagebox.showerror("Error", str(payload), parent=self)
                    self.refresh_all()
                elif kind == "done":
                    self.running_threads = max(0, self.running_threads - 1)
                    if hasattr(self, "live_progress"):
                        self.live_progress.stop()
                    if hasattr(self, "live_step_var"):
                        self.live_step_var.set("Done")
                    self.live_job_started_at = None
                    self.log(str(payload or "Done"))
                    self.refresh_all()
                elif kind == "export_done":
                    self.running_threads = max(0, self.running_threads - 1)
                    if hasattr(self, "live_progress"):
                        self.live_progress.stop()
                    self.live_job_started_at = None
                    path = Path(str(payload))
                    self.log(f"Export created: {path}")
                    self.export_log.insert("end", f"Export created: {path}\n")
                    self.export_log.see("end")
                    if self.db.setting("open_exports_after_creation", "0") == "1":
                        open_path(path)
                    self.refresh_all()
        except queue.Empty:
            pass
        self.after(150, self._poll_queue)

    def selected_evidence_id(self) -> Optional[int]:
        sel = self.evidence_tree.selection()
        if sel:
            try:
                return int(self.evidence_tree.item(sel[0], "values")[0])
            except Exception:
                return None
        # Fall back to active combo in current tabs.
        current = self.tabs.tab(self.tabs.select(), "text") if self.tabs.select() else ""
        if current == "Media Review":
            return self.combo_id(self.media_var.get())
        if current == "Transcripts / Documents":
            return self.combo_id(self.doc_var.get())
        if current == "Live Analysis" and hasattr(self, "live_evidence_var"):
            return self.combo_id(self.live_evidence_var.get())
        if current == "Speakers / Diarization" and hasattr(self, "speaker_var"):
            return self.combo_id(self.speaker_var.get())
        return None

    def combo_id(self, value: str) -> Optional[int]:
        m = re.match(r"#(\d+)\s+", value or "")
        return int(m.group(1)) if m else None

    def set_tree_rows(self, tree: ttk.Treeview, rows: Iterable[Sequence[Any]]) -> None:
        for item in tree.get_children():
            tree.delete(item)
        for row in rows:
            tree.insert("", "end", values=list(row))

    def _run_thread(self, target: Callable[[], None]) -> None:
        self.running_threads += 1
        t = threading.Thread(target=target, daemon=True)
        t.start()

    # ---------- live analysis / speaker actions ----------

    def analyze_live_selected(self) -> None:
        eid = self.combo_id(self.live_evidence_var.get()) if hasattr(self, "live_evidence_var") else None
        if eid is None:
            eid = self.selected_evidence_id()
        if eid is None:
            messagebox.showinfo("Select evidence", "Select evidence to analyze.", parent=self)
            return
        self.save_live_settings()
        self.run_analysis([eid])

    def request_cancel_analysis(self) -> None:
        self.cancel_requested = True
        self.log("Cancel requested. The current Whisper/ffmpeg step may need to finish before the worker stops.")
        if hasattr(self, "live_step_var"):
            self.live_step_var.set("Cancel requested; waiting for current step boundary")

    def clear_live_output(self) -> None:
        for attr in ["live_activity_box", "live_raw_box", "live_transcript_box"]:
            box = getattr(self, attr, None)
            if box:
                box.delete("1.0", "end")
        self.log("Live Analysis output cleared.")

    def save_live_settings(self) -> None:
        if not hasattr(self, "live_setting_vars"):
            return
        data = {k: v.get() for k, v in self.live_setting_vars.items()}
        self.db.update_settings(data)
        for k, v in data.items():
            if k in self.setting_vars:
                self.setting_vars[k].set(v)
        self.refresh_dashboard()
        self.log("Live Analysis options saved to Settings.")

    def refresh_live_options(self) -> None:
        if not hasattr(self, "live_setting_vars"):
            return
        for key, var in self.live_setting_vars.items():
            var.set(self.db.setting(key, DEFAULT_SETTINGS.get(key, "")))
        if hasattr(self, "live_threads_var"):
            self.live_threads_var.set(f"CPU threads setting: {self.db.setting('whisper_cpu_threads', str(os.cpu_count() or 1))}")

    def fast_whisper_preset(self) -> None:
        data = {
            "whisper_engine": "auto",
            "whisper_model": "tiny",
            "whisper_device": "cpu",
            "whisper_compute_type": "int8",
            "whisper_beam_size": "1",
            "whisper_language": "en",
            "audio_analysis_enabled": "0",
            "fast_transcription_first": "1",
            "extract_audio_before_whisper": "1",
            "reuse_cached_audio_for_whisper": "1",
        }
        self.db.update_settings(data)
        self.refresh_live_options()
        self.refresh_settings()
        self.log("FASTEST Whisper preset applied: tiny / CPU / int8 / beam 1 / skip audio-level analysis.")

    def balanced_whisper_preset(self) -> None:
        data = {
            "whisper_engine": "auto",
            "whisper_model": "base",
            "whisper_device": "cpu",
            "whisper_compute_type": "int8",
            "whisper_beam_size": "3",
            "whisper_language": "en",
            "audio_analysis_enabled": "0",
            "fast_transcription_first": "1",
            "extract_audio_before_whisper": "1",
            "reuse_cached_audio_for_whisper": "1",
        }
        self.db.update_settings(data)
        self.refresh_live_options()
        self.refresh_settings()
        self.log("Balanced Whisper preset applied: base / CPU / int8 / beam 3.")

    def use_all_cores(self) -> None:
        cores = max(1, os.cpu_count() or 1)
        self.db.update_settings({"whisper_cpu_threads": str(cores)})
        self.refresh_live_options()
        self.refresh_settings()
        self.log(f"CPU thread setting changed to all cores: {cores}")

    def refresh_live_evidence_combo(self) -> None:
        if not hasattr(self, "live_evidence_combo"):
            return
        values = [f"#{ev.id} {ev.display_name} ({ev.type})" for ev in self.db.evidences()]
        self.live_evidence_combo["values"] = values
        if values and self.live_evidence_var.get() not in values:
            self.live_evidence_var.set(values[0])
        elif not values:
            self.live_evidence_var.set("")

    def refresh_speaker_combo(self) -> None:
        if not hasattr(self, "speaker_combo"):
            return
        values = [f"#{ev.id} {ev.display_name} ({ev.type})" for ev in self.db.evidences({"video", "audio"})]
        self.speaker_combo["values"] = values
        if values and self.speaker_var.get() not in values:
            self.speaker_var.set(values[0])
        elif not values:
            self.speaker_var.set("")

    def refresh_speakers(self) -> None:
        if not hasattr(self, "speaker_tree"):
            return
        eid = self.combo_id(self.speaker_var.get()) if hasattr(self, "speaker_var") else None
        rows = []
        if eid is not None:
            for seg in self.db.speaker_segments(eid):
                rows.append((seg.get("id"), seg.get("start_text"), seg.get("end_text"), seg.get("speaker_label"), seg.get("role_label"), f"{float(seg.get('confidence') or 0):.0f}%", seg.get("source")))
        self.set_tree_rows(self.speaker_tree, rows)
        if hasattr(self, "speaker_detail"):
            self.speaker_detail.delete("1.0", "end")
            deps = dependency_status(self.db.settings())
            detail = [
                "Speaker diarization uses real sidecar RTTM or pyannote.audio only; it never invents speakers.",
                "Recommended default: diarization_preload_audio=1 to bypass pyannote AudioDecoder/TorchCodec file-path failures.",
                "Rename Speaker 1 / Speaker 2 after reviewing who is speaking.",
                "",
                "Dependency highlights:",
                deps.get("pyannote.audio", ""),
                deps.get("torch", ""),
                deps.get("Hugging Face token", ""),
                deps.get("TorchCodec AudioDecoder", ""),
                deps.get("pyannote preload workaround", ""),
            ]
            self.speaker_detail.insert("1.0", "\n".join(str(x) for x in detail if x is not None))

    def run_diarization_selected(self) -> None:
        eid = self.combo_id(self.speaker_var.get()) if hasattr(self, "speaker_var") else None
        if eid is None:
            messagebox.showinfo("Select media", "Choose a media evidence item first.", parent=self)
            return
        def work() -> None:
            try:
                ev = self.db.evidence(eid)
                if not ev:
                    self.post("error", f"Evidence #{eid} not found")
                    return
                diarizer = SpeakerDiarizer(self.db, lambda m: self.post("log", m))
                self.post("log", f"Running speaker diarization for evidence #{eid}: {ev.display_name}")
                segments, engine, ok = diarizer.diarize(ev)
                if ok:
                    # If a transcript already exists, apply speaker labels to latest transcript content.
                    t = self.db.latest_transcript(eid)
                    if t and (t.get("content") or "").strip():
                        labeled = diarizer.label_transcript_text(eid, t["content"])
                        self.db.update_transcript_content(int(t["id"]), labeled, "speaker-labeled")
                    self.post("done", f"Speaker diarization complete: {len(segments)} segments via {engine}")
                else:
                    self.post("done", f"Speaker diarization unavailable/not applied: {engine}")
            except Exception as e:
                self.post("error", f"Speaker diarization failed:\n{e}\n\n{traceback.format_exc()}")
        self._run_thread(work)

    def rename_selected_speaker(self) -> None:
        eid = self.combo_id(self.speaker_var.get()) if hasattr(self, "speaker_var") else None
        sel = self.speaker_tree.selection() if hasattr(self, "speaker_tree") else []
        if eid is None or not sel:
            messagebox.showinfo("Select speaker", "Select a speaker segment first.", parent=self)
            return
        vals = self.speaker_tree.item(sel[0], "values")
        speaker_label = str(vals[3]) if len(vals) > 3 else ""
        if not speaker_label:
            return
        new_role = simpledialog.askstring("Rename speaker", f"Rename {speaker_label} to:", initialvalue=str(vals[4]) if len(vals) > 4 else speaker_label, parent=self)
        if not new_role:
            return
        self.db.update_speaker_role(eid, speaker_label, new_role)
        # Apply the rename to latest transcript display as well.
        t = self.db.latest_transcript(eid)
        if t and (t.get("content") or "").strip():
            content = re.sub(rf"\b{re.escape(speaker_label)}\s*:", f"{new_role}:", t["content"])
            self.db.update_transcript_content(int(t["id"]), content, "speaker-renamed")
        self.refresh_all()
        self.log(f"Speaker renamed for evidence #{eid}: {speaker_label} -> {new_role}")

    def clear_speaker_segments_selected(self) -> None:
        eid = self.combo_id(self.speaker_var.get()) if hasattr(self, "speaker_var") else None
        if eid is None:
            return
        if messagebox.askyesno("Clear speaker segments", "Clear speaker diarization segments for this evidence?", parent=self):
            self.db.clear_speaker_segments(eid)
            self.refresh_speakers()
            self.log(f"Speaker segments cleared for evidence #{eid}.")

    # ---------- case and evidence actions ----------

    def new_case(self) -> None:
        directory = filedialog.askdirectory(title="Choose or create a new case folder", initialdir=str(app_dir() / "cases"))
        if not directory:
            return
        self.db.close()
        self.case_dir = Path(directory)
        self.db = DB(self.case_dir)
        self.logger = self._setup_logger()
        self.refresh_all()
        self.log(f"Opened new case folder: {self.case_dir}")

    def open_case(self) -> None:
        directory = filedialog.askdirectory(title="Open case folder", initialdir=str(app_dir() / "cases"))
        if not directory:
            return
        self.db.close()
        self.case_dir = Path(directory)
        self.db = DB(self.case_dir)
        self.logger = self._setup_logger()
        self.refresh_all()
        self.log(f"Opened case folder: {self.case_dir}")

    def save_case_info(self) -> None:
        data = {k: v.get() for k, v in self.case_vars.items()}
        data["case_notes"] = self.case_notes.get("1.0", "end").strip()
        self.db.update_case_info(data)
        self.refresh_dashboard()
        self.log("Case info saved.")

    def import_evidence(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Import evidence files",
            filetypes=[
                ("Supported evidence", "*.mp4 *.mov *.avi *.mkv *.m4v *.wmv *.webm *.wav *.mp3 *.m4a *.flac *.aac *.ogg *.txt *.md *.csv *.json *.pdf *.docx *.rtf *.srt *.vtt *.png *.jpg *.jpeg *.bmp *.tif *.tiff *.webp"),
                ("All files", "*.*"),
            ],
        )
        if not paths:
            return
        copy = self.db.setting("copy_evidence_into_case_folder", "1") == "1"
        ids = []
        for p in paths:
            try:
                ids.append(self.db.add_evidence(p, copy_into_case=copy))
            except Exception as e:
                messagebox.showerror("Import failed", f"{p}\n\n{e}", parent=self)
        self.refresh_all()
        self.log(f"Imported {len(ids)} evidence file(s).")
        if ids and self.db.setting("auto_analyze_on_import", "0") == "1":
            self.run_analysis(ids)

    def attach_transcript_to_selected(self) -> None:
        eid = self.selected_evidence_id()
        if eid is None:
            messagebox.showinfo("Select evidence", "Select an evidence file first.", parent=self)
            return
        self.attach_transcript(eid)

    def attach_transcript_to_media_combo(self) -> None:
        eid = self.combo_id(self.media_var.get())
        if eid is None:
            messagebox.showinfo("Select media", "Choose a media evidence item first.", parent=self)
            return
        self.attach_transcript(eid)

    def attach_transcript(self, eid: int) -> None:
        ev = self.db.evidence(eid)
        if not ev:
            return
        path = filedialog.askopenfilename(title=f"Attach transcript for {ev.display_name}", filetypes=[("Transcript/Text", "*.txt *.srt *.vtt *.md *.csv *.json"), ("All files", "*.*")])
        if not path:
            return
        text, engine, ok = TextExtractor(self.log).extract(Path(path))
        if not ok or not text.strip():
            messagebox.showerror("Transcript attach failed", f"No text could be extracted.\n\nExtractor result: {engine}", parent=self)
            return
        self.db.add_transcript(eid, text, f"attached-file:{engine}:{Path(path).name}", "attached-transcript", 95, attached=True)
        # Build timeline from attached transcript immediately, keeping existing analysis.
        Analyzer(self.db, self.log).timeline_from_text(ev, text, ev.type if ev.type in {"video", "audio"} else "attached-transcript")
        Analyzer(self.db, self.log).global_analysis()
        self.refresh_all()
        self.log(f"Attached transcript to #{eid}: {Path(path).name}")

    def analyze_selected(self) -> None:
        eid = self.selected_evidence_id()
        if eid is None:
            messagebox.showinfo("Select evidence", "Select evidence to analyze.", parent=self)
            return
        self.run_analysis([eid])

    def analyze_all(self) -> None:
        ids = [ev.id for ev in self.db.evidences()]
        if not ids:
            messagebox.showinfo("No evidence", "Import evidence first.", parent=self)
            return
        self.run_analysis(ids)

    def run_analysis(self, ids: List[int]) -> None:
        self.cancel_requested = False
        self.post("analysis_start", f"Analysis started for {len(ids)} evidence file(s).")
        def work() -> None:
            try:
                analyzer = Analyzer(self.db, lambda m: self.post("log", m))
                completed = 0
                for idx, eid in enumerate(ids, 1):
                    if self.cancel_requested:
                        self.post("log", "Cancel flag detected before next evidence. Stopping batch.")
                        break
                    ev = self.db.evidence(eid)
                    label = f"#{eid}" + (f" {ev.display_name}" if ev else "")
                    self.post("analysis_step", f"Analyzing {idx}/{len(ids)}: evidence {label}")
                    self.post("log", f"Analyzing {idx}/{len(ids)}: evidence {label}")
                    analyzer.analyze(eid, refresh_global=False)
                    completed += 1
                    self.post("analysis_step", f"Finished {idx}/{len(ids)}: evidence {label}")
                analyzer.global_analysis()
                self.post("done", f"Analyzed {completed}/{len(ids)} evidence file(s).")
            except Exception as e:
                self.post("error", f"Analysis failed:\n{e}\n\n{traceback.format_exc()}")
        self._run_thread(work)

    def refresh_global_analysis(self) -> None:
        try:
            Analyzer(self.db, self.log).global_analysis()
            self.refresh_all()
            self.log("Global analysis refreshed.")
        except Exception as e:
            messagebox.showerror("Global analysis failed", str(e), parent=self)

    def open_selected_original(self) -> None:
        eid = self.selected_evidence_id()
        ev = self.db.evidence(eid) if eid else None
        if not ev:
            messagebox.showinfo("Select evidence", "Select evidence first.", parent=self)
            return
        open_path(ev.path)

    def open_selected_copy(self) -> None:
        eid = self.selected_evidence_id()
        ev = self.db.evidence(eid) if eid else None
        if not ev:
            messagebox.showinfo("Select evidence", "Select evidence first.", parent=self)
            return
        open_path(ev.analysis_path)

    def verify_selected_hash(self) -> None:
        eid = self.selected_evidence_id()
        if eid is None:
            messagebox.showinfo("Select evidence", "Select evidence first.", parent=self)
            return
        try:
            ok, old, current = self.db.verify_hash(eid)
            msg = "Hash verified: file matches import hash." if ok else "Hash mismatch or file missing."
            messagebox.showinfo("Hash Verification", f"{msg}\n\nExpected: {old}\nCurrent:  {current}", parent=self)
            self.db.audit("Hash verified" if ok else "Hash verification failed", f"#{eid} expected={old} current={current}")
        except Exception as e:
            messagebox.showerror("Hash verification failed", str(e), parent=self)

    def remove_selected_evidence(self) -> None:
        eid = self.selected_evidence_id()
        ev = self.db.evidence(eid) if eid else None
        if not ev:
            messagebox.showinfo("Select evidence", "Select evidence first.", parent=self)
            return
        if not messagebox.askyesno("Remove evidence", f"Remove evidence #{eid} {ev.display_name} from this case database?\n\nThe source file will not be deleted.", parent=self):
            return
        self.db.remove_evidence(eid)
        self.refresh_all()
        self.log(f"Removed evidence #{eid}.")

    def save_evidence_notes(self) -> None:
        eid = self.selected_evidence_id()
        if eid is None:
            messagebox.showinfo("Select evidence", "Select evidence first.", parent=self)
            return
        self.db.update_evidence_notes(eid, self.evidence_notes.get("1.0", "end").strip())
        self.refresh_evidence()
        self.log("Evidence notes saved.")

    # ---------- media/doc actions ----------

    def analyze_media_combo(self) -> None:
        eid = self.combo_id(self.media_var.get())
        if eid is None:
            messagebox.showinfo("Select media", "Choose media evidence first.", parent=self)
            return
        self.run_analysis([eid])

    def open_media_combo(self) -> None:
        eid = self.combo_id(self.media_var.get())
        ev = self.db.evidence(eid) if eid else None
        if ev:
            open_path(ev.analysis_path)

    def load_media_review(self) -> None:
        eid = self.combo_id(self.media_var.get())
        self.media_meta_box.delete("1.0", "end")
        self.media_audio_box.delete("1.0", "end")
        self.media_transcript_box.delete("1.0", "end")
        if eid is None:
            return
        ev = self.db.evidence(eid)
        if not ev:
            return
        analyses = self.db.media_analysis(eid)
        if not analyses:
            self.media_meta_box.insert("1.0", "No media analysis stored yet. Click Analyze to probe the actual file.")
        for a in analyses:
            try:
                data = json.loads(a.get("content_json") or "{}")
            except Exception:
                data = a.get("content_json", "")
            block = f"[{a.get('kind')}] {a.get('title')}\nCreated: {pretty_date(a.get('created_at'))}\n\n{a.get('summary') or ''}\n\n{short_json(data, max_chars=30000)}\n\n"
            if a.get("kind") == "audio-levels":
                self.media_audio_box.insert("end", block)
            else:
                self.media_meta_box.insert("end", block)
        tr = self.db.latest_transcript(eid)
        if tr:
            header = f"Engine: {tr.get('engine')} | Source: {tr.get('source_kind')} | Confidence: {tr.get('confidence')} | Created: {pretty_date(tr.get('created_at'))}\n\n"
            self.media_transcript_box.insert("1.0", header + (tr.get("content") or ""))
        else:
            self.media_transcript_box.insert("1.0", "No transcript exists for this media evidence. The app will not fake one. Attach a transcript, add a sidecar .txt/.srt/.vtt next to the media, or install/enable a real Whisper engine.")

    def analyze_doc_combo(self) -> None:
        eid = self.combo_id(self.doc_var.get())
        if eid is None:
            messagebox.showinfo("Select evidence", "Choose evidence first.", parent=self)
            return
        self.run_analysis([eid])

    def load_doc_text(self) -> None:
        eid = self.combo_id(self.doc_var.get())
        self.doc_text_box.delete("1.0", "end")
        if eid is None:
            return
        ev = self.db.evidence(eid)
        if not ev:
            return
        tr = self.db.latest_transcript(eid)
        if tr:
            self.doc_text_box.insert("1.0", f"Engine: {tr.get('engine')} | Source: {tr.get('source_kind')} | Created: {pretty_date(tr.get('created_at'))}\n\n" + (tr.get("content") or ""))
            return
        if ev.type in {"document", "transcript"}:
            text, engine, ok = TextExtractor(self.log).extract(Path(ev.analysis_path))
            if ok and text.strip():
                self.doc_text_box.insert("1.0", f"Preview extractor: {engine}\nNot stored yet. Click Analyze to store timeline/events.\n\n{text}")
            else:
                self.doc_text_box.insert("1.0", f"No text extracted. Extractor result: {engine}")
        else:
            self.doc_text_box.insert("1.0", "No transcript stored for this evidence. Use Attach Transcript or Analyze with a real transcription engine.")

    def save_doc_box_as_attached(self) -> None:
        eid = self.combo_id(self.doc_var.get())
        ev = self.db.evidence(eid) if eid else None
        if not ev:
            messagebox.showinfo("Select evidence", "Choose evidence first.", parent=self)
            return
        text = self.doc_text_box.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo("No text", "The text box is empty.", parent=self)
            return
        # Strip preview headers if present only at user's discretion? Do not modify real data automatically.
        self.db.add_transcript(ev.id, text, "manual-textbox", "attached-transcript", 95, attached=True)
        Analyzer(self.db, self.log).timeline_from_text(ev, text, ev.type if ev.type in {"video", "audio"} else "attached-transcript")
        Analyzer(self.db, self.log).global_analysis()
        self.refresh_all()
        self.log(f"Saved text box as attached transcript for #{ev.id}.")

    def search_doc_box(self) -> None:
        term = self.doc_search_var.get().strip()
        if not term:
            return
        start = self.doc_text_box.search(term, "insert", stopindex="end", nocase=True)
        if not start:
            start = self.doc_text_box.search(term, "1.0", stopindex="end", nocase=True)
        if start:
            end = f"{start}+{len(term)}c"
            self.doc_text_box.tag_remove("search_hit", "1.0", "end")
            self.doc_text_box.tag_add("search_hit", start, end)
            self.doc_text_box.tag_config("search_hit", background="yellow")
            self.doc_text_box.mark_set("insert", end)
            self.doc_text_box.see(start)
        else:
            messagebox.showinfo("Not found", f"'{term}' not found.", parent=self)

    # ---------- timeline/review actions ----------

    def add_manual_event(self) -> None:
        eid = self.selected_evidence_id()
        if eid is None:
            # Let a global/manual event be created if no evidence selected.
            if not messagebox.askyesno("No evidence selected", "Create a global manual event not tied to a specific evidence file?", parent=self):
                return
        time_str = simpledialog.askstring("Event time", "Timestamp (MM:SS, HH:MM:SS, seconds, or blank):", parent=self)
        if time_str is None:
            return
        time_value = seconds_from_timestamp(time_str) if time_str.strip() else None
        category = simpledialog.askstring("Category", "Category:", initialvalue="Manual Review", parent=self)
        if category is None:
            return
        severity = simpledialog.askstring("Severity", "Severity: Info, Low, Medium, High, Critical", initialvalue="Medium", parent=self)
        if severity is None:
            return
        if severity not in SEVERITY_LEVELS:
            severity = "Medium"
        desc = simpledialog.askstring("Description", "Event description:", parent=self)
        if not desc:
            return
        ev = self.db.evidence(eid) if eid else None
        source = ev.display_name if ev else "Global Manual Event"
        self.db.add_event(eid, time_value, source, "Reviewer", category, severity, 100, desc, "manual,human-reviewed", review_status="Human-confirmed", created_by="human-reviewer", raw_text=desc)
        Analyzer(self.db, self.log).global_analysis()
        self.refresh_all()
        self.log("Manual timeline event added.")

    def mark_manual_force_moment(self) -> None:
        eid = self.selected_evidence_id()
        if eid is None:
            messagebox.showinfo("Select evidence", "Select the evidence that contains the force moment.", parent=self)
            return
        ev = self.db.evidence(eid)
        if not ev:
            return
        time_str = simpledialog.askstring("Force moment timestamp", "Exact force timestamp (MM:SS, HH:MM:SS, or seconds):", parent=self)
        if time_str is None:
            return
        time_value = seconds_from_timestamp(time_str)
        if time_value is None:
            messagebox.showerror("Invalid timestamp", "Enter a timestamp like 00:25, 01:02:33, or 25.0", parent=self)
            return
        desc = simpledialog.askstring("Force description", "Describe the force event:", initialvalue="Human-confirmed moment of force", parent=self)
        if not desc:
            return
        self.db.add_event(ev.id, time_value, ev.display_name, "Reviewer", "Use of Force", "Critical", 100, "HUMAN-CONFIRMED MOMENT OF FORCE: " + desc, "force,moment-of-force,physical-force,human-confirmed,manual", review_status="Human-confirmed", created_by="human-reviewer", raw_text=desc)
        Analyzer(self.db, self.log).global_analysis()
        self.refresh_all()
        self.tabs.select(self.force_tab)
        self.log(f"Manual force moment marked at {fmt_time(time_value)}.")

    def review_selected_event(self, status: str) -> None:
        event_id = self.selected_event_id
        if event_id is None:
            # Try current selected timeline row.
            sel = self.timeline_tree.selection()
            if sel:
                try:
                    event_id = int(self.timeline_tree.item(sel[0], "values")[0])
                except Exception:
                    event_id = None
        if event_id is None:
            messagebox.showinfo("Select event", "Select a timeline event first.", parent=self)
            return
        notes = simpledialog.askstring("Reviewer Notes", f"Notes for status '{status}' (optional):", parent=self) or ""
        self.db.update_event_review(event_id, status, notes)
        self.refresh_all()

    def toggle_selected_event_export(self) -> None:
        event_id = self.selected_event_id
        if event_id is None:
            messagebox.showinfo("Select event", "Select a timeline event first.", parent=self)
            return
        event = self.db.event(event_id)
        if not event:
            return
        include = not bool(event.get("export_include"))
        self.db.set_event_export(event_id, include)
        self.refresh_timeline()
        self.log(f"Timeline event #{event_id} export include set to {include}.")

    def review_selected_issue(self, status: str) -> None:
        issue_id = self.selected_issue_id
        if issue_id is None:
            sel = self.issues_tree.selection()
            if sel:
                try:
                    issue_id = int(self.issues_tree.item(sel[0], "values")[0])
                except Exception:
                    issue_id = None
        if issue_id is None:
            messagebox.showinfo("Select issue", "Select an issue first.", parent=self)
            return
        notes = simpledialog.askstring("Reviewer Notes", f"Notes for status '{status}' (optional):", parent=self) or ""
        self.db.update_issue_review(issue_id, status, notes)
        self.refresh_issues()
        self.log(f"Issue #{issue_id} reviewed as {status}.")

    def extract_frame_dialog(self) -> None:
        eid = self.selected_evidence_id() or self.combo_id(self.media_var.get())
        ev = self.db.evidence(eid) if eid else None
        if not ev:
            messagebox.showinfo("Select video", "Select video evidence first.", parent=self)
            return
        time_str = simpledialog.askstring("Frame timestamp", "Timestamp to extract (MM:SS, HH:MM:SS, or seconds):", parent=self)
        if time_str is None:
            return
        ts = seconds_from_timestamp(time_str)
        if ts is None:
            messagebox.showerror("Invalid timestamp", "Enter a timestamp like 00:25, 01:02:33, or 25.0", parent=self)
            return
        path, msg = MediaTools(self.db, self.log).extract_frame(ev, ts)
        if path:
            messagebox.showinfo("Frame extracted", f"Frame saved:\n{path}", parent=self)
            open_path(path)
        else:
            messagebox.showerror("Frame extraction failed", msg, parent=self)

    def extract_force_frame(self) -> None:
        force = Analyzer(self.db, self.log).force_moment()
        if not force:
            messagebox.showinfo("No force moment", "No force moment is detected yet.", parent=self)
            return
        eid = force.get("evidence_id")
        ev = self.db.evidence(eid) if eid else None
        if not ev or ev.type != "video":
            messagebox.showinfo("Not video", "The detected force event is not tied to video evidence. Select a video and use Extract Frame.", parent=self)
            return
        ts = force.get("event_time_seconds")
        if ts is None:
            messagebox.showinfo("No timestamp", "The detected force event has no timestamp.", parent=self)
            return
        path, msg = MediaTools(self.db, self.log).extract_frame(ev, float(ts))
        if path:
            messagebox.showinfo("Frame extracted", f"Frame saved:\n{path}", parent=self)
            open_path(path)
        else:
            messagebox.showerror("Frame extraction failed", msg, parent=self)

    # ---------- rules actions ----------

    def add_rule(self) -> None:
        editor = RuleEditor(self)
        self.wait_window(editor)
        if editor.result:
            self.db.save_rule(editor.result)
            self.refresh_rules()

    def edit_rule(self) -> None:
        rid = self.selected_rule_id
        if rid is None:
            messagebox.showinfo("Select rule", "Select a rule first.", parent=self)
            return
        rule = next((r for r in self.db.rules() if int(r.get("id")) == rid), None)
        if not rule:
            return
        editor = RuleEditor(self, rule)
        self.wait_window(editor)
        if editor.result:
            self.db.save_rule(editor.result, rid=rid)
            self.refresh_rules()

    def delete_rule(self) -> None:
        rid = self.selected_rule_id
        if rid is None:
            messagebox.showinfo("Select rule", "Select a rule first.", parent=self)
            return
        if not messagebox.askyesno("Delete rule", f"Delete rule #{rid}?", parent=self):
            return
        self.db.delete_rule(rid)
        self.refresh_rules()

    def reset_rules(self) -> None:
        if not messagebox.askyesno("Reset rules", "Replace all rules with the default rule set?", parent=self):
            return
        self.db.reset_rules()
        self.refresh_rules()
        self.log("Default rules restored.")

    def test_rules_text(self) -> None:
        text = simpledialog.askstring("Test Rules", "Enter text to test against enabled rules:", parent=self)
        if text is None:
            return
        matches = RuleMatcher(self.db.rules(enabled_only=True)).match(text)
        if not matches:
            messagebox.showinfo("Rule Test", "No enabled rules matched.", parent=self)
            return
        msg = "\n\n".join(f"{m.get('name')}\nCategory: {m.get('category')}\nSeverity: {m.get('severity')}\nExcerpt: {m.get('excerpt')}" for m in matches)
        messagebox.showinfo("Rule Test Matches", msg, parent=self)

    # ---------- export actions ----------

    def export_report(self, kind: str, mode: Optional[str] = None, public: bool = False) -> None:
        mode = mode or self.export_mode_var.get() if hasattr(self, "export_mode_var") else "Internal Review"
        exporter = Exporter(self.db)
        default_map = {
            "html": exporter.default_path("html", "public_report" if public else "report"),
            "zip": exporter.default_path("zip", "public_packet" if public else "packet"),
            "json": exporter.default_path("json", "case_data"),
            "timeline_csv": exporter.default_path("csv", "timeline"),
            "issues_csv": exporter.default_path("csv", "issues"),
            "summary_txt": exporter.default_path("txt", "summary"),
        }
        ext_map = {"html": ".html", "zip": ".zip", "json": ".json", "timeline_csv": ".csv", "issues_csv": ".csv", "summary_txt": ".txt"}
        path_str = filedialog.asksaveasfilename(title="Save export", initialfile=default_map[kind].name, initialdir=str(default_map[kind].parent), defaultextension=ext_map[kind])
        if not path_str:
            return
        path = Path(path_str)

        def work() -> None:
            try:
                exp = Exporter(self.db)
                if kind == "html":
                    out = exp.html_report(path, mode, public)
                elif kind == "zip":
                    out = exp.zip_packet(path, mode, public)
                elif kind == "json":
                    out = exp.json_export(path)
                elif kind == "timeline_csv":
                    out = exp.timeline_csv(path)
                elif kind == "issues_csv":
                    out = exp.issues_csv(path)
                elif kind == "summary_txt":
                    out = exp.summary_txt(path, mode)
                else:
                    raise ValueError(kind)
                self.post("export_done", str(out))
            except Exception as e:
                self.post("error", f"Export failed:\n{e}\n\n{traceback.format_exc()}")
        self._run_thread(work)

    # ---------- refresh/select handlers ----------

    def refresh_all(self) -> None:
        self._setup_style()
        self.refresh_case_info()
        self.refresh_dashboard()
        self.refresh_evidence()
        self.refresh_media_combo()
        self.refresh_doc_combo()
        self.refresh_live_evidence_combo()
        self.refresh_speaker_combo()
        self.refresh_timeline()
        self.refresh_force()
        self.refresh_issues()
        self.refresh_rules()
        self.refresh_settings()
        self.refresh_live_options()
        self.refresh_speakers()
        self.refresh_logs()

    def refresh_case_info(self) -> None:
        info = self.db.case_info()
        for key, var in self.case_vars.items():
            var.set(info.get(key, ""))
        if hasattr(self, "case_notes"):
            self.case_notes.delete("1.0", "end")
            self.case_notes.insert("1.0", info.get("case_notes", ""))

    def refresh_dashboard(self) -> None:
        info = self.db.case_info()
        stats = self.db.stats()
        force = Analyzer(self.db).force_moment()
        deps = dependency_status(self.db.settings())
        lines = [
            f"Case folder: {self.case_dir}",
            f"Title: {info.get('title', 'Untitled Case')}",
            f"Created: {pretty_date(info.get('created_at'))}",
            f"Updated: {pretty_date(info.get('updated_at'))}",
            "",
            "Evidence / analysis status",
            "--------------------------",
            f"Evidence: {stats['evidence']}",
            f"Analyzed: {stats['analyzed']}",
            f"Pending: {stats['pending']}",
            f"Failed: {stats['failed']}",
            f"Transcripts: {stats['transcripts']}",
            f"Media analyses: {stats['media_analysis']}",
            f"Speaker segments: {stats.get('speaker_segments', 0)}",
            f"Timeline events: {stats['events']}",
            f"Issues: {stats['issues']}",
            f"Force events: {stats['force_events']}",
            "",
            "Force moment",
            "------------",
        ]
        if force:
            lines.append(f"Earliest actual force: {force.get('event_time_text')} | {force.get('source_name')} | {force.get('description')}")
        else:
            lines.append("No actual force moment detected yet.")
        lines.extend(["", "Dependency status", "-----------------"])
        for k, v in deps.items():
            lines.append(f"{k}: {v}")
        self.stats_box.delete("1.0", "end")
        self.stats_box.insert("1.0", "\n".join(lines))

    def refresh_evidence(self) -> None:
        rows = []
        for ev in self.db.evidences():
            rows.append((ev.id, ev.display_name, ev.type, ev.status, human_size(ev.size), ev.sha256[:32] + "...", pretty_date(ev.imported_at), ev.source_label))
        self.set_tree_rows(self.evidence_tree, rows)
        self.on_evidence_select(clear_if_none=True)

    def refresh_media_combo(self) -> None:
        values = [f"#{ev.id} {ev.display_name} ({ev.type})" for ev in self.db.evidences({"video", "audio"})]
        self.media_combo["values"] = values
        if values and self.media_var.get() not in values:
            self.media_var.set(values[0])
        elif not values:
            self.media_var.set("")
        if self.media_var.get():
            self.load_media_review()

    def refresh_doc_combo(self) -> None:
        values = [f"#{ev.id} {ev.display_name} ({ev.type})" for ev in self.db.evidences()]
        self.doc_combo["values"] = values
        if values and self.doc_var.get() not in values:
            self.doc_var.set(values[0])
        elif not values:
            self.doc_var.set("")

    def refresh_timeline(self) -> None:
        events = self.db.events()
        search = self.filter_vars.get("search", tk.StringVar(value="")).get().lower() if self.filter_vars else ""
        severity = self.filter_vars.get("severity", tk.StringVar(value="All")).get() if self.filter_vars else "All"
        category = self.filter_vars.get("category", tk.StringVar(value="All")).get() if self.filter_vars else "All"
        status = self.filter_vars.get("status", tk.StringVar(value="All")).get() if self.filter_vars else "All"
        categories = sorted({e.get("category", "") for e in events if e.get("category")})
        if hasattr(self, "category_combo"):
            self.category_combo["values"] = ["All"] + categories
            if category not in ["All"] + categories:
                self.filter_vars["category"].set("All")
        filtered = []
        for e in events:
            blob = " ".join(str(e.get(k, "")) for k in ["source_name", "speaker", "category", "severity", "description", "tags", "review_status"]).lower()
            if search and search not in blob:
                continue
            if severity != "All" and e.get("severity") != severity:
                continue
            if category != "All" and e.get("category") != category:
                continue
            if status != "All" and e.get("review_status") != status:
                continue
            filtered.append(e)
        rows = [(e.get("id"), e.get("event_time_text"), e.get("source_name"), e.get("speaker"), e.get("category"), e.get("severity"), f"{float(e.get('confidence') or 0):.0f}%", e.get("description"), e.get("review_status")) for e in filtered]
        self.set_tree_rows(self.timeline_tree, rows)

    def clear_timeline_filters(self) -> None:
        self.filter_vars["search"].set("")
        self.filter_vars["severity"].set("All")
        self.filter_vars["category"].set("All")
        self.filter_vars["status"].set("All")
        self.refresh_timeline()

    def refresh_force(self) -> None:
        analyzer = Analyzer(self.db)
        force = analyzer.force_moment()
        self.force_summary.delete("1.0", "end")
        for item in self.force_context_tree.get_children():
            self.force_context_tree.delete(item)
        if not force:
            self.force_summary.insert("1.0", "No actual force moment detected yet.\n\nThe detector intentionally does not treat warnings such as 'Taser taser' as the actual moment of force. Actual force requires a force-use phrase, an attached/manual force event, or a rule tagged as moment-of-force/physical-force.")
            return
        lines = [
            "Earliest detected actual moment of force",
            "----------------------------------------",
            f"Time: {force.get('event_time_text')}",
            f"Source: {force.get('source_name')}",
            f"Category: {force.get('category')}",
            f"Severity: {force.get('severity')}",
            f"Confidence: {force.get('confidence')}%",
            f"Review status: {force.get('review_status')}",
            f"Description: {force.get('description')}",
            "",
            "Reviewer action: confirm this against the exact video frame/audio moment. Use manual mark if the exact moment differs.",
        ]
        self.force_summary.insert("1.0", "\n".join(lines))
        if force.get("event_time_seconds") is None:
            return
        ft = float(force["event_time_seconds"])
        window = 20.0
        nearby = [e for e in self.db.events() if e.get("event_time_seconds") is not None and abs(float(e.get("event_time_seconds")) - ft) <= window]
        rows = [(e.get("id"), e.get("event_time_text"), e.get("source_name"), e.get("category"), e.get("severity"), e.get("description"), e.get("review_status")) for e in nearby]
        self.set_tree_rows(self.force_context_tree, rows)

    def refresh_issues(self) -> None:
        rows = [(i.get("id"), i.get("severity"), i.get("category"), i.get("title"), f"{float(i.get('confidence') or 0):.0f}%", i.get("review_status")) for i in self.db.issues()]
        self.set_tree_rows(self.issues_tree, rows)

    def refresh_rules(self) -> None:
        rows = [(r.get("id"), "yes" if int(r.get("enabled", 0)) else "no", r.get("name"), r.get("category"), r.get("severity"), f"{float(r.get('confidence') or 0):.0f}%", r.get("pattern_type"), r.get("tags")) for r in self.db.rules()]
        self.set_tree_rows(self.rules_tree, rows)

    def refresh_settings(self) -> None:
        settings = self.db.settings()
        for key, var in self.setting_vars.items():
            var.set(settings.get(key, DEFAULT_SETTINGS.get(key, "")))

    def refresh_logs(self) -> None:
        if not hasattr(self, "audit_tree"):
            return
        rows = [(a.get("id"), pretty_date(a.get("created_at")), a.get("actor"), a.get("action"), a.get("detail")) for a in self.db.audits(1000)]
        self.set_tree_rows(self.audit_tree, rows)

    def on_evidence_select(self, clear_if_none: bool = False) -> None:
        eid = self.selected_evidence_id()
        self.evidence_notes.delete("1.0", "end")
        self.evidence_meta.delete("1.0", "end")
        if eid is None:
            if clear_if_none:
                return
            return
        ev = self.db.evidence(eid)
        if not ev:
            return
        self.evidence_notes.insert("1.0", ev.notes or "")
        self.evidence_meta.insert("1.0", short_json(ev.metadata, max_chars=30000))

    def on_timeline_select(self) -> None:
        sel = self.timeline_tree.selection()
        self.timeline_detail.delete("1.0", "end")
        if not sel:
            self.selected_event_id = None
            return
        try:
            eid = int(self.timeline_tree.item(sel[0], "values")[0])
        except Exception:
            self.selected_event_id = None
            return
        self.selected_event_id = eid
        event = self.db.event(eid)
        if event:
            self.timeline_detail.insert("1.0", short_json(event, max_chars=12000))

    def on_force_context_select(self) -> None:
        sel = self.force_context_tree.selection()
        if not sel:
            return
        try:
            eid = int(self.force_context_tree.item(sel[0], "values")[0])
            self.selected_event_id = eid
            event = self.db.event(eid)
            self.timeline_detail.delete("1.0", "end")
            if event:
                self.timeline_detail.insert("1.0", short_json(event, max_chars=12000))
        except Exception:
            pass

    def on_issue_select(self) -> None:
        sel = self.issues_tree.selection()
        self.issue_detail.delete("1.0", "end")
        if not sel:
            self.selected_issue_id = None
            return
        try:
            iid = int(self.issues_tree.item(sel[0], "values")[0])
        except Exception:
            self.selected_issue_id = None
            return
        self.selected_issue_id = iid
        issue = next((i for i in self.db.issues() if int(i.get("id")) == iid), None)
        if issue:
            lines = [
                f"Issue #{issue.get('id')}: {issue.get('title')}",
                f"Severity: {issue.get('severity')} | Category: {issue.get('category')} | Confidence: {float(issue.get('confidence') or 0):.0f}% | Status: {issue.get('review_status')}",
                "",
                "WHY THIS ISSUE WAS CREATED",
                str(issue.get('description') or ''),
                "",
                "EXACT TRIGGERING SOURCE EXAMPLES / EVIDENCE QUOTE",
                str(issue.get('evidence_quote') or 'No source quote stored.'),
                "",
                "RECOMMENDED REVIEWER ACTION",
                str(issue.get('recommendation') or ''),
                "",
                "REVIEWER NOTES",
                str(issue.get('reviewer_notes') or ''),
            ]
            self.issue_detail.insert("1.0", "\n".join(lines))

    def on_rule_select(self) -> None:
        sel = self.rules_tree.selection()
        self.rule_detail.delete("1.0", "end")
        if not sel:
            self.selected_rule_id = None
            return
        try:
            rid = int(self.rules_tree.item(sel[0], "values")[0])
        except Exception:
            self.selected_rule_id = None
            return
        self.selected_rule_id = rid
        rule = next((r for r in self.db.rules() if int(r.get("id")) == rid), None)
        if rule:
            self.rule_detail.insert("1.0", short_json(rule, max_chars=12000))

    def save_settings(self) -> None:
        data = {k: v.get() for k, v in self.setting_vars.items()}
        self.db.update_settings(data)
        self._setup_style()
        self.refresh_dashboard()
        self.log("Settings saved.")

    # ---------- help ----------

    def show_dependency_status(self) -> None:
        status = dependency_status(self.db.settings())
        msg = "\n".join(f"{k}: {v}" for k, v in status.items())
        messagebox.showinfo("Dependency Status", msg, parent=self)

    def about(self) -> None:
        messagebox.showinfo("About", f"{APP_NAME}\nVersion: {APP_VERSION}\n\nThis version does not generate mock transcripts. It uses real file metadata, optional real transcription/OCR dependencies, sidecar/attached transcripts, rule-based timeline review, and exportable case packets.", parent=self)

    def transcription_help(self) -> None:
        messagebox.showinfo("Real-Data Transcription Help", "Media speech analysis requires one of these real inputs:\n\n1. Attach a transcript to the selected media file.\n2. Put a sidecar file next to the media, such as video.transcript.txt, video.srt, or video.vtt.\n3. Install faster-whisper, openai-whisper, or Whisper CLI and keep Settings → transcribe_media enabled.\n\nThe app will not invent transcript text if none of those are available.", parent=self)

    def close(self) -> None:
        try:
            self.save_case_info()
        except Exception:
            pass
        try:
            self.db.close()
        except Exception:
            pass
        self.destroy()


def _passfail(name: str, ok: bool, detail: str = "", fix: str = "") -> str:
    tag = "[PASS]" if ok else "[FAIL]"
    msg = f"{tag} {name}"
    if detail:
        msg += f" — {detail}"
    if not ok and fix:
        msg += f" | FIX: {fix}"
    return msg


def dependency_status(settings: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    settings = settings or DEFAULT_SETTINGS
    ffmpeg = settings.get("ffmpeg_path", "ffmpeg") or "ffmpeg"
    ffprobe = settings.get("ffprobe_path", "ffprobe") or "ffprobe"
    py = sys.executable
    status: Dict[str, str] = {
        "App version": f"[PASS] {APP_NAME} {APP_VERSION}",
        "Python executable": f"[PASS] {py}",
        "Python version": f"[PASS] {sys.version.split()[0]}",
        "Platform": f"[PASS] {platform.platform()}",
        "ffmpeg": _passfail("ffmpeg", command_available(ffmpeg), ffmpeg, "Install ffmpeg or set ffmpeg_path"),
        "ffprobe": _passfail("ffprobe", command_available(ffprobe), ffprobe, "Install ffmpeg or set ffprobe_path"),
    }
    # Whisper engines
    status["faster-whisper"] = _passfail("faster-whisper Python module", module_available("faster_whisper"), "preferred fast local engine", f'"{py}" -m pip install -U faster-whisper')
    whisper_spec = importlib.util.find_spec("whisper")
    whisper_ok = whisper_spec is not None
    whisper_detail = "importable as module 'whisper'" if whisper_ok else "missing"
    status["openai-whisper package"] = _passfail("openai-whisper Python module", whisper_ok, whisper_detail, f'"{py}" -m pip uninstall -y whisper && "{py}" -m pip install -U openai-whisper')
    status["openai-whisper note"] = "[WARN] Dependency check avoids importing whisper to stay fast. If transcription says wrong package, run the uninstall/install command above."
    cli = settings.get("whisper_cli_path", "whisper") or "whisper"
    cli_exe = shlex.split(cli, posix=not sys.platform.startswith("win"))[0] if cli else "whisper"
    status["whisper CLI"] = _passfail("Whisper CLI", command_available(cli_exe), cli, "Set whisper_cli_path to the exact command that works in terminal")
    # Speaker diarization
    status["pyannote.audio"] = _passfail("pyannote.audio", module_available("pyannote.audio"), "speaker diarization", f'"{py}" -m pip install -U pyannote.audio torch')
    status["torch"] = _passfail("torch", module_available("torch"), "required by pyannote", f'"{py}" -m pip install -U torch')
    token = (settings.get("pyannote_auth_token", "") or os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_TOKEN") or "").strip()
    status["Hugging Face token"] = _passfail("Hugging Face token", bool(token), "configured" if token else "missing", "Set Settings → pyannote_auth_token or HF_TOKEN")
    tc_ok = module_available("torchcodec.decoders")
    tc_detail = "torchcodec.decoders appears importable" if tc_ok else "torchcodec.decoders not found/importable"
    status["TorchCodec AudioDecoder"] = ("[PASS] TorchCodec AudioDecoder — " + tc_detail) if tc_ok else ("[WARN] TorchCodec AudioDecoder — " + tc_detail + " | App workaround: keep diarization_preload_audio=1")
    status["pyannote preload workaround"] = _passfail("pyannote preload workaround", settings.get("diarization_preload_audio", "1") == "1", "ON - bypasses AudioDecoder file-path decoding", "Set diarization_preload_audio=1")
    # Document/OCR dependencies
    for mod, install in [("pypdf", "pypdf"), ("PyPDF2", "PyPDF2"), ("pdfminer", "pdfminer.six"), ("PIL", "pillow"), ("pytesseract", "pytesseract")]:
        status[mod] = _passfail(mod, module_available(mod), "optional", f'"{py}" -m pip install -U {install}')
    # Current speed settings
    speed_keys = ["whisper_engine", "whisper_model", "whisper_device", "whisper_compute_type", "whisper_cpu_threads", "whisper_beam_size", "whisper_language", "audio_analysis_enabled", "fast_transcription_first", "extract_audio_before_whisper", "reuse_cached_audio_for_whisper", "speaker_diarization_enabled", "diarization_preload_audio"]
    for key in speed_keys:
        status[f"setting:{key}"] = f"[PASS] {key}={settings.get(key, DEFAULT_SETTINGS.get(key,''))}"
    return status


def self_test() -> int:
    """Non-GUI smoke test using only real created files; no mock fallback."""
    tmp = Path(tempfile.mkdtemp(prefix="ai_case_review_selftest_"))
    print(f"Self-test case: {tmp}")
    db = DB(tmp)
    try:
        db.update_settings({
            "transcribe_media": "0",  # First media pass should not fake transcript.
            "audio_analysis_enabled": "1",
            "store_nonflag_transcript_lines": "1",
        })
        # Real document/transcript file.
        transcript_path = tmp / "bodycam_transcript.srt"
        transcript_path.write_text("""1
00:00:00,000 --> 00:00:04,000
Officer: Get on the ground.

2
00:00:15,000 --> 00:00:18,000
Officer: Stop resisting.

3
00:00:18,000 --> 00:00:21,000
Subject: I'm not resisting.

4
00:00:22,000 --> 00:00:24,000
Officer: Taser taser.

5
00:00:25,000 --> 00:00:27,000
Officer: Taser deployed.

6
00:00:31,000 --> 00:00:33,000
Subject: I can't breathe.
""", encoding="utf-8")
        report_path = tmp / "report.txt"
        report_path.write_text("Subject became agitated and non-compliant. Officer feared for safety and force was required. Taser was deployed.", encoding="utf-8")
        # Real WAV file: sine tone with a loud section.
        wav_path = tmp / "audio.wav"
        with wave.open(str(wav_path), "wb") as wf:
            rate = 16000
            wf.setnchannels(1)
            wf.setsampwidth(2)
            wf.setframerate(rate)
            frames = bytearray()
            for i in range(rate * 3):
                amp = 0.05 if i < rate else 0.8 if i < 2 * rate else 0.02
                sample = int(32767 * amp * math.sin(2 * math.pi * 440 * i / rate))
                frames += struct.pack("<h", sample)
            wf.writeframes(bytes(frames))
        eid_srt = db.add_evidence(transcript_path, copy_into_case=True)
        eid_report = db.add_evidence(report_path, copy_into_case=True)
        eid_audio = db.add_evidence(wav_path, copy_into_case=True)
        analyzer = Analyzer(db, print)
        analyzer.analyze(eid_srt, refresh_global=False)
        analyzer.analyze(eid_report, refresh_global=False)
        analyzer.analyze(eid_audio, refresh_global=False)
        analyzer.global_analysis()
        force = analyzer.force_moment()
        assert force, "Force moment not detected"
        assert force["event_time_text"] == "00:25", f"Expected 00:25 force moment, got {force}"
        assert "Taser deployed" in force["description"], force["description"]
        events = db.events()
        assert any(e["category"] == "Force Warning" and "Taser taser" in e["description"] for e in events), "force warning missing"
        assert any(e["category"] == "Audio Peak" for e in events), "real audio peak analysis missing"
        html_path = Exporter(db).html_report(tmp / "report.html", "Use-of-Force Review")
        json_path = Exporter(db).json_export(tmp / "case.json")
        zip_path = Exporter(db).zip_packet(tmp / "packet.zip")
        assert html_path.exists() and json_path.exists() and zip_path.exists(), "exports missing"
        print("Self-test passed.")
        print(f"Force moment: {force['event_time_text']} | {force['description']}")
        print(f"Events: {len(events)} | Issues: {len(db.issues())}")
        return 0
    finally:
        db.close()


def main() -> None:
    if "--self-test" in sys.argv:
        raise SystemExit(self_test())
    if "--dependency-check" in sys.argv:
        for k, v in dependency_status(DEFAULT_SETTINGS).items():
            print(f"{k}: {v}")
        raise SystemExit(0)
    case_dir: Optional[Path] = None
    for arg in sys.argv[1:]:
        if arg != "--self-test":
            case_dir = Path(arg).expanduser()
            break
    app = App(case_dir=case_dir)
    app.mainloop()


if __name__ == "__main__":
    main()
