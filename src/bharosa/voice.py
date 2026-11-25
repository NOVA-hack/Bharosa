"""Spoken warnings in English, Hindi and Kannada, cached so the demo works offline.

Engines, tried in order unless ``BHAROSA_VOICE_ENGINE`` picks one:

1. ``cache``      a clip already generated for this exact (engine, language, text)
2. ``elevenlabs`` only when BHAROSA_VOICE_ENGINE=elevenlabs and ELEVENLABS_API_KEY are set (paid, opt-in)
3. ``espeak``     espeak-ng on PATH (supports hi and kn)
4. ``sapi``       Windows built-in speech, when a voice for the language is installed
5. ``say``        macOS built-in speech
6. ``text``       no audio: the script is printed instead

The TTS service only ever receives the template text, never the parent's message.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import wave
from dataclasses import dataclass
from pathlib import Path

from .config import voice_cache_dir

ESPEAK_VOICES = {"en": "en-in", "hi": "hi", "kn": "kn"}
SAPI_CULTURES = {"en": "en-", "hi": "hi-IN", "kn": "kn-IN"}
ELEVEN_MODEL = "eleven_multilingual_v2"
ELEVEN_DEFAULT_VOICE = "21m00Tcm4TlvDq8ikWAM"


@dataclass
class VoiceResult:
    engine: str
    path: Path | None
    played: bool
    text: str
    cached: bool = False


def _key(engine: str, lang: str, text: str) -> str:
    return hashlib.sha256(f"{engine}|{lang}|{text}".encode("utf-8")).hexdigest()[:24]


def cache_path(engine: str, lang: str, text: str) -> Path:
    return voice_cache_dir() / f"{lang}-{engine}-{_key(engine, lang, text)}.wav"


def _find_cached(lang: str, text: str) -> Path | None:
    for engine in ("elevenlabs", "espeak", "sapi", "say"):
        p = cache_path(engine, lang, text)
        if p.exists() and p.stat().st_size > 44:
            return p
    return None


def _espeak(lang: str, text: str, out: Path) -> bool:
    exe = shutil.which("espeak-ng") or shutil.which("espeak")
    if not exe:
        return False
    r = subprocess.run([exe, "-v", ESPEAK_VOICES.get(lang, "en"), "-s", "140", "-w", str(out), text],
                       capture_output=True, timeout=60)
    return r.returncode == 0 and out.exists()


def _sapi(lang: str, text: str, out: Path) -> bool:
    if platform.system() != "Windows" or not shutil.which("powershell"):
        return False
    script = (
        "Add-Type -AssemblyName System.Speech;"
        "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer;"
        "$v = $s.GetInstalledVoices() | Where-Object { $_.VoiceInfo.Culture.Name -like ($env:BH_CULTURE + '*') } "
        "| Select-Object -First 1;"
        "if (-not $v) { exit 3 };"
        "$s.SelectVoice($v.VoiceInfo.Name); $s.Rate = -1;"
        "$s.SetOutputToWaveFile($env:BH_OUT); $s.Speak($env:BH_TEXT); $s.Dispose()"
    )
    env = dict(os.environ, BH_CULTURE=SAPI_CULTURES.get(lang, "en-"), BH_OUT=str(out), BH_TEXT=text)
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                       capture_output=True, timeout=60, env=env)
    return r.returncode == 0 and out.exists() and out.stat().st_size > 44


def _say(lang: str, text: str, out: Path) -> bool:
    if platform.system() != "Darwin" or not shutil.which("say"):
        return False
    aiff = out.with_suffix(".aiff")
    r = subprocess.run(["say", "-o", str(aiff), text], capture_output=True, timeout=60)
    if r.returncode != 0:
        return False
    r = subprocess.run(["afconvert", "-f", "WAVE", "-d", "LEI16", str(aiff), str(out)], capture_output=True)
    aiff.unlink(missing_ok=True)
    return r.returncode == 0 and out.exists()


def _elevenlabs(lang: str, text: str, out: Path) -> bool:
    key = os.environ.get("ELEVENLABS_API_KEY")
    if not key:
        return False
    import httpx

    voice = os.environ.get("ELEVENLABS_VOICE_ID", ELEVEN_DEFAULT_VOICE)
    r = httpx.post(
        f"https://api.elevenlabs.io/v1/text-to-speech/{voice}",
        params={"output_format": "pcm_16000"},
        headers={"xi-api-key": key},
        json={"text": text, "model_id": ELEVEN_MODEL},
        timeout=30,
    )
    if r.status_code != 200 or not r.content:
        return False
    with wave.open(str(out), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(16000)
        w.writeframes(r.content)
    return True


ENGINES = {"elevenlabs": _elevenlabs, "espeak": _espeak, "sapi": _sapi, "say": _say}


def synthesize(text: str, lang: str = "en", engine: str | None = None) -> tuple[str, Path | None, bool]:
    """Return (engine, wav_path or None, cached). Never raises for a missing engine."""
    engine = engine or os.environ.get("BHAROSA_VOICE_ENGINE")
    if engine == "text":
        return "text", None, False
    cached = _find_cached(lang, text) if engine in (None, "cache") else (
        cache_path(engine, lang, text) if cache_path(engine, lang, text).exists() else None)
    if cached:
        return cached.name.split("-")[1], cached, True
    order = [engine] if engine and engine in ENGINES else ["espeak", "sapi", "say"]
    for name in order:
        out = cache_path(name, lang, text)
        try:
            if ENGINES[name](lang, text, out):
                return name, out, False
        except Exception:
            out.unlink(missing_ok=True)
    return "text", None, False


def play(path: Path) -> bool:
    try:
        if platform.system() == "Windows":
            import winsound

            winsound.PlaySound(str(path), winsound.SND_FILENAME)
            return True
        for player in (["afplay"], ["aplay", "-q"], ["paplay"]):
            if shutil.which(player[0]):
                return subprocess.run(player + [str(path)], capture_output=True).returncode == 0
    except Exception:
        return False
    return False


def speak(text: str, lang: str = "en", engine: str | None = None, play_audio: bool = True) -> VoiceResult:
    name, path, cached = synthesize(text, lang, engine)
    played = bool(path) and play_audio and play(path)
    return VoiceResult(name, path, played, text, cached)


def warm_cache(lang_texts: list[tuple[str, str]], engine: str | None = None) -> list[VoiceResult]:
    """Pre-generate clips (bharosa voice cache) so the demo needs no network or TTS at run time."""
    return [speak(text, lang, engine, play_audio=False) for lang, text in lang_texts]
