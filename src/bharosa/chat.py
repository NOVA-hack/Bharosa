"""Parse exported chats (WhatsApp 'Export chat' .txt) into messages for bharosa check chat."""

from __future__ import annotations

import re
from dataclasses import dataclass

# 12/03/26, 10:15 pm - Sender: text     |  [12/03/2026, 22:15:03] Sender: text
_LINE_RE = re.compile(
    r"^\[?(?P<date>\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4}),?\s+(?P<time>\d{1,2}:\d{2}(?::\d{2})?\s*(?:[ap]\.?m\.?)?)\]?"
    r"\s*(?:-\s*)?(?P<sender>[^:]{1,60}):\s(?P<text>.*)$",
    re.IGNORECASE,
)


@dataclass
class ChatMessage:
    index: int
    when: str
    sender: str
    text: str


def parse_chat(raw: str) -> list[ChatMessage]:
    msgs: list[ChatMessage] = []
    for line in raw.splitlines():
        line = line.replace("‎", "").replace(" ", " ").rstrip()
        m = _LINE_RE.match(line)
        if m:
            msgs.append(ChatMessage(len(msgs) + 1, f"{m['date']} {m['time']}".strip(), m["sender"].strip(),
                                    m["text"]))
        elif msgs and line:
            msgs[-1].text += "\n" + line  # continuation of a multi-line message
        elif line:
            msgs.append(ChatMessage(len(msgs) + 1, "", "", line))
    return [m for m in msgs if m.text.strip() and m.text.strip() not in ("<Media omitted>", "This message was deleted")]
