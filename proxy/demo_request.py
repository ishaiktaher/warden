"""Deterministic parsing for the local Wispr Flow comparison demo."""

from pathlib import Path
import re


_AUTHORITY = r"(?:authorized?\s+maximum|maximum(?:\s+spend|\s+price)?|max(?:imum)?\s+spend|spending\s+limit|limit|budget|authorize(?:d)?(?:\s+up\s+to)?|up\s+to)"
_LIMIT_PATTERNS = (
    re.compile(
        _AUTHORITY + r"[^0-9₹]{0,50}(?:₹|INR\s*)?([0-9][0-9,]*(?:\.\d+)?)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:₹|INR\s*)?([0-9][0-9,]*(?:\.\d+)?)\s*(?:rupees?)?\s*(?:maximum|max|limit|budget)",
        re.IGNORECASE,
    ),
)
_NUMBER_WORDS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
    "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14,
    "fifteen": 15, "sixteen": 16, "seventeen": 17, "eighteen": 18,
    "nineteen": 19, "twenty": 20, "thirty": 30, "forty": 40,
    "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90,
}
_WORD_LIMIT_PATTERN = re.compile(
    _AUTHORITY
    + r"(?:\s+(?:of|is|at|to|rupees?|INR)){0,4}\s+"
    + r"((?:(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|lakh|and)[ -]*)+)",
    re.IGNORECASE,
)
_PRICE_PATTERN = re.compile(r'data-flight-price-inr="([0-9]+(?:\.[0-9]+)?)"')


def infer_authorized_maximum(instruction: str) -> float:
    for pattern in _LIMIT_PATTERNS:
        match = pattern.search(instruction)
        if match:
            return float(match.group(1).replace(",", ""))

    word_match = _WORD_LIMIT_PATTERN.search(instruction)
    if word_match:
        return float(_parse_number_words(word_match.group(1)))
    raise ValueError(
        "State an explicit maximum, for example: I authorize up to ₹5,000"
    )


def _parse_number_words(value: str) -> int:
    total = 0
    current = 0
    found = False
    for word in re.findall(r"[a-z]+", value.lower()):
        if word == "and":
            continue
        if word in _NUMBER_WORDS:
            current += _NUMBER_WORDS[word]
            found = True
        elif word == "hundred":
            current = max(current, 1) * 100
            found = True
        elif word in {"thousand", "lakh"}:
            scale = 1_000 if word == "thousand" else 100_000
            total += max(current, 1) * scale
            current = 0
            found = True
        else:
            break
    if not found or total + current <= 0:
        raise ValueError("maximum spend must be greater than zero")
    return total + current


def read_demo_flight_price(page: Path) -> float:
    match = _PRICE_PATTERN.search(page.read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError("Demo flight page has no structured price")
    return float(match.group(1))
