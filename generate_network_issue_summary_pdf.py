#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path


OUTPUT_PDF = Path("network_issue_summary_20260629_readable.pdf")
OUTPUT_PS = Path("network_issue_summary_20260629_readable.ps")
OUTPUT_TABLE_PDF = Path("network_issue_summary_20260629_table.pdf")
OUTPUT_TABLE_PS = Path("network_issue_summary_20260629_table.ps")

PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT_MARGIN = 72
TOP_MARGIN = 72
BOTTOM_MARGIN = 72
TITLE_SIZE = 18
BODY_SIZE = 12
LINE_HEIGHT = 16


def ps_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pages(lines: list[str], lines_first_page: int, lines_other_pages: int) -> list[list[str]]:
    pages: list[list[str]] = []
    index = 0
    while index < len(lines):
        page_limit = lines_first_page if not pages else lines_other_pages
        pages.append(lines[index:index + page_limit])
        index += page_limit
    return pages or [[]]


def build_postscript(lines: list[str]) -> str:
    lines_first_page = int((PAGE_HEIGHT - TOP_MARGIN - BOTTOM_MARGIN - 48) / LINE_HEIGHT)
    lines_other_pages = int((PAGE_HEIGHT - TOP_MARGIN - BOTTOM_MARGIN) / LINE_HEIGHT)
    pages = build_pages(lines, lines_first_page, lines_other_pages)

    parts: list[str] = [
        "%!PS-Adobe-3.0",
        f"%%Pages: {len(pages)}",
        f"<< /PageSize [{PAGE_WIDTH} {PAGE_HEIGHT}] >> setpagedevice",
        "/FTitle /Helvetica-Bold findfont 18 scalefont def",
        "/FBody /Helvetica findfont 12 scalefont def",
    ]

    for page_number, page_lines in enumerate(pages, start=1):
        parts.append(f"%%Page: {page_number} {page_number}")
        parts.append("FBody setfont")
        y = PAGE_HEIGHT - TOP_MARGIN

        if page_number == 1:
            parts.append("FTitle setfont")
            parts.append(f"{LEFT_MARGIN} {y} moveto")
            parts.append(f"({ps_escape('Network Issue Summary - June 29, 2026')}) show")
            y -= 32
            parts.append("FBody setfont")

        for line in page_lines:
            parts.append(f"{LEFT_MARGIN} {y} moveto")
            parts.append(f"({ps_escape(line)}) show")
            y -= LINE_HEIGHT

        parts.append("showpage")

    parts.append("%%EOF")
    return "\n".join(parts) + "\n"


def build_table_report_lines() -> list[str]:
    rows = [
        ("12:56:13", "gateway", "Gateway 192.168.2.1 unreachable from WSL. Local path/router issue."),
        ("12:57:08", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("12:58:38", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("12:59:13", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("12:59:35", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("12:59:45", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("13:02:55", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("13:03:12", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("13:03:34", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("13:06:45", "routing", "Default route disappeared briefly; restored at 13:06:47."),
        ("13:09:55", "gateway", "Gateway unreachable from WSL. Local path/router issue."),
        ("13:11:10", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("13:11:43", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("13:13:34", "gateway+dns", "Gateway unreachable and DNS timed out; restored at 13:13:36."),
        ("13:14:33", "internet", "Gateway reachable and DNS OK, but external internet failed."),
        ("13:15:53", "internet", "Gateway reachable and DNS OK, but external internet failed."),
    ]

    lines = [
        "Report date: June 29, 2026 (local time UTC+02:00)",
        "",
        "Summary:",
        "The logs show intermittent network instability. Most failures were upstream internet",
        "losses with the gateway still reachable. A smaller number were local gateway or routing",
        "failures, which point to instability between the machine and the router.",
        "",
        "Event Table:",
        "Time       Type         Meaning",
        "---------- ------------ ------------------------------------------------------------",
    ]

    for event_time, event_type, meaning in rows:
        wrapped = textwrap.wrap(meaning, width=60) or [""]
        first = f"{event_time:<10} {event_type:<12} {wrapped[0]}"
        lines.append(first)
        for continuation in wrapped[1:]:
            lines.append(f"{'':<10} {'':<12} {continuation}")

    lines.extend(
        [
            "",
            "Overall conclusion:",
            "This is not mainly a clean Wi-Fi adapter disconnect. The WSL interface stayed up most",
            "of the time, kept the same IP address, and often still had DNS and the default route.",
            "The strongest evidence points to mixed local gateway instability plus repeated upstream",
            "internet loss beyond the router.",
        ]
    )
    return lines


def main() -> None:
    paragraphs = [
        "Summary for the network logs captured on June 29, 2026.",
        "",
        "Overall conclusion:",
        "The issue is intermittent network loss, not a clean Wi-Fi disconnect most of the time. "
        "The WSL interface eth2 usually stays up, keeps the same IP address 192.168.2.36, and often still "
        "has the default route and DNS working.",
        "",
        "What happened:",
        "- Several times, external internet failed while the gateway 192.168.2.1 was still reachable. "
        "This means the local network stayed up, but internet beyond the router failed.",
        "- A few times, the gateway itself became unreachable. This means the problem was between "
        "WSL/Windows and the router, or the router briefly stopped responding.",
        "- At least once, the default route disappeared briefly. This points to a local network stack "
        "or routing issue.",
        "- At least once, ping, gateway, and DNS all failed together, then recovered within about 2 seconds. "
        "This is a stronger local outage event.",
        "",
        "Times when internet was lost while the gateway was still reachable:",
        "- 12:57:08",
        "- 12:58:38",
        "- 12:59:13",
        "- 12:59:35",
        "- 12:59:45",
        "- 13:02:55",
        "- 13:03:12",
        "- 13:03:34",
        "- 13:11:10",
        "- 13:11:43",
        "- 13:14:33",
        "- 13:15:53",
        "",
        "Most important outage times:",
        "- 12:56:13: gateway unreachable.",
        "- 13:06:45: default route missing, restored at 13:06:47.",
        "- 13:13:34: gateway unreachable and DNS failed, restored at 13:13:36.",
        "",
        "Pattern seen in the logs:",
        "- Local gateway instability happened a few times.",
        "- Internet beyond the router failed many times.",
        "- WSL interface eth2 stayed up, so the problem is not simply interface down.",
        "",
        "Practical interpretation:",
        "The logs point to unstable connectivity between the machine and the router, plus repeated upstream "
        "internet failures after the router. This does not look like only a website problem, only a DNS problem, "
        "or a permanent adapter failure.",
    ]

    wrapped_lines: list[str] = []
    for paragraph in paragraphs:
        if not paragraph:
            wrapped_lines.append("")
            continue
        wrapped_lines.extend(textwrap.wrap(paragraph, width=86))

    OUTPUT_PS.write_text(build_postscript(wrapped_lines), encoding="utf-8")
    subprocess.run(["ps2pdf", str(OUTPUT_PS), str(OUTPUT_PDF)], check=True)

    table_lines = build_table_report_lines()
    OUTPUT_TABLE_PS.write_text(build_postscript(table_lines), encoding="utf-8")
    subprocess.run(["ps2pdf", str(OUTPUT_TABLE_PS), str(OUTPUT_TABLE_PDF)], check=True)


if __name__ == "__main__":
    main()
