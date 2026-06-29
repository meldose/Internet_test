#!/usr/bin/env python3
from __future__ import annotations

import textwrap
from pathlib import Path


PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT_MARGIN = 72
TOP_MARGIN = 72
BOTTOM_MARGIN = 72
LINE_HEIGHT = 16
FONT_SIZE = 12
TITLE_SIZE = 16


def escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pages(lines: list[str]) -> list[list[str]]:
    max_lines = int((PAGE_HEIGHT - TOP_MARGIN - BOTTOM_MARGIN) / LINE_HEIGHT)
    pages: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if len(current) >= max_lines:
            pages.append(current)
            current = []
        current.append(line)
    if current or not pages:
        pages.append(current)
    return pages


def build_content_stream(page_lines: list[str], is_first_page: bool) -> bytes:
    y_start = PAGE_HEIGHT - TOP_MARGIN
    parts: list[str] = ["BT"]

    if is_first_page:
        parts.append(f"/F1 {TITLE_SIZE} Tf")
        parts.append(f"{LEFT_MARGIN} {y_start} Td")
        parts.append("(Network Issue Summary - June 29, 2026) Tj")
        parts.append("T*")
        parts.append(f"/F1 {FONT_SIZE} Tf")
        parts.append("T*")
    else:
        parts.append(f"/F1 {FONT_SIZE} Tf")
        parts.append(f"{LEFT_MARGIN} {y_start} Td")

    for line in page_lines:
        parts.append(f"({escape_pdf_text(line)}) Tj")
        parts.append("T*")
    parts.append("ET")
    return "\n".join(parts).encode("ascii", errors="ignore")


def write_pdf(output_path: Path, body_lines: list[str]) -> None:
    pages = build_pages(body_lines)

    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    page_object_ids: list[int] = []
    content_object_ids: list[int] = []

    next_object_id = 4
    for index, page_lines in enumerate(pages):
        page_object_ids.append(next_object_id)
        content_object_ids.append(next_object_id + 1)
        next_object_id += 2
        objects.append(b"")
        objects.append(build_content_stream(page_lines, is_first_page=(index == 0)))

    kids = " ".join(f"{obj_id} 0 R" for obj_id in page_object_ids)
    objects[1] = f"<< /Type /Pages /Kids [ {kids} ] /Count {len(page_object_ids)} >>".encode("ascii")

    for idx, page_object_id in enumerate(page_object_ids):
        content_object_id = content_object_ids[idx]
        objects[page_object_id - 1] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_id} 0 R >>"
        ).encode("ascii")
        stream = objects[content_object_id - 1]
        objects[content_object_id - 1] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"
        )

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for object_number, payload in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{object_number} 0 obj\n".encode("ascii"))
        pdf.extend(payload)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )

    output_path.write_bytes(pdf)


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
        "- Several times, external internet failed while the gateway 192.168.2.1 was still reachable.",
        "  This means the local network stayed up, but internet beyond the router failed.",
        "- A few times, the gateway itself became unreachable.",
        "  This means the problem was between WSL/Windows and the router, or the router briefly stopped responding.",
        "- At least once, the default route disappeared briefly.",
        "  This points to a local network stack or routing issue.",
        "- At least once, ping, gateway, and DNS all failed together, then recovered within about 2 seconds.",
        "  This is a stronger local outage event.",
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
        "The logs point to unstable connectivity between the machine and the router, plus repeated upstream internet "
        "failures after the router. This does not look like only a website problem, only a DNS problem, or a permanent "
        "adapter failure.",
    ]

    wrapped_lines: list[str] = []
    for paragraph in paragraphs:
        if not paragraph:
            wrapped_lines.append("")
            continue
        wrapped_lines.extend(textwrap.wrap(paragraph, width=88) or [""])

    output_path = Path("network_issue_summary_20260629.pdf")
    write_pdf(output_path, wrapped_lines)


if __name__ == "__main__":
    main()
