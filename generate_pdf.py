#!/usr/bin/env python3
"""
pixelproof pdf — Generate a professional PDF report from a Markdown analysis file.

Usage:
    python generate_pdf.py <markdown_file> [output.pdf]

Requires:
    pip install markdown2 weasyprint
    brew install pango  (macOS)
"""
import sys
import os
import markdown2


def generate_pdf(md_path, pdf_path=None):
    """Convert a Markdown file to a styled forensic report PDF."""
    if pdf_path is None:
        pdf_path = os.path.splitext(md_path)[0] + ".pdf"

    with open(md_path, "r") as f:
        md_content = f.read()

    html_body = markdown2.markdown(
        md_content,
        extras=["tables", "fenced-code-blocks", "code-friendly", "break-on-newline"],
    )

    css = """
@page {
    size: letter;
    margin: 0.75in 0.85in;
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9px;
        color: #888;
        font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    }
    @top-center {
        content: "PIXELPROOF FORENSIC REPORT";
        font-size: 8px;
        color: #aaa;
        font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
        letter-spacing: 2px;
        text-transform: uppercase;
    }
}
body {
    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
    font-size: 11px; line-height: 1.6; color: #1a1a1a;
}
h1 {
    font-size: 22px; font-weight: 700; color: #111;
    border-bottom: 3px solid #c0392b; padding-bottom: 8px; margin-top: 0;
}
h2 {
    font-size: 16px; font-weight: 700; color: #2c3e50;
    border-bottom: 1.5px solid #bdc3c7; padding-bottom: 5px;
    margin-top: 28px; page-break-after: avoid;
}
h3 {
    font-size: 13px; font-weight: 700; color: #34495e;
    margin-top: 18px; page-break-after: avoid;
}
h4 {
    font-size: 12px; font-weight: 700; color: #555;
    margin-top: 14px; page-break-after: avoid;
}
p { margin: 6px 0; }
strong { color: #111; }
blockquote {
    border-left: 4px solid #c0392b; background: #fdf2f2;
    padding: 10px 14px; margin: 12px 0; font-style: normal; color: #333;
}
table {
    width: 100%; border-collapse: collapse; margin: 10px 0;
    font-size: 10px; page-break-inside: avoid;
}
th {
    background: #2c3e50; color: white; font-weight: 600;
    text-align: left; padding: 6px 8px; font-size: 10px;
}
td {
    padding: 5px 8px; border-bottom: 1px solid #ddd; vertical-align: top;
}
tr:nth-child(even) { background: #f7f9fa; }
code {
    background: #f4f4f4; padding: 1px 4px; border-radius: 3px;
    font-family: 'Menlo', 'Courier New', monospace; font-size: 10px; color: #c0392b;
}
pre {
    background: #1e1e1e; color: #d4d4d4; padding: 12px 14px;
    border-radius: 4px; font-family: 'Menlo', 'Courier New', monospace;
    font-size: 9.5px; line-height: 1.5; page-break-inside: avoid;
}
pre code { background: none; color: #d4d4d4; padding: 0; }
hr { border: none; border-top: 1px solid #ccc; margin: 20px 0; }
ul, ol { margin: 6px 0; padding-left: 24px; }
li { margin: 3px 0; }
"""

    html_doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><style>{css}</style></head>
<body>{html_body}</body></html>"""

    from weasyprint import HTML

    HTML(string=html_doc).write_pdf(pdf_path)

    size_kb = os.path.getsize(pdf_path) / 1024
    print(f"✓ PDF generated: {pdf_path} ({size_kb:.1f} KB)")
    return pdf_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python generate_pdf.py <markdown_file> [output.pdf]")
        sys.exit(1)

    md_path = sys.argv[1]
    pdf_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.isfile(md_path):
        print(f"Error: file not found — {md_path}")
        sys.exit(1)

    generate_pdf(md_path, pdf_path)


if __name__ == "__main__":
    main()
