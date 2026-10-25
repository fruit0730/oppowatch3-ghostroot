#!/usr/bin/env python3
"""Markdown -> .docx converter tailored for the OWW212 technical report.

Pure python-docx (no pandoc).  Understands the subset used by the report:
ATX headings (#/##/###), fenced code blocks, pipe tables, bullet/numbered
lists, blockquotes, inline **bold** / `code` / *em* / ~~strike~~ / [text](url),
and horizontal rules.

Usage:  python docs/md2docx.py <in.md> <out.docx> [--toc-after N]
"""
import re
import sys

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor, Cm

LATIN = "Times New Roman"
EAST = "宋体"
HEAD_EAST = "黑体"
MONO = "Consolas"


def set_east(run, east):
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:eastAsia"), east)


def shade(el, fill):
    """Apply background shading to a paragraph or table cell element."""
    pr = el.get_or_add_pPr() if el.tag.endswith("}p") else el.get_or_add_tcPr()
    sh = OxmlElement("w:shd")
    sh.set(qn("w:val"), "clear")
    sh.set(qn("w:color"), "auto")
    sh.set(qn("w:fill"), fill)
    pr.append(sh)


def field(par, instr, placeholder=""):
    r = par.add_run()
    f1 = OxmlElement("w:fldChar")
    f1.set(qn("w:fldCharType"), "begin")
    r._element.append(f1)
    r2 = par.add_run()
    it = OxmlElement("w:instrText")
    it.set(qn("xml:space"), "preserve")
    it.text = instr
    r2._element.append(it)
    r3 = par.add_run()
    f2 = OxmlElement("w:fldChar")
    f2.set(qn("w:fldCharType"), "separate")
    r3._element.append(f2)
    r4 = par.add_run(placeholder or "（在此按 F9 更新目录/页码）")
    r5 = par.add_run()
    f3 = OxmlElement("w:fldChar")
    f3.set(qn("w:fldCharType"), "end")
    r5._element.append(f3)
    return par


INLINE = re.compile(
    r"(\*\*[^*]+\*\*|`[^`]+`|~~.+?~~|\[[^\]]+\]\([^)]+\)|(?<!\*)\*[^*\n]+\*(?!\*))"
)


def add_inline(par, text, base_size=None):
    for piece in INLINE.split(text):
        if not piece:
            continue
        bold = code = em = strike = False
        link = None
        t = piece
        if t.startswith("**") and t.endswith("**"):
            bold, t = True, t[2:-2]
        elif t.startswith("`") and t.endswith("`"):
            code, t = True, t[1:-1]
        elif t.startswith("~~"):
            strike, t = True, t[2:-2]
        elif t.startswith("[") and "](" in t:
            m = re.match(r"\[([^\]]+)\]\(([^)]+)\)", t)
            link, t = m.group(2), m.group(1)
        elif t.startswith("*") and t.endswith("*"):
            em, t = True, t[1:-1]
        run = par.add_run(t)
        run.bold = bold or code is True and False
        run.bold = bold
        run.italic = em
        run.font.strike = strike
        if code:
            run.font.name = MONO
            run.font.size = Pt((base_size or 10.5) - 0.5)
            run.font.color.rgb = RGBColor(0x8B, 0x1C, 0x1C)
            set_east(run, EAST)
        else:
            set_east(run, EAST)
        if link:
            run.font.color.rgb = RGBColor(0x1F, 0x49, 0x7D)
            run.font.underline = True
    return par


def para(doc, text, style=None, size=10.5, space_after=4, indent=None):
    p = doc.add_paragraph(style=style)
    pf = p.paragraph_format
    pf.space_after = Pt(space_after)
    pf.line_spacing = 1.35
    if indent is not None:
        pf.left_indent = Cm(indent)
    add_inline(p, text, base_size=size)
    for r in p.runs:
        if r.font.name != MONO:
            r.font.name = LATIN
            r.font.size = Pt(size)
    return p


def code_block(doc, lines):
    p = doc.add_paragraph()
    pf = p.paragraph_format
    pf.space_after = Pt(6)
    pf.space_before = Pt(6)
    pf.line_spacing = 1.0
    pf.left_indent = Cm(0.4)
    shade(p._element, "F4F4F4")
    txt = "\n".join(lines)
    run = p.add_run(txt)
    run.font.name = MONO
    run.font.size = Pt(8.5)
    set_east(run, "宋体")
    return p


def table(doc, rows):
    head = [c.strip() for c in rows[0].strip().strip("|").split("|")]
    body = []
    for r in rows[1:]:
        cells = [c.strip() for c in r.strip().strip("|").split("|")]
        if len(cells) < len(head):
            cells += [""] * (len(head) - len(cells))
        elif len(cells) > len(head):
            cells = cells[: len(head) - 1] + ["|".join(cells[len(head) - 1 :])]
        body.append(cells)
    t = doc.add_table(rows=1 + len(body), cols=len(head))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for j, h in enumerate(head):
        cell = t.rows[0].cells[j]
        cell.text = ""
        p = cell.paragraphs[0]
        add_inline(p, h)
        for r in p.runs:
            r.bold = True
            r.font.size = Pt(9)
            r.font.name = LATIN
            set_east(r, HEAD_EAST)
        shade(cell._tc, "E8EEF7")
    for i, row in enumerate(body):
        for j in range(len(head)):
            cell = t.rows[i + 1].cells[j]
            cell.text = ""
            p = cell.paragraphs[0]
            add_inline(p, row[j])
            for r in p.runs:
                r.font.size = Pt(8.5)
                if r.font.name != MONO:
                    r.font.name = LATIN
                    set_east(r, EAST)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def heading(doc, text, level):
    h = doc.add_heading("", level=level)
    h.paragraph_format.space_before = Pt(12 if level <= 2 else 8)
    h.paragraph_format.space_after = Pt(6)
    run = h.add_run(text)
    run.font.name = LATIN
    sizes = {1: 16, 2: 13.5, 3: 12, 4: 11}
    run.font.size = Pt(sizes.get(level, 11))
    run.font.color.rgb = RGBColor(0x1F, 0x3B, 0x63)
    set_east(run, HEAD_EAST)
    if level == 1:
        run.bold = True
    return h


def convert(md_path, docx_path):
    src = open(md_path, encoding="utf-8").read().splitlines()
    doc = Document()
    st = doc.styles["Normal"]
    st.font.name = LATIN
    st.font.size = Pt(10.5)
    st.element.rPr.rFonts.set(qn("w:eastAsia"), EAST)
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    sec.left_margin = sec.right_margin = Cm(2.4)
    sec.top_margin = sec.bottom_margin = Cm(2.4)

    # footer page number
    fp = sec.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    field(fp, "PAGE")
    for r in fp.runs:
        r.font.size = Pt(8)

    in_code = False
    code_lines = []
    tbl = []
    i = 0
    n = len(src)
    while i < n:
        line = src[i]
        s = line.rstrip()

        if s.startswith("```"):
            if in_code:
                code_block(doc, code_lines)
                code_lines, in_code = [], False
            else:
                in_code = True
            i += 1
            continue
        if in_code:
            code_lines.append(line)
            i += 1
            continue

        if s.strip().startswith("|"):
            tbl.append(s)
            i += 1
            if i < n and src[i].strip().startswith("|"):
                continue
            rows = [r for r in tbl if not re.match(r"^\s*\|[\s:\-\|]+\|\s*$", r)]
            if len(rows) >= 2:
                table(doc, rows)
            tbl = []
            continue

        if not s.strip():
            i += 1
            continue
        if re.match(r"^-{3,}$", s.strip()):
            i += 1
            continue

        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            lvl = min(len(m.group(1)), 4)
            heading(doc, m.group(2).strip(), lvl)
            i += 1
            continue

        m = re.match(r"^\s*[-*]\s+(.*)$", s)
        if m:
            para(doc, m.group(1), style="List Bullet", space_after=2, size=10.5)
            i += 1
            continue
        m = re.match(r"^\s*(\d+)[.)]\s+(.*)$", s)
        if m:
            para(doc, m.group(2), style="List Number", space_after=2, size=10.5)
            i += 1
            continue
        m = re.match(r"^>\s?(.*)$", s)
        if m:
            p = para(doc, m.group(1), size=10, space_after=2, indent=0.6)
            shade(p._element, "F7F7F2")
            i += 1
            continue

        para(doc, s.strip())
        i += 1

    if in_code and code_lines:
        code_block(doc, code_lines)

    insert_toc(doc)
    doc.save(docx_path)
    print("wrote", docx_path)


def insert_toc(doc):
    """Put a real Word TOC field just before the first '摘要' heading."""
    target = None
    for p in doc.paragraphs:
        if p.style.name.startswith("Heading") and p.text.strip().startswith("摘要"):
            target = p
            break
    if target is None:
        return
    h = doc.add_paragraph(style="Heading 1")
    r = h.add_run("目录")
    r.font.name = LATIN
    r.font.size = Pt(14)
    r.font.color.rgb = RGBColor(0x1F, 0x3B, 0x63)
    set_east(r, HEAD_EAST)
    t = doc.add_paragraph()
    field(t, r'TOC \o "1-3" \h \z \u', "（在 Word 中右键此处 → 更新域，即可生成目录）")
    br = doc.add_paragraph()
    rb = br.add_run()
    b = OxmlElement("w:br")
    b.set(qn("w:type"), "page")
    rb._element.append(b)
    for el in (h._element, t._element, br._element):
        target._element.addprevious(el)


if __name__ == "__main__":
    convert(sys.argv[1], sys.argv[2])
