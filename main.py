#!/usr/bin/env python3
"""
Static-analysis linter for a web/Odoo project tree.

Checks
──────
Images   : unreferenced image files
SCSS     : position:absolute / font-family not using o-website-value() / @extend
XML      : many rules – see inline comments
"""

import os
import re
import sys

# ── ANSI colours ─────────────────────────────────────────────────────────────
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def red(s):    return f"{RED}{s}{RESET}"
def green(s):  return f"{GREEN}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def bold(s):   return f"{BOLD}{s}{RESET}"
def dim(s):    return f"{DIM}{s}{RESET}"

# ── Constants ─────────────────────────────────────────────────────────────────
IMAGE_EXTENSIONS  = {".webp", ".jpg", ".jpeg", ".png", ".gif", ".svg"}
SOURCE_EXTENSIONS = {".scss", ".xml", ".py"}
BREAKPOINTS       = {"xs", "sm", "md", "lg", "xl", "xxl", "print"}

# XML – class-based checks
FORBIDDEN_CLASS_TOKENS = {"pb0", "pt0", "o_default_snippet_text", "o_we_custom_image"}
FORBIDDEN_CLASS_PAIRS = [
    ("row",             {"d-flex", "align-items-stretch", "flex-row", "pt*", "pb*", "py*"}),
    ("container",       {"w-100", "mx-auto", "d-block"}),
    ("container-fluid", {"w-100", "mx-auto", "d-block"}),
    ("d-*",             {"d-*"}),
    ("pt-#",            {"pb-#"}),
    ("mt-#",            {"mb-#"}),
    ("me-#",            {"ms-#"}),
    ("shadow",          {"shadow-*"}),
    ("overflow-*",      {"overflow-*"}),
    ("img-fluid",       {"mw-100"}),
    ("d-flex",          {"flex-row", "align-items-stretch"}),
]
CLASS_ATTRS = {"class", "t-att-class", "t-attf-class"}

# XML – data-attribute names to forbid
FORBIDDEN_ATTRIBUTES = {
    ("loading", "lazy"),
    "data-mimetype",
    "data-aspect-ratio",
    "data-original-id",
    "data-original-src",
    "data-original-title",
    "data-scale-x",
    "data-scale-y"
}

EMPTY_ATTRS = {"add", "remove", "style"}

# XML – text-align replacements
FORBIDDEN_STYLE = {
    "background-image: none;",
    "padding:",
    "padding-*:",
    "margin:",
    "margin-*:",
    ("position: *;", "position-*"),
    ("text-align: center;", "text-center"),
    ("text-align: left;", "text-start"),
    ("text-align: right;", "text-end"),
    ("border-left-color", "border-{color}"),
    ("border-bottom-color", "border-{color}"),
    ("border-right-color", "border-{color}"),
    ("border-top-color", "border-{color}"),
}

# HTML void / self-closing elements that are legitimately empty
VOID_ELEMENTS = {
    "img", "br", "hr", "input", "link", "meta",
    "area", "base", "col", "embed", "param",
    "source", "track", "wbr",
}

# ── Helpers ───────────────────────────────────────────────────────────────────

def find_files(root: str, extensions: set) -> list[str]:
    matches = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in extensions:
                matches.append(os.path.join(dirpath, fn))
    return sorted(matches)


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""

def _pattern_prefix(pattern: str) -> str | None:
    return pattern[:-1] if pattern.endswith(("*", "#")) else None

def _matches_class_pattern(token: str, pattern: str) -> bool:
    prefix = _pattern_prefix(pattern)
    return token.startswith(prefix) if prefix else token == pattern

def _pattern_is_exact(pattern: str) -> bool:
    return pattern.endswith("#")

def _get_suffix(token: str, prefix: str) -> str:
    """Return everything after the prefix."""
    return token[len(prefix):]

def _get_breakpoint(token: str, prefix: str) -> str:
    rest = token[len(prefix):]
    first = rest.split("-")[0]
    return first if first in BREAKPOINTS else ""

def class_tokens(value: str) -> set[str]:
    """Split a class-like attribute value into individual tokens."""
    return set(re.split(r"[\s\"'{}()+,|]+", value))


Violation = tuple[int, str]   # (line_number, message)   line_number=0 → file-level


def _fmt(violations: list[Violation]) -> list[str]:
    return [f"  line {ln}: {msg}" if ln else f"  {msg}" for ln, msg in violations]


# ─────────────────────────────────────────────────────────────────────────────
# SCSS checks
# ─────────────────────────────────────────────────────────────────────────────

def check_scss_file(path: str) -> list[Violation]:
    violations: list[Violation] = []
    lines = read_text(path).splitlines()

    for i, raw in enumerate(lines, 1):
        line = raw.strip()

        # Skip pure comment lines
        if line.startswith("//") or line.startswith("*"):
            continue

        # 1. position: absolute
        if re.search(r'position\s*:\s*absolute', line):
            violations.append((i, f"position: absolute  (consider using odoo's o-position-absolute mixin)"))

        # 2. font-family not using o-website-value()
        m = re.search(r'font-family\s*:', line)
        if m:
            value_part = line[m.end():]
            if "o-website-value(" not in value_part and "ico" not in value_part:
                violations.append((i, f"font-family without o-website-value()  →  \"{line.strip()}\""))

        # 3. @extend
        if re.match(r'\s*@extend\b', raw):
            violations.append((i, f"@extend detected  →  \"{line.strip()}\""))

    return violations


# ─────────────────────────────────────────────────────────────────────────────
# XML checks  (line-by-line + full-content regex for multi-line patterns)
# ─────────────────────────────────────────────────────────────────────────────

# Regex to grab all attributes of a tag as a raw string (handles most template tags)
_TAG_RE   = re.compile(r'<([A-Za-z][A-Za-z0-9_:-]*)((?:\s[^>]*?)?)/?>',   re.DOTALL)
_ATTR_RE  = re.compile(r"""([\w:@-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")
_HEADING_RE = re.compile(r'<(h[1-6])\b', re.IGNORECASE)

def _attrs(attr_str: str) -> dict[str, str]:
    """Return {name: value} for all attributes in a raw attribute string."""
    return {m.group(1): (m.group(2) if m.group(2) is not None else m.group(3))
            for m in _ATTR_RE.finditer(attr_str)}


def check_xml_file(path: str, scss_js_content: str = "") -> list[Violation]:
    content = read_text(path)
    if not content:
        return []

    violations: list[Violation] = []
    lines      = content.splitlines()

    # ── per-line tag scan ──────────────────────────────────────────────────
    for lineno, raw in enumerate(lines, 1):

        for tag_m in _TAG_RE.finditer(raw):
            tag      = tag_m.group(1)
            attr_str = tag_m.group(2) or ""
            attrs    = _attrs(attr_str)

            # ---- class-based helpers ----
            all_class_vals = [attrs.get(a, "") for a in CLASS_ATTRS]
            all_tokens: set[str] = set()
            for v in all_class_vals:
                all_tokens |= class_tokens(v)

            # 1. Forbidden class tokens: pb0 / pt0
            bad_cls = FORBIDDEN_CLASS_TOKENS & all_tokens
            if bad_cls:
                violations.append((lineno,
                    f"<{tag}> has forbidden class token(s): {', '.join(sorted(bad_cls))}"))

            # 2. duplicate classes
            for attr in CLASS_ATTRS:
                raw_val = attrs.get(attr, "")
                if raw_val:
                    cleaned = re.sub(r'#\{[^}]*\}|\{\{[^}]*\}\}', '', raw_val)
                    tokens_list = [t for t in re.split(r"[\s\"'{}()+,|]+", cleaned) if t]
                    seen, dupes = set(), set()
                    for t in tokens_list:
                        (dupes if t in seen else seen).add(t)
                    if dupes:
                        violations.append((lineno,
                            f"<{tag}> has duplicate class(es): {', '.join(sorted(dupes))}"))

            # 3. <img> without alt
            if tag == "img" and "alt" not in attrs and "t-att-alt" not in attrs:
                violations.append((lineno, "<img> tag is missing an 'alt' attribute"))

            # 4. forbidden attributes (exact name, or name+value pair)
            for entry in FORBIDDEN_ATTRIBUTES:
                if isinstance(entry, tuple):
                    attr_name, forbidden_val = entry
                    if attrs.get(attr_name, "").lower() == forbidden_val:
                        violations.append((lineno,
                            f"<{tag}> has forbidden attribute '{attr_name}=\"{forbidden_val}\"'"))
                else:
                    if entry in attrs:
                        violations.append((lineno,
                            f"<{tag}> has forbidden attribute '{entry}'"))

            # 5. empty EMPTY_ATTRS attributes
            for ea in EMPTY_ATTRS:
                if ea in attrs and attrs[ea].strip() == "":
                    violations.append((lineno, f"<{tag}> has empty '{ea}' attribute"))

            # 6. width / height must be pure numbers
            for dim_attr in ("width", "height"):
                dim_val = attrs.get(dim_attr, None)
                if dim_val is not None and not re.fullmatch(r'\d+', dim_val.strip()):
                    violations.append((lineno,
                        f"<{tag}> has non-numeric '{dim_attr}' attribute value: \"{dim_val}\""))

            # 7. style checks
            style_val = attrs.get("style", None)
            if style_val is not None:
                for entry in FORBIDDEN_STYLE:
                    if isinstance(entry, str):
                        prop = entry.rstrip("*:").rstrip("-")
                        if re.search(r'(?<![a-zA-Z-])\b' + re.escape(prop) + r'[-\w]*\s*:', style_val):
                            violations.append((lineno,
                                f"<{tag}> has \"{entry}\" in style attribute — remove it"))
                    else:
                        needle, suggestion = entry
                        prop, _, pattern_val = needle.partition(": ")
                        if pattern_val.rstrip(";").strip() == "*":
                            m = re.search(
                                r'(?<![a-zA-Z-])\b' + re.escape(prop) + r'\s*:\s*([^;]+);',
                                style_val,
                            )
                            if m:
                                actual_val = m.group(1).strip()
                                class_suggestion = suggestion.replace("*", actual_val)
                                violations.append((lineno,
                                    f"<{tag}> has \"{prop}: {actual_val};\" in style"
                                    f" — use CSS class '{class_suggestion}' instead"))
                        else:
                            if prop in style_val:
                                violations.append((lineno,
                                    f"<{tag}> has \"{prop}\" in style"
                                    f" — use CSS class '{suggestion}' instead"))

            # 8. x_wd_ classes not referenced in SCSS/JS
            for token in all_tokens:
                if token.startswith("x_wd_") and not token.startswith("x_wd_i_") and token not in scss_js_content:
                    violations.append((lineno,
                        f"<{tag}> uses class '{token}' which is not referenced in any SCSS or JS file"))

            # 9. forbidden class combinations
            for anchor_pattern, forbidden_patterns in FORBIDDEN_CLASS_PAIRS:
                anchor_prefix = _pattern_prefix(anchor_pattern)
                anchor_tokens = (
                    {t for t in all_tokens if t.startswith(anchor_prefix)}
                    if anchor_prefix else
                    ({anchor_pattern} if anchor_pattern in all_tokens else set())
                )
                for anchor_token in anchor_tokens:
                    anchor_suffix = _get_suffix(anchor_token, anchor_prefix) if anchor_prefix else ""
                    anchor_bp = _get_breakpoint(anchor_token, anchor_prefix) if anchor_prefix else ""
                    bad = set()
                    for t in all_tokens:
                        if t == anchor_token:
                            continue
                        for p in forbidden_patterns:
                            if not _matches_class_pattern(t, p):
                                continue
                            p_prefix = _pattern_prefix(p)
                            if _pattern_is_exact(p):
                                t_suffix = _get_suffix(t, p_prefix) if p_prefix else ""
                                if t_suffix == anchor_suffix:
                                    bad.add(t)
                            else:
                                t_bp = _get_breakpoint(t, p_prefix) if p_prefix else ""
                                if t_bp == anchor_bp:
                                    bad.add(t)
                    if bad:
                        violations.append((lineno,
                            f"<{tag}> combines '{anchor_token}' with forbidden class(es): {', '.join(sorted(bad))}"))

    # 10. No headings inside <div id="footer">
    for footer_m in re.finditer(r'<div\b[^>]*\bid=["\']footer["\'][^>]*>(.*?)</div\s*>', content, re.DOTALL | re.IGNORECASE):
        headings = _HEADING_RE.findall(footer_m.group(1))
        if headings:
            lineno = content[:footer_m.start()].count("\n") + 1
            violations.append((lineno,
                f"<div id=\"footer\"> contains heading(s): {', '.join(f'<{h}>' for h in headings)}"))

    # 11. No headings inside <field name="mega_menu_content" type="html">
    for rec_m in re.finditer(
            r'<record\b[^>]*\bmodel=["\']website\.menu["\'][^>]*>(.*?)</record\s*>',
            content, re.DOTALL | re.IGNORECASE):
        for field_m in re.finditer(
                r'<field\b[^>]*\bname=["\']mega_menu_content["\'][^>]*>(.*?)</field\s*>',
                rec_m.group(1), re.DOTALL | re.IGNORECASE):
            headings = _HEADING_RE.findall(field_m.group(1))
            if headings:
                lineno = content[:rec_m.start()].count("\n") + 1
                violations.append((lineno,
                    f"<record model=\"website.menu\"> mega_menu_content contains heading(s):"
                    f" {', '.join(f'<{h}>' for h in headings)}"))

    # 12. Heading hierarchy inside <record model="website.page"> arch field
    for rec_m in re.finditer(
            r'<record\b[^>]*\bmodel=["\']website\.page["\'][^>]*>(.*?)</record\s*>',
            content, re.DOTALL | re.IGNORECASE):
        for field_m in re.finditer(
                r'<field\b[^>]*\bname=["\']arch["\'][^>]*>(.*?)</field\s*>',
                rec_m.group(1), re.DOTALL | re.IGNORECASE):
            headings = [(content[:rec_m.start()].count("\n") + 1
                         + rec_m.group(1)[:field_m.start()].count("\n")
                         + field_m.group(1)[:m.start()].count("\n"),
                         int(m.group(1)[1]))
                        for m in _HEADING_RE.finditer(field_m.group(1))]
            if not headings:
                continue
            levels = [lvl for _, lvl in headings]
            # Only one <h1>
            if levels.count(1) > 1:
                first_extra = next(ln for ln, lvl in headings if lvl == 1 and headings.index((ln, lvl)) > 0)
                violations.append((headings[levels.index(1, 1)][0],
                    f"<record model=\"website.page\"> arch has more than one <h1>"))
            # Must start with h1
            if levels[0] != 1:
                violations.append((headings[0][0],
                    f"<record model=\"website.page\"> arch heading hierarchy does not start with <h1>"
                    f" (found <h{levels[0]}>)"))
            # Must not skip levels going down (can jump up freely)
            for i in range(1, len(levels)):
                if levels[i] > levels[i - 1] + 1:
                    violations.append((headings[i][0],
                        f"<record model=\"website.page\"> arch heading skips from"
                        f" <h{levels[i-1]}> to <h{levels[i]}>"))

    # ── full-content regex: empty block tags ──────────────────────────────
    # Match <tag ...></tag> with only whitespace between (not self-closing void elements)
    empty_tag_re = re.compile(
        r'<([A-Za-z][A-Za-z0-9_:-]*)(?:\s[^>]*)?(?<!/)>\s*</\1\s*>',
        re.DOTALL,
    )
    for m in empty_tag_re.finditer(content):
        tag = m.group(1).lower()
        if tag in VOID_ELEMENTS:
            continue
        # find line number from match start offset
        lineno = content[:m.start()].count("\n") + 1
        violations.append((lineno, f"<{tag}> appears to be an empty block element"))

    violations.sort(key=lambda v: v[0])
    return violations


# ─────────────────────────────────────────────────────────────────────────────
# Image checks
# ─────────────────────────────────────────────────────────────────────────────

def check_images(root: str, image_files: list[str], source_files: list[str]) -> dict[str, list[str]]:
    all_source = "\n".join(read_text(p) for p in source_files)
    issues: dict[str, list[str]] = {}
    for img_path in image_files:
        img_name = os.path.basename(img_path)
        img_rel  = os.path.relpath(img_path, root)
        msgs = []
        if img_name not in all_source and img_rel not in all_source:
            msgs.append("not referenced in any SCSS/XML/Python file")
        if "_" in os.path.splitext(img_name)[0]:
            msgs.append("filename contains underscore")
        ext = os.path.splitext(img_name)[1].lower()
        if ext not in {".webp", ".svg", ".png"}:
            msgs.append(f"non webp/svg/png format: {ext}")
        if msgs:
            issues[img_rel] = msgs
    return issues

# ─────────────────────────────────────────────────────────────────────────────
# Section printer
# ─────────────────────────────────────────────────────────────────────────────

def print_section(title: str):
    print(f"\n{bold('── ' + title + ' ' + '─' * max(0, 55 - len(title)))}")


def print_file_violations(rel_path: str, lines: list[str]):
    print(red(f"  {rel_path}"))
    for l in lines:
        print(l)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    raw_path   = sys.argv[1] if len(sys.argv) > 1 else "."
    root       = os.path.abspath(os.path.expanduser(raw_path))
    img_folder = os.path.join(root, "static", "src")

    print(f"\n{bold('Scanning:')} {root}")

    image_files  = find_files(img_folder, IMAGE_EXTENSIONS)
    js_files     = find_files(root, {".js"})
    source_files = find_files(root, SOURCE_EXTENSIONS)
    scss_files   = [f for f in source_files if f.endswith(".scss")]
    xml_files    = [f for f in source_files if f.endswith(".xml")]

    any_issue = False

    # ── Images ────────────────────────────────────────────────────────────
    print_section("Image check")
    print(dim(f"  {len(image_files)} image(s), {len(source_files)} source file(s) scanned."))

    if not image_files:
        print("  No image files found.")
    else:
        issues = check_images(root, image_files, source_files)
        if issues:
            any_issue = True
            for rel_path, msgs in issues.items():
                print(red(f"  {rel_path}"))
                for msg in msgs:
                    print(f"    - {msg}")
            print(red(f"\n  {len(issues)} image(s) with issues / {len(image_files)} total."))
        else:
            print(green(f"  All {len(image_files)} image(s) are referenced."))

    # ── SCSS ──────────────────────────────────────────────────────────────
    print_section("SCSS check")
    print(dim(f"  {len(scss_files)} SCSS file(s) scanned."))

    if not scss_files:
        print("  No SCSS files found.")
    else:
        scss_issues = 0
        for path in scss_files:
            v = check_scss_file(path)
            if v:
                any_issue  = True
                scss_issues += len(v)
                print_file_violations(os.path.relpath(path, root), _fmt(v))
        if scss_issues == 0:
            print(green("  No issues found."))
        else:
            print(red(f"\n  {scss_issues} issue(s) found in SCSS files."))

    # ── XML ───────────────────────────────────────────────────────────────
    print_section("XML check")
    print(dim(f"  {len(xml_files)} XML file(s) scanned."))

    if not xml_files:
        print("  No XML files found.")
    else:
        scss_js_content = "\n".join(read_text(p) for p in scss_files + js_files)
        xml_issues = 0
        for path in xml_files:
            v = check_xml_file(path, scss_js_content)
            if v:
                any_issue  = True
                xml_issues += len(v)
                print_file_violations(os.path.relpath(path, root), _fmt(v))
        if xml_issues == 0:
            print(green("  No issues found."))
        else:
            print(red(f"\n  {xml_issues} issue(s) found in XML files."))

    print()
    sys.exit(1 if any_issue else 0)


if __name__ == "__main__":
    main()
