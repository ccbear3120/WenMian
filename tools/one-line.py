#!/usr/bin/env python3
"""Collapse text files to a single line for the blobs stored on GitHub,
and expand them back to multi-line on checkout (so the worktree stays
readable; only uploads are minified/stripped).

Goal: working-tree files stay readable (multi-line); what lands in git /
on GitHub is the 1-line version.

  git filter:   python3 tools/one-line.py clean <path>    # stdin -> stdout
                python3 tools/one-line.py smudge <path>   # stdin -> stdout
  batch check:  python3 tools/one-line.py min <file...>   # print in/out stats
  self-test:    python3 tools/one-line.py test

Stdlib only. Conservative on purpose:
  * .json -> json.loads + json.dumps(separators=(',',':')) (exact 1 line)
* .js   -> small tokenizer: strings/templates/regex kept verbatim,
           all comments (//, /* */, <!-- -->) are dropped entirely;
           a dropped comment still counts as separation so tokens never merge
* .css  -> whitespace runs collapse to one space, strings kept verbatim,
           /* */ comments are dropped (one space kept if needed to avoid merge)
* .html -> tags collapse whitespace, <!-- --> comments are dropped;
           <script>/<style> minified
             with the rules above; <pre>/<textarea> newlines become &#10;
             (renders the same, file stays 1 line)
  * anything else -> passthrough (exit 0, bytes unchanged)

As a git `clean` filter this script NEVER fails the `git add`: any error
prints a warning to stderr and passes the input through unchanged (so the
pushed file is readable that time, but never broken).
"""
import json
import re
import sys

WORDCH = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$"
)
OPCH = set("+-=!<>|&*/%^~?:.")
JS_REGEX_KEYWORDS = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete",
    "void", "throw", "case", "do", "else", "yield", "await",
}
JS_OPS_3 = (
    "===", "!==", ">>>", "<<=", ">>=", "**=", "...", "??=", "?.",
)
JS_OPS_2 = (
    "==", "!=", "<=", ">=", "++", "--", "&&", "||", "**", "<<", ">>",
    "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "=>", "??",
)


def _match_op(s, i):
    for op in JS_OPS_3:
        if s.startswith(op, i):
            return op
    for op in JS_OPS_2:
        if s.startswith(op, i):
            return op
    return s[i]


def _lex_js_expr(s, i, n, toks, gaps, stop_on_brace):
    """Tokenize JS from i; append (text, gap_before). Return new index.

    gap_before=True means whitespace/comment separated this token from the
    previous one (needed to keep e.g. `a - -b` from merging into `a--b`).
    With stop_on_brace=True, stop BEFORE a `}` that closes the caller
    (used for `${ ... }`); the caller consumes the `}`.
    """
    prev_rx = True  # at expression start a regex literal is allowed
    at_line_start = True
    gap = False
    while i < n:
        c = s[i]
        if c in " \t\n\v\f":
            gap = True
            if c == "\n":
                at_line_start = True
            i += 1
            continue
        if c == "/" and s.startswith("//", i):
            j = s.find("\n", i + 2)
            if j == -1:
                j = n
            gap = True  # 注释丢弃，但仍算分隔，防前后 token 粘连
            prev_rx = True
            i = j
            continue
        if c == "/" and s.startswith("/*", i):
            j = s.find("*/", i + 2)
            if j == -1:
                raise ValueError("unterminated block comment")
            gap = True
            prev_rx = True
            i = j + 2
            continue
        if c == "<" and s.startswith("<!--", i):
            j = s.find("\n", i + 4)
            if j == -1:
                j = n
            gap = True
            prev_rx = True
            i = j
            continue
        if c == "-" and s.startswith("-->", i) and at_line_start:
            j = s.find("\n", i + 3)
            if j == -1:
                j = n
            gap = True
            prev_rx = True
            i = j
            continue
        if c == "/" and not prev_rx:
            toks.append(("/", gap))
            gap = False
            prev_rx = True
            at_line_start = False
            i += 1
            continue
        if c == "/":
            # regex literal
            j = i + 1
            in_class = False
            buf = ["/"]
            while j < n:
                d = s[j]
                if d == "\\":
                    buf.append(s[j:j + 2])
                    j += 2
                    continue
                if d == "\n":
                    if in_class:
                        buf.append("\\n")
                        j += 1
                        continue
                    raise ValueError("newline in regex literal")
                if d == "[":
                    in_class = True
                elif d == "]":
                    in_class = False
                elif d == "/" and not in_class:
                    buf.append("/")
                    j += 1
                    while j < n and s[j] in WORDCH:
                        buf.append(s[j])
                        j += 1
                    break
                else:
                    buf.append(d)
                    j += 1
                    continue
                buf.append(d) if d not in "\\" else None
                j += 1
            else:
                raise ValueError("unterminated regex literal")
            toks.append(("".join(buf), gap))
            gap = False
            prev_rx = False
            at_line_start = False
            i = j
            continue
        if c in ("'", '"'):
            j = i + 1
            buf = [c]
            while j < n:
                d = s[j]
                if d == "\\":
                    buf.append(s[j:j + 2])
                    j += 2
                    continue
                if d == c:
                    buf.append(d)
                    j += 1
                    break
                if d == "\n":
                    buf.append("\\n")  # invalid in source; keep 1-line
                    j += 1
                    continue
                buf.append(d)
                j += 1
            else:
                raise ValueError("unterminated string literal")
            toks.append(("".join(buf), gap))
            gap = False
            prev_rx = False
            at_line_start = False
            i = j
            continue
        if c == "`":
            tok, i = _lex_js_template(s, i, n)
            toks.append((tok, gap))
            gap = False
            prev_rx = False
            at_line_start = False
            continue
        if c == "{":
            toks.append(("{", gap))
            gap = False
            prev_rx = True
            at_line_start = False
            i += 1
            continue
        if c == "}":
            if stop_on_brace:
                return i
            toks.append(("}", gap))
            gap = False
            prev_rx = True
            at_line_start = False
            i += 1
            continue
        if c == "#" and i + 1 < n and (
            s[i + 1].isalpha() or s[i + 1] in "_$"
        ):
            j = i + 1
            while j < n and s[j] in WORDCH:
                j += 1
            toks.append((s[i:j], gap))
            gap = False
            prev_rx = False
            at_line_start = False
            i = j
            continue
        if c.isalpha() or c in "_$":
            j = i + 1
            while j < n and s[j] in WORDCH:
                j += 1
            word = s[i:j]
            toks.append((word, gap))
            gap = False
            prev_rx = word in JS_REGEX_KEYWORDS
            at_line_start = False
            i = j
            continue
        if c.isdigit() or (
            c == "." and i + 1 < n and s[i + 1].isdigit()
        ):
            j = i
            while j < n and (s[j] in WORDCH or s[j] == "."):
                j += 1
            toks.append((s[i:j], gap))
            gap = False
            prev_rx = False
            at_line_start = False
            i = j
            continue
        op = _match_op(s, i)
        toks.append((op, gap))
        gap = False
        if op in (")", "]"):
            prev_rx = False
        elif op in ("++", "--"):
            prev_rx = False
        else:
            prev_rx = True
        at_line_start = False
        i += len(op)
    if stop_on_brace:
        raise ValueError("missing closing brace")
    return i


def _lex_js_template(s, i, n):
    """Parse a template literal starting at s[i]=='`'. Return (text, idx)."""
    buf = ["`"]
    i += 1
    while i < n:
        c = s[i]
        if c == "\\":
            buf.append(s[i:i + 2])
            i += 2
            continue
        if c == "`":
            buf.append("`")
            return "".join(buf), i + 1
        if c == "\n":
            buf.append("\\n")  # == LF inside template literals
            i += 1
            continue
        if c == "$" and s.startswith("${", i):
            buf.append("${")
            i += 2
            inner = []
            i = _lex_js_expr(s, i, n, inner, [], stop_on_brace=True)
            buf.append(_join_js_tokens(inner))
            # s[i] == '}' (caller contract: stop BEFORE it)
            buf.append("}")
            i += 1
            continue
        buf.append(c)
        i += 1
    raise ValueError("unterminated template literal")


def _join_js_tokens(toks):
    out = []
    prev = ""
    for text, gap in toks:
        if out:
            la, fb = prev[-1], text[0]
            need = (la in WORDCH and fb in WORDCH) or (
                gap and la in OPCH and fb in OPCH
            ) or (
                gap and la.isdigit() and fb == "."
            )
            if need:
                out.append(" ")
        out.append(text)
        prev = text
    return "".join(out)


def one_line_js(src):
    s = src.replace("\r\n", "\n").replace("\r", "\n")
    if s.startswith("#!"):
        nl = s.find("\n")
        s = s[nl + 1:] if nl != -1 else ""
    toks = []
    _lex_js_expr(s, 0, len(s), toks, [], stop_on_brace=False)
    out = _join_js_tokens(toks)
    if "\n" in out:
        raise ValueError("newline leaked into JS output")
    return out


def one_line_css(src):
    s = src.replace("\r\n", "\n").replace("\r", "\n")
    out = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c in ("'", '"'):
            j = i + 1
            buf = [c]
            while j < n:
                d = s[j]
                if d == "\\":
                    buf.append(s[j:j + 2])
                    j += 2
                    continue
                if d == c:
                    buf.append(d)
                    j += 1
                    break
                if d == "\n":
                    buf.append(" ")  # invalid in source; stay 1-line
                    j += 1
                    continue
                buf.append(d)
                j += 1
            else:
                raise ValueError("unterminated CSS string")
            out.append("".join(buf))
            i = j
            continue
        if c == "/" and s.startswith("/*", i):
            j = s.find("*/", i + 2)
            if j == -1:
                raise ValueError("unterminated CSS comment")
            # 注释直接丢弃；前后若无空白则补一个空格，防 `0/*c*/auto` 粘连
            if out and not out[-1].endswith(" "):
                out.append(" ")
            i = j + 2
            continue
        if c in " \t\n\v\f":
            if out and not out[-1].endswith(" "):
                out.append(" ")
            i += 1
            continue
        out.append(c)
        i += 1
    res = "".join(out).strip()
    if "\n" in res:
        raise ValueError("newline leaked into CSS output")
    return res


def one_line_json(text):
    return json.dumps(json.loads(text), ensure_ascii=False, separators=(",", ":"))


def _scan_tag(s, lt):
    """Return (tag_text, index_after) starting at s[lt]=='<', quotes aware."""
    i, n = lt + 1, len(s)
    quote = None
    while i < n:
        c = s[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = None
        elif c in ("'", '"'):
            quote = c
        elif c == ">":
            return s[lt:i + 1], i + 1
        i += 1
    return s[lt:], n


def one_line_html(src):
    s = src.replace("\r\n", "\n").replace("\r", "\n")
    out = []
    i, n = 0, len(s)
    while i < n:
        lt = s.find("<", i)
        if lt == -1:
            out.append(re.sub(r"\s+", " ", s[i:]))
            break
        if lt > i:
            out.append(re.sub(r"\s+", " ", s[i:lt]))
        if s.startswith("<!--", lt):
            end = s.find("-->", lt + 4)
            if end == -1:
                raise ValueError("unterminated HTML comment")
            i = end + 3  # HTML 注释直接丢弃（浏览器本来就不渲染它）
            # 注释两侧的空白合并成一个：否则 `> <` 留下双空格，二次压缩漂移
            if i < n and s[i] in " \t\n\v\f" and out and out[-1].endswith(" "):
                while i < n and s[i] in " \t\n\v\f":
                    i += 1
            continue
        m = re.match(r"<\s*(/?)\s*([A-Za-z][A-Za-z0-9]*)", s[lt:])
        tag, j = _scan_tag(s, lt)
        if not m:
            out.append(re.sub(r"\s+", " ", tag))
            i = j
            continue
        closing, name = m.group(1), m.group(2).lower()
        if closing or name not in ("script", "style", "pre", "textarea"):
            out.append(re.sub(r"\s+", " ", tag))
            i = j
            continue
        cm = re.search(r"</\s*" + name + r"\s*>", s[j:], re.I)
        if not cm:
            raise ValueError("unterminated <%s> block" % name)
        inner = s[j:j + cm.start()]
        closetag = cm.group(0)
        j = j + cm.end()
        opentag = re.sub(r"\s+", " ", tag)
        closetag = re.sub(r"\s+", " ", closetag)
        if name in ("pre", "textarea"):
            out.append(opentag + inner.replace("\n", "&#10;") + closetag)
        elif name == "style":
            try:
                inner2 = one_line_css(inner)
            except Exception:
                inner2 = re.sub(r"\s+", " ", inner)
            out.append(opentag + inner2 + closetag)
        else:  # script
            tm = re.search(
                r'''(?i)\btype\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)''', opentag
            )
            typ = tm.group(1).strip("\"'").lower() if tm else ""
            has_src = re.search(r"(?i)[\s]src\s*=", opentag)
            if has_src and not inner.strip():
                out.append(opentag + closetag)
            elif "json" in typ:
                try:
                    inner2 = one_line_json(inner)
                except Exception:
                    inner2 = re.sub(r"\s+", " ", inner)
                out.append(opentag + inner2 + closetag)
            elif typ in ("", "module", "text/javascript",
                         "application/javascript", "text/ecmascript"):
                out.append(opentag + one_line_js(inner) + closetag)
            else:
                out.append(opentag + re.sub(r"\s+", " ", inner) + closetag)
        i = j
    res = "".join(out).strip()
    if "\n" in res:
        raise ValueError("newline leaked into HTML output")
    return res


    res = "".join(out).strip()
    if "\n" in res:
        raise ValueError("newline leaked into HTML output")
    return res


# ---------------------------------------------------------------------------
# 展开方向（smudge：checkout/pull 时把 1 行 blob 还原成多行可读版）。
# 安全原则：只加空白、绝不改 token 流；调用方（_smudge_filter）会校验
# clean(expand(x)) == x，不满足则原样直通，绝不写坏工作区。
# ---------------------------------------------------------------------------
_JS_HAZARD_START = ("(", "[", "`", "+", "-", "/", "=>")
# 上一行以这些结尾时，下一行换行一定安全（表达式位置），无需合并；
# 注意 "=>" 必须合并（箭头函数 ) 与 => 间不允许换行），见下
_JS_NO_MERGE_TAIL = ("{", ";", ",", "(", "[", "=>", ":", "?", "return",
                     "typeof", "throw", "in", "of", "new", "delete",
                     "void", "do", "else", "case")
# 上一行以这些结尾时，下一行换行一定安全（表达式位置），无需合并
_JS_NO_MERGE_TAIL = ("{", ";", ",", "(", "[", "=>", ":", "?", "return",
                     "typeof", "throw", "in", "of", "new", "delete",
                     "void", "do", "else", "case")
_JS_EXPR_CONT = {
    ".", "(", "[", "`", "=>",  # "=>"：} 后跟 => 不断行（箭头不允许换行），合并逻辑见下
    "+", "-", "*", "/", "%", "**",
    "==", "!=", "===", "!==", "<", ">", "<=", ">=",
    "&&", "||", "??", "?", ":",
    "=", "+=", "-=", "*=", "/=", "%=", "**=", "&&=", "||=", "??=",
    "&", "|", "^", "<<", ">>", ">>>",
    ",", ";", ")", "]", "}",
    "in", "of", "instanceof", "as",
}


def expand_js(src):
    toks = []
    _lex_js_expr(src, 0, len(src), toks, [], stop_on_brace=False)
    for t, _g in toks:
        if "\n" in t:
            raise ValueError("newline inside token")
    lines = []
    cur = []
    indent = 0
    rnd = sqr = 0
    base_stack = []
    n = len(toks)

    def flush():
        nonlocal cur
        if cur:
            lines.append((indent, cur))
            cur = []

    def at_stmt_level():
        base = base_stack[-1] if base_stack else (0, 0)
        return (rnd, sqr) == base

    i = 0
    while i < n:
        text, gap = toks[i]
        if text == "(":
            rnd += 1
            cur.append((text, gap))
        elif text == ")":
            rnd -= 1
            cur.append((text, gap))
        elif text == "[":
            sqr += 1
            cur.append((text, gap))
        elif text == "]":
            sqr -= 1
            cur.append((text, gap))
        elif text == "{":
            cur.append((text, gap))
            flush()
            base_stack.append((rnd, sqr))
            indent += 1
        elif text == "}":
            flush()
            indent = max(0, indent - 1)
            if base_stack:
                base_stack.pop()
            j = i + 1
            trail = []
            while j < n and toks[j][0] in (",", ";", ")", "]"):
                if toks[j][0] == ")":
                    rnd -= 1
                elif toks[j][0] == "]":
                    sqr -= 1
                trail.append(toks[j])
                j += 1
            cur = [("}", False)] + trail
            if j < n and toks[j][0] in ("else", "catch", "finally", "while"):
                cur.append(toks[j])
                j += 1
                if j < n and toks[j][0] == "{":
                    cur.append(toks[j])
                    j += 1
                    flush()
                    indent += 1
            elif j < n and toks[j][0] not in _JS_EXPR_CONT:
                flush()  # } 后是新语句/新块/EOF：断行
            i = j - 1
        elif text == ";" and at_stmt_level():
            cur.append((text, gap))
            flush()
        else:
            cur.append((text, gap))
        i += 1
    flush()

    # ASI 保护：以 ( [ ` + - / 开头的延续行并回上一行（还原压缩版原样）
    merged = []
    for ind, tl in lines:
        first = tl[0][0] if tl else ""
        if merged and first.startswith(_JS_HAZARD_START):
            plast = merged[-1][1][-1][0] if merged[-1][1] else ""
            if plast not in _JS_NO_MERGE_TAIL:
                pind, ptl = merged[-1]
                merged[-1] = (pind, ptl + tl)
                continue
        merged.append((ind, tl))
    out = "\n".join("  " * ind + _join_js_tokens(tl) for ind, tl in merged)
    return out.rstrip("\n") + "\n"


_HTML_BLOCK_TAGS = {
    "html", "head", "body", "div", "section", "header", "footer", "main",
    "nav", "form", "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "table", "thead", "tbody", "tr", "td", "th", "fieldset", "script",
}


def _split_html_tags(s):
    toks = []
    i, n = 0, len(s)
    while i < n:
        lt = s.find("<", i)
        if lt == -1:
            toks.append(("text", s[i:]))
            break
        if lt > i:
            toks.append(("text", s[i:lt]))
        tag, j = _scan_tag(s, lt)
        m = re.match(r"<\s*(/?)\s*([A-Za-z][A-Za-z0-9]*)", tag)
        closing = bool(m and m.group(1))
        name = m.group(2).lower() if m else ""
        toks.append(("tag", tag, name, closing))
        i = j
    return toks


def expand_html(src):
    toks = _split_html_tags(src)
    out = []
    depth = 0
    IND = "  "
    pending_gap = False  # 刚消费过一个纯空白 gap（换行只源于此，渲染等价）

    def newline():
        out.append("\n" + IND * depth)

    i, n = 0, len(toks)
    while i < n:
        tk = toks[i]
        if tk[0] == "text":
            if tk[1].strip() == "":
                pending_gap = True
            else:
                if pending_gap:
                    newline()
                    pending_gap = False
                out.append(tk[1])
            i += 1
            continue
        _k, tag, name, closing = tk
        if name == "script" and not closing:
            m2 = re.search(r'type\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)',
                           tag, re.I)
            typ = m2.group(1).strip("\"'").lower() if m2 else ""
            j = i + 1
            inner_parts = []
            while j < n:
                if (toks[j][0] == "tag" and toks[j][2] == "script"
                        and toks[j][3]):
                    break
                inner_parts.append(toks[j])
                j += 1
            closetag = toks[j][1] if j < n else "</script>"
            raw_inner = "".join(p[1] for p in inner_parts)
            if pending_gap:
                newline()
                pending_gap = False
            out.append(tag)
            if "json" in typ and raw_inner.strip():
                obj = json.loads(raw_inner)
                pretty = json.dumps(obj, ensure_ascii=False, indent=2)
                pad = "\n" + IND * (depth + 1)
                out.append("\n" + IND * (depth + 1)
                           + pretty.replace("\n", pad)
                           + "\n" + IND * depth + closetag)
            else:
                out.append(closetag)
            i = j + 1
            continue
        if name == "textarea" and not closing:
            if pending_gap:
                newline()
                pending_gap = False
            j = i + 1
            buf = [tag]
            while j < n:
                buf.append(toks[j][1])
                if (toks[j][0] == "tag" and toks[j][2] == "textarea"
                        and toks[j][3]):
                    break
                j += 1
            out.append("".join(buf))
            i = j + 1
            continue
        is_block = name in _HTML_BLOCK_TAGS
        if closing and is_block:
            depth = max(0, depth - 1)
        if pending_gap:
            newline()
            pending_gap = False
        out.append(tag)
        if not closing and is_block and not tag.rstrip().endswith("/>"):
            depth += 1
        i += 1
    res = "".join(out)
    res = re.sub(r"\n{3,}", "\n\n", res).strip("\n") + "\n"
    return res


def expand_css(src):
    # 只在 blob 已有空白处断行（clean 会把换行压回单空格，往返一致）；
    # 且只在 { } ; , 之后断行，其余空格（如选择器后代、属性值内）保留，
    # 贴近手写风格；字符串/注释内原样保留。
    out = []
    i, n = 0, len(src)
    depth = 0
    pd = 0  # 圆括号深度：括号内的逗号后不断行（如 rgba(…)）
    prev = ""
    while i < n:
        c = src[i]
        if c in ("'", '"'):
            j = i + 1
            buf = [c]
            while j < n:
                d = src[j]
                if d == "\\":
                    buf.append(src[j:j + 2])
                    j += 2
                    continue
                buf.append(d)
                j += 1
                if d == c:
                    break
            out.append("".join(buf))
            prev = c
            i = j
            continue
        if c == "/" and src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(src[i:j])
            prev = "/"
            i = j
            continue
        if c in " \t\n\v\f":
            j = i
            while j < n and src[j] in " \t\n\v\f":
                j += 1
            nxt = src[j] if j < n else ""
            if nxt == "":
                pass  # 尾部空白丢弃
            elif nxt == "}":
                depth = max(0, depth - 1)
                out.append("\n" + "  " * depth)
            elif prev in ("{", "}", ";") or (prev == "," and pd == 0):
                out.append("\n" + "  " * depth)
            else:
                out.append(" ")
            i = j
            continue
        if c == "(":
            out.append(c)
            pd += 1
            prev = "("
            i += 1
            continue
        if c == ")":
            out.append(c)
            pd = max(0, pd - 1)
            prev = ")"
            i += 1
            continue
        if c == "{":
            out.append("{")
            depth += 1
            prev = "{"
            i += 1
            continue
        if c == "}":
            depth = max(0, depth - 1)
            out.append("}")
            prev = "}"
            i += 1
            continue
        out.append(c)
        if c not in " \t\n\v\f":
            prev = c
        i += 1
    res = "".join(out)
    res = re.sub(r"\n{3,}", "\n\n", res).strip() + "\n"
    return res


def expand_json(text):
    return json.dumps(json.loads(text), ensure_ascii=False, indent=2) + "\n"


def expand_for_path(path, text):
    p = path.lower()
    if p.endswith(".json"):
        return expand_json(text)
    if p.endswith((".js", ".mjs", ".cjs")):
        return expand_js(text)
    if p.endswith(".css"):
        return expand_css(text)
    if p.endswith((".html", ".htm")):
        return expand_html(text)
    return None


def transform_for_path(path, text):
    p = path.lower()
    if p.endswith(".json"):
        return one_line_json(text)
    if p.endswith((".js", ".mjs", ".cjs")):
        return one_line_js(text)
    if p.endswith(".css"):
        return one_line_css(text)
    if p.endswith((".html", ".htm")):
        return one_line_html(text)
    return None


def _clean_filter(path):
    data = sys.stdin.buffer.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        sys.stdout.buffer.write(data)  # binary: passthrough
        return
    try:
        out = transform_for_path(path, text)
    except Exception as e:  # fail open: never break `git add`
        sys.stderr.write("one-line.py: %s not minified (%s)\n" % (path, e))
        sys.stdout.buffer.write(data)
        return
    if out is None:
        sys.stdout.buffer.write(data)
        return
    if "\n" in out.rstrip("\n"):
        sys.stderr.write("one-line.py: %s leaked newline, passthrough\n" % path)
        sys.stdout.buffer.write(data)
        return
    sys.stdout.buffer.write((out.rstrip("\n") + "\n").encode("utf-8"))


def _smudge_filter(path):
    data = sys.stdin.buffer.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        sys.stdout.buffer.write(data)  # binary: passthrough
        return
    try:
        out = expand_for_path(path, text)
    except Exception as e:  # fail open: never break `git checkout`
        sys.stderr.write("one-line.py: %s not expanded (%s)\n" % (path, e))
        sys.stdout.buffer.write(data)
        return
    if out is None:
        sys.stdout.buffer.write(data)
        return
    try:
        back = transform_for_path(path, out)
    except Exception as e:
        sys.stderr.write("one-line.py: %s re-minify failed (%s)\n"
                         % (path, e))
        sys.stdout.buffer.write(data)
        return
    # 往返自检：展开版压回去必须与输入 blob 一致，否则直通 1 行版
    if back is None or back.rstrip("\n") != text.rstrip("\n"):
        sys.stderr.write("one-line.py: %s roundtrip mismatch, passthrough\n"
                         % path)
        sys.stdout.buffer.write(data)
        return
    sys.stdout.buffer.write(out.encode("utf-8"))


def _cmd_min(files):
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            text = fh.read()
        out = transform_for_path(f, text)
        if out is None:
            print("%s: skipped (unsupported type)" % f)
            continue
        in_lines = text.count("\n") + (0 if text.endswith("\n") else 1)
        print("%s: %d lines -> 1 line, %d -> %d bytes"
              % (f, in_lines, len(text.encode("utf-8")),
                 len((out.rstrip("\n") + "\n").encode("utf-8"))))


def _cmd_test():
    # JS: comments, regex vs division, template literals, strings with //
    js = (
        "// head comment\n"
        "const url = 'https://x.test/a//b'; // tail\n"
        "const re = /^\\d{4}-(\\d{2})$/gi; /*块*/\n"
        "let a = 1 / 2 / 3;\n"
        "const t = `hi ${a + `in ${re.source}`} bye\nnext`;\n"
        "if (a) { b(); } else { c(); }\n"
        "a - -b;\n"
    )
    o = one_line_js(js)
    assert "\n" not in o, o
    assert "head comment" not in o and "tail" not in o and "块" not in o  # 注释全剥离
    assert "https://x.test/a//b" in o
    assert o == one_line_js(o), "JS not idempotent"
    # 注释充当分隔：删掉也不能让 token 粘连
    assert one_line_js("a/**/b") == "a b"
    assert one_line_js("a/*x*/-/*y*/-b") == "a- -b"
    # division vs regex spot checks
    assert "1/2/3" in o, o
    assert "/^\\d{4}-(\\d{2})$/gi" in o, o
    assert "a- -b" in o, o  # operator merge guard keeps one space
    # CSS
    css = "a {\n  color: red; /* 注 */\n  content: \"x;y\";\n}\n"
    oc = one_line_css(css)
    assert oc.count("\n") == 0 and "content:" in oc and '"x;y"' in oc
    assert "注" not in oc  # CSS 注释剥离
    assert one_line_css("a{margin:0/*c*/auto}") == "a{margin:0 auto}"  # 防粘连空格
    # JSON
    assert one_line_json('{\n"a": [1, 2]\n}\n') == '{"a":[1,2]}'
    # HTML: script-json + pre + comment
    html = ("<html>\n<head><title>t</title></head>\n<body>\n"
            "<!-- hi\nthere -->\n"
            '<script id="d" type="application/json">\n{"a": 1}\n</script>\n'
            "<pre>a\nb</pre>\n<p>x  y</p>\n</body></html>\n")
    oh = one_line_html(html)
    assert oh.count("\n") == 0, oh
    assert "<!--" not in oh  # HTML 注释剥离
    assert '{"a":1}' in oh and "a&#10;b" in oh and "<p>x y</p>" in oh
    assert oh == one_line_html(oh), "HTML not idempotent"
    # smudge 往返：展开后再压回必须与 1 行版一致（工作区可读性的根基）
    assert transform_for_path("a.js", expand_js(o)) == o
    assert transform_for_path("a.css", expand_css(oc)) == oc
    assert transform_for_path("a.html", expand_html(oh)) == oh
    assert transform_for_path("a.json", expand_json('{"a":[1,2]}')) == \
        '{"a":[1,2]}'
    assert expand_for_path("a.txt", "x") is None  # 不支持的类型直通
    # 箭头回归：解构参数的 } ) 与 => 之间绝不能断行（非法 JS）
    arr = ("const m=a.map(({id,...rest})=>rest);"
           "const f=(a,b)=>a+b;if(x){y();}const q={a:1};q();")
    oarr = one_line_js(arr)
    earr = expand_js(oarr)
    assert "}\n=>" not in earr and ")\n=>" not in earr, earr
    assert transform_for_path("a.js", earr) == oarr
    print("one-line.py self-test OK")


def main(argv):
    if len(argv) >= 2 and argv[1] == "clean":
        _clean_filter(argv[2] if len(argv) > 2 else "")
    elif len(argv) >= 2 and argv[1] == "smudge":
        _smudge_filter(argv[2] if len(argv) > 2 else "")
    elif len(argv) >= 2 and argv[1] == "min":
        _cmd_min(argv[2:])
    elif len(argv) >= 2 and argv[1] == "test":
        _cmd_test()
    else:
        sys.stderr.write(
            "usage: one-line.py clean <path> | smudge <path> | min <file...> | test\n"
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
