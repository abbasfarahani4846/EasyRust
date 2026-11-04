"""Send a coding task to a 9Router model and write the files it returns.

usage: python tools/delegate.py <task-name> "<task text>" [extra context files...]
"""
import base64, json, pathlib, re, sys, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODEL = "cx/gpt-6.1-sol"

MARK = "=" * 3
FILE_PREFIX = f"{MARK} FILE: "
FILE_SUFFIX = f" {MARK}"
END_MARKER = f"{MARK} END {MARK}"

SYSTEM = f"""You are a senior Rust engineer implementing part of a project from a spec.
Output ONLY files, each in this exact format (no prose outside it, no markdown fences):
{FILE_PREFIX}relative/path/from/repo/root{FILE_SUFFIX}
<full file content>
{END_MARKER}
Optionally the very first line may be `NOTES: ...` for anything the lead must know.
Write complete, compiling, idiomatic code. No placeholders, no TODOs."""


def main():
    name, task, *ctx = sys.argv[1:]
    parts = [f"## SPEC.md\n{(ROOT / 'SPEC.md').read_text(encoding='utf-8')}",
             f"## crates/easyvpn-core/src/profile.rs\n{(ROOT / 'crates/easyvpn-core/src/profile.rs').read_text(encoding='utf-8')}"]
    images = []
    image_mimes = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp",
    }
    for c in ctx:
        path = ROOT / c
        mime = image_mimes.get(path.suffix.lower())
        if mime:
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
            images.append({"type": "image_url",
                           "image_url": {"url": f"data:{mime};base64,{encoded}"}})
        else:
            parts.append(f"## {c}\n{path.read_text(encoding='utf-8')}")
    parts.append(f"## YOUR TASK\n{task}")
    content = "\n\n".join(parts)
    if images:
        content = [{"type": "text", "text": content}, *images]
    body = json.dumps({"model": MODEL, "reasoning_effort": "medium",
                       "messages": [{"role": "system", "content": SYSTEM},
                                    {"role": "user", "content": content}]}).encode()
    req = urllib.request.Request("http://localhost:20128/v1/chat/completions", body,
                                 {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=1800) as r:
        out = json.load(r)["choices"][0]["message"]["content"]
    log = ROOT / "tools" / "logs"
    log.mkdir(exist_ok=True)
    (log / f"{name}.txt").write_text(out, encoding="utf-8")
    files = re.findall(
        rf"^{re.escape(FILE_PREFIX)}([^\r\n]+?){re.escape(FILE_SUFFIX)}\r?\n"
        rf"(.*?)\r?\n{re.escape(END_MARKER)}\r?$",
        out, re.S | re.M,
    )
    if not files:
        sys.exit(f"[{name}] no files in response, see tools/logs/{name}.txt")
    for path, content in files:
        dest = (ROOT / path.strip()).resolve()
        if ROOT not in dest.parents:  # refuse writes outside the repo
            print(f"[{name}] skipped unsafe path {path}")
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content + "\n", encoding="utf-8")
        print(f"[{name}] wrote {path.strip()}")
    notes = [l for l in out.splitlines()[:3] if l.startswith("NOTES:")]
    if notes:
        print(f"[{name}] {notes[0]}")


if __name__ == "__main__":
    main()
