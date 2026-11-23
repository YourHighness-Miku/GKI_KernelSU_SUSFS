#!/usr/bin/env python3
"""Adapt the pinned Nova builtin tree to the target's actual LSM API."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess


def replace_once(text, old, new):
    if new in text:
        return text
    if text.count(old) != 1:
        raise ValueError(f"Expected one source anchor: {old!r}")
    return text.replace(old, new, 1)


def adapt_lsm(common, root):
    header = (common / "include/linux/lsm_hooks.h").read_text()
    declaration = re.search(r"void\s+security_add_hooks\s*\([^;]+;", header)
    if declaration is None:
        raise ValueError("Target security_add_hooks declaration missing")
    if "const struct lsm_id *" not in declaration.group():
        return "legacy API unchanged"
    path = root / "kernel/hook/lsm_hook.c"
    text = path.read_text()
    old = 'security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), "ksu");'
    new = "security_add_hooks(ksu_hooks, ARRAY_SIZE(ksu_hooks), &ksu_lsmid);"
    definition = ('static const struct lsm_id ksu_lsmid = {\n'
                  '    .name = "ksu",\n'
                  '    .id = LSM_ID_UNDEF,\n'
                  '};\n\n')
    text = replace_once(text, old, new)
    text = replace_once(text, "void __init ksu_lsm_hook_init(void)",
                        definition + "void __init ksu_lsm_hook_init(void)")
    count_path = common / "include/linux/lsm_count.h"
    if count_path.exists():
        count = count_path.read_text()
        anchor = "#define __COUNT_LSMS(skipped_arg, args...) COUNT_ARGS(args...)"
        slot = ("#if IS_BUILTIN(CONFIG_KSU)\n#define KSU_ENABLED 1,\n"
                "#else\n#define KSU_ENABLED\n#endif\n\n")
        count = replace_once(count, anchor, slot + anchor)
        count, changed = re.subn(r"(COUNT_LSMS\(\s*\\\n)(\s*)(CAPABILITIES_ENABLED)",
                                r"\1\2KSU_ENABLED \\\n\2\3", count)
        if changed != 1 and not re.search(r"COUNT_LSMS\(\s*\\\n\s*KSU_ENABLED", count):
            raise ValueError("Cannot reserve the builtin LSM static-call slot")
        count_path.write_text(count)
    elif "lsm_static_call" in header:
        raise ValueError("Static-call LSM header without lsm_count.h")
    path.write_text(text)
    return "typed lsm_id; builtin static-call slot reserved"


def pin_version(root):
    path = root / "kernel/Makefile"
    text = path.read_text()
    base = int(re.search(r"^VERSION_BASE\s*:=\s*(\d+)$", text, re.M)[1])
    offset = int(re.search(r"^VERSION_OFFSET\s*:=\s*(\d+)$", text, re.M)[1])
    count = int(subprocess.check_output(
        ["git", "-C", str(root), "rev-list", "--count", "HEAD"], text=True))
    version = base + count - offset
    if version <= 0:
        raise ValueError("Invalid Nova version from immutable history")
    substitutions = {
        "git_commit_count": f"{count}",
        "git_branch": "builtin-ci",
        "KSU_GITHUB_VER": "",
        "GITHUB_COMMITS": "",
    }
    for name, value in substitutions.items():
        text, n = re.subn(rf"^{name}\s*:?=.*$", f"{name} := {value}", text, flags=re.M)
        if n != 1:
            raise ValueError(f"Expected one Nova version variable: {name}")
    path.write_text(text)
    return version, count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("common", type=Path)
    parser.add_argument("root", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    lsm = adapt_lsm(args.common, args.root)
    version, count = pin_version(args.root)
    commit = subprocess.check_output(
        ["git", "-C", str(args.root), "rev-parse", "HEAD"], text=True).strip()
    report = dict(root_commit=commit, version_code=version, commit_count=count,
                  version_method="pinned Makefile base + HEAD history - offset", lsm=lsm)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    if os.environ.get("GITHUB_ENV"):
        with open(os.environ["GITHUB_ENV"], "a") as env:
            env.write(f"ROOT_VERSION_CODE={version}\nROOT_MANAGER=SukiSU Nova Manager\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()
