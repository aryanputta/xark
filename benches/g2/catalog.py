#!/usr/bin/env python3
"""Fingerprint and deduplicate the available Xark files without unpacking archives."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

from reconstruct import sha256

PREFIX = re.compile(r"^(?:(?:aaa-)?xark[-.]|blueshift-xark[-.])")
TEXT_SUFFIXES = (
    ".csv",
    ".json",
    ".log",
    ".md",
    ".patch",
    ".sha256",
    ".txt",
    ".toml",
    "Cargo.lock",
)
OPAQUE_ARCHIVES = {"xark-05-macos-cargo-cache.tar.gz"}
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_MEMBERS = 50_000


def safe_member(name):
    path = PurePosixPath(name)
    return (
        bool(path.parts)
        and not path.is_absolute()
        and ".." not in path.parts
        and "\\" not in name
    )


def digest_member(member, size, opener):
    if (
        not safe_member(member)
        or size > MAX_TEXT_BYTES
        or not member.endswith(TEXT_SUFFIXES)
    ):
        return None
    with opener() as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def tar_index(path):
    entries = []
    seen = set()
    with tarfile.open(path, "r|*") as archive:
        for member in archive:
            name = str(PurePosixPath(member.name))
            if member.isdir():
                continue
            if len(entries) >= MAX_MEMBERS:
                raise ValueError(f"too many members in {path.name}")
            approved = safe_member(member.name) and name not in seen and member.isfile()
            digest = (
                digest_member(name, member.size, lambda: archive.extractfile(member))
                if approved
                else None
            )
            entries.append(
                {
                    "name": name,
                    "size": member.size,
                    "text_sha256": digest,
                    "safe_regular_file": approved,
                }
            )
            seen.add(name)
    return entries


def zip_index(path):
    entries = []
    seen = set()
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            name = str(PurePosixPath(member.filename))
            if len(entries) >= MAX_MEMBERS:
                raise ValueError(f"too many members in {path.name}")
            mode = (member.external_attr >> 16) & 0o170000
            approved = (
                safe_member(member.filename)
                and name not in seen
                and mode in (0, 0o100000)
            )
            digest = (
                digest_member(name, member.file_size, lambda: archive.open(member))
                if approved
                else None
            )
            entries.append(
                {
                    "name": name,
                    "size": member.file_size,
                    "text_sha256": digest,
                    "safe_regular_file": approved,
                }
            )
            seen.add(name)
    return entries


def catalog(directory):
    inputs = []
    outer = {}
    inner = {}
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or not path.is_file() or not PREFIX.match(path.name):
            continue
        digest = sha256(path)
        item = {"name": path.name, "size": path.stat().st_size, "sha256": digest}
        inputs.append(item)
        if digest in outer:
            item["identical_to"] = outer[digest]
            continue
        outer[digest] = path.name
        try:
            if path.name in OPAQUE_ARCHIVES:
                item[
                    "archive_note"
                ] = "Build dependency cache fingerprinted without traversing its members."
            elif path.name.endswith((".tar.gz", ".tgz")):
                item["members"] = tar_index(path)
            elif path.suffix == ".zip":
                item["members"] = zip_index(path)
        except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
            item["archive_error"] = str(error)
        for member in item.get("members", []):
            digest = member["text_sha256"]
            if digest:
                qualified = f"{path.name}/{member['name']}"
                if digest in inner:
                    member["identical_text_to"] = inner[digest]
                else:
                    inner[digest] = qualified
    return {
        "input_count": len(inputs),
        "distinct_inputs": len(outer),
        "distinct_archived_text_members": len(inner),
        "inputs": inputs,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("downloads", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    result = catalog(arguments.downloads)
    with arguments.output.open("x") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(
        f"{result['input_count']} files; {result['distinct_inputs']} distinct by SHA-256"
    )


if __name__ == "__main__":
    main()
