#!/usr/bin/env python3
"""Time resident Rapidsnark 81eddf1 proofs with independent snarkjs checks.

The C ABI call includes witness parsing and JSON output. Key loading, R1CS
witness checking, and statement and proof verification are outside timing.
Use the same exported R1CS and witness as the Xark comparison.
The native C++ pool sizes itself from hardware concurrency, independently of
the OpenMP limit. Use a host with the intended number of online CPUs.
"""

import argparse
import ctypes
from hashlib import file_digest
import json
import os
from pathlib import Path
import subprocess
from time import perf_counter_ns


RAPIDSNARK_REVISION = "81eddf1a536d26497b237c0b8a04fe90baf7e439"


class BenchmarkError(RuntimeError):
    pass


class Rapidsnark:
    def __init__(self, path):
        library = ctypes.CDLL(os.fspath(path))
        ptr = ctypes.c_void_p
        ull = ctypes.c_ulonglong
        ull_ptr = ctypes.POINTER(ull)
        library.groth16_public_size_for_zkey_buf.argtypes = [
            ptr,
            ull,
            ull_ptr,
            ptr,
            ull,
        ]
        library.groth16_public_size_for_zkey_buf.restype = ctypes.c_int
        library.groth16_proof_size.argtypes = [ull_ptr]
        library.groth16_proof_size.restype = None
        library.groth16_prover_create.argtypes = [
            ctypes.POINTER(ptr),
            ptr,
            ull,
            ptr,
            ull,
        ]
        library.groth16_prover_create.restype = ctypes.c_int
        library.groth16_prover_prove.argtypes = [
            ptr,
            ptr,
            ull,
            ptr,
            ull_ptr,
            ptr,
            ull_ptr,
            ptr,
            ull,
        ]
        library.groth16_prover_prove.restype = ctypes.c_int
        library.groth16_prover_destroy.argtypes = [ptr]
        library.groth16_prover_destroy.restype = None
        self.library = library

    def measure(self, zkey, witness, samples, warmups):
        library = self.library
        # The prover borrows the input bytes. Keep this owned buffer live through
        # destroy. The pinned file constructor unmaps its temporary file loader.
        key = ctypes.create_string_buffer(zkey, len(zkey))
        wtns = ctypes.create_string_buffer(witness, len(witness))
        error = ctypes.create_string_buffer(1024)
        public_capacity = ctypes.c_ulonglong()
        proof_capacity = ctypes.c_ulonglong()
        code = library.groth16_public_size_for_zkey_buf(
            key, len(key), ctypes.byref(public_capacity), error, len(error)
        )
        if code:
            raise BenchmarkError(
                f"load proving key header failed (Rapidsnark code {code})"
            )
        library.groth16_proof_size(ctypes.byref(proof_capacity))
        if not proof_capacity.value or not public_capacity.value:
            raise BenchmarkError("invalid proof or public output capacity")
        proof = ctypes.create_string_buffer(proof_capacity.value)
        public = ctypes.create_string_buffer(public_capacity.value)
        handle = ctypes.c_void_p()
        code = library.groth16_prover_create(
            ctypes.byref(handle), key, len(key), error, len(error)
        )
        if code or not handle:
            raise BenchmarkError(
                f"create resident prover failed (Rapidsnark code {code})"
            )
        measured = []
        try:
            for index in range(warmups + samples):
                proof_size = ctypes.c_ulonglong(len(proof))
                public_size = ctypes.c_ulonglong(len(public))
                call = (
                    handle,
                    wtns,
                    len(wtns),
                    proof,
                    ctypes.byref(proof_size),
                    public,
                    ctypes.byref(public_size),
                    error,
                    len(error),
                )
                start = perf_counter_ns()
                code = library.groth16_prover_prove(*call)
                elapsed = perf_counter_ns() - start
                if code:
                    raise BenchmarkError(
                        f"prove sample {index + 1} failed (Rapidsnark code {code})"
                    )
                if not (
                    0 < proof_size.value < len(proof)
                    and 0 < public_size.value < len(public)
                ):
                    raise BenchmarkError("invalid proof or public output length")
                if index >= warmups:
                    measured.append(
                        (
                            elapsed,
                            proof[: proof_size.value],
                            public[: public_size.value],
                        )
                    )
        finally:
            library.groth16_prover_destroy(handle)
        return measured


def file_hash(path):
    with path.open("rb") as stream:
        return file_digest(stream, "sha256").hexdigest()


def verify_with_node(verifier, snarkjs, mode, *paths, payload=None):
    result = subprocess.run(
        ["node", verifier, snarkjs, mode, *paths],
        input=payload if payload is not None else b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=300,
    )
    if result.returncode:
        raise BenchmarkError(f"snarkjs {mode} failed (exit {result.returncode})")


def run(args):
    verifier = Path(__file__).with_name("verify_rapidsnark_resident.cjs")
    public = args.fixture / "public.json"
    changed = args.fixture / "public-changed.json"
    snarkjs = args.snarkjs.resolve()
    artifacts = {
        "library": args.library,
        "r1cs": args.r1cs,
        "witness": args.wtns,
        "proving_key": args.zkey,
        "verification_key": args.vk,
        "public": public,
        "changed_public": changed,
        "benchmark_driver": Path(__file__),
        "verifier_driver": verifier,
        "snarkjs_manifest": snarkjs / "package.json",
        "snarkjs_verifier": snarkjs / "build/main.cjs",
    }
    before = {name: file_hash(path) for name, path in artifacts.items()}

    verify_with_node(verifier, snarkjs, "witness", args.r1cs, args.wtns)

    os.environ["OMP_NUM_THREADS"] = str(args.threads)
    os.environ["OMP_THREAD_LIMIT"] = str(args.threads)
    os.environ["OMP_DYNAMIC"] = "FALSE"
    prover = Rapidsnark(args.library.resolve())
    samples = prover.measure(
        args.zkey.read_bytes(), args.wtns.read_bytes(), args.samples, args.warmups
    )
    if len({proof for _, proof, _ in samples}) != args.samples:
        raise BenchmarkError("measured proof encodings were not distinct")
    payload = json.dumps(
        [
            {"proof": json.loads(proof), "public": json.loads(statement)}
            for _, proof, statement in samples
        ],
        separators=(",", ":"),
    ).encode()
    verify_with_node(
        verifier, snarkjs, "proofs", args.vk, public, changed, payload=payload
    )

    after = {name: file_hash(path) for name, path in artifacts.items()}
    if before != after:
        raise BenchmarkError("benchmark artifacts changed during the run")

    print(f"Rapidsnark pin: {RAPIDSNARK_REVISION}")
    print(f"warmups: {args.warmups}")
    print(f"OpenMP thread limit: {args.threads}")
    print(f"OS CPU count reported to the process: {os.cpu_count()}")
    if hasattr(os, "sched_getaffinity"):
        print(f"CPUs allowed by process affinity: {len(os.sched_getaffinity(0))}")
    print("witness checked against exported R1CS by snarkjs outside timing")
    print(f"verified {len(samples)} proofs with snarkjs")
    print("changed statement rejected by snarkjs")
    for name, sha in before.items():
        print(f"{name} sha256: {sha}")
    for elapsed, _, _ in samples:
        seconds, ns = divmod(elapsed, 1_000_000_000)
        print(f"warm prove: rapidsnark {seconds}.{ns // 1000:06d}s")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name, help_text in (
        ("library", "pinned Rapidsnark shared library"),
        ("r1cs", "ordered fixture R1CS export"),
        ("wtns", "ordered fixture witness export"),
        ("zkey", "snarkjs test-only proving key"),
        ("vk", "verification key from the same test-only setup"),
        ("fixture", "SDK fixture directory containing both public statement files"),
        ("snarkjs", "installed snarkjs package directory"),
    ):
        parser.add_argument(f"--{name}", type=Path, required=True, help=help_text)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--threads", type=int, default=2, help="OpenMP thread limit")
    args = parser.parse_args()
    if args.samples < 1 or args.warmups < 0 or args.threads < 1:
        parser.error("samples and threads must be positive and warmups nonnegative")
    try:
        run(args)
    except BenchmarkError as err:
        parser.exit(1, f"error: {err}\n")
    except (AttributeError, OSError, ValueError, subprocess.TimeoutExpired):
        parser.exit(
            1,
            "error: invalid benchmark input, unavailable runtime, or verifier timeout\n",
        )


if __name__ == "__main__":
    main()
