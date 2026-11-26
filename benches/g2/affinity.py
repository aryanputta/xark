#!/usr/bin/env python3
"""Choose a two-thread placement using the Linux guest's reported CPU topology."""

import argparse
import json
import os
import subprocess


def choose_pair(lscpu, allowed, policy):
    allowed = sorted(set(allowed))
    if len(allowed) < 2:
        raise ValueError("the benchmark needs at least two allowed logical CPUs")
    processors = {}
    for source in lscpu.splitlines():
        line = source.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(",")
        if len(fields) != 3:
            continue
        try:
            cpu, core, socket = map(int, fields)
        except ValueError:
            continue
        if cpu in allowed and core >= 0 and socket >= 0:
            processors[cpu] = (socket, core)

    siblings = []
    physical = []
    for a, topology_a in sorted(processors.items()):
        for b, topology_b in sorted(processors.items()):
            if b <= a:
                continue
            if topology_a == topology_b:
                siblings.append((a, b))
            elif topology_a[0] == topology_b[0]:
                physical.append((a, b))
    if policy == "smt":
        possibilities, placement = siblings, "smt-siblings"
    elif policy == "physical":
        possibilities, placement = physical, "same-socket-distinct-cores"
    elif policy == "auto":
        if siblings:
            possibilities, placement = siblings, "smt-siblings"
        elif physical:
            possibilities, placement = physical, "same-socket-distinct-cores"
        else:
            possibilities, placement = [tuple(allowed[:2])], "unclassified"
    else:
        raise ValueError(f"unknown affinity policy {policy}")
    if not possibilities:
        raise ValueError(f"Linux does not expose the requested {policy} placement")
    cpus = list(possibilities[0])
    return {
        "requested": policy,
        "placement": placement,
        "cpus": cpus,
        "allowed_cpus": allowed,
        "reported_socket_core": {
            str(cpu): processors[cpu] for cpu in cpus if cpu in processors
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", choices=("auto", "smt", "physical"))
    args = parser.parse_args()
    try:
        topology = subprocess.check_output(
            ["lscpu", "-p=CPU,CORE,SOCKET"], text=True, timeout=15
        )
        print(json.dumps(choose_pair(topology, os.sched_getaffinity(0), args.policy)))
    except (AttributeError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"affinity: {error}\n")


if __name__ == "__main__":
    main()
