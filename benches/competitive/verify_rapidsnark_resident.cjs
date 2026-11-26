#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const BN254_SCALAR_MODULUS =
    21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function readPublicHash(file) {
    const statement = JSON.parse(fs.readFileSync(file, "utf8"));
    const hash = statement?.public_hash;
    if (
        !statement ||
        Object.keys(statement).length !== 1 ||
        typeof hash !== "string" ||
        !/^(0|[1-9][0-9]*)$/.test(hash) ||
        BigInt(hash) >= BN254_SCALAR_MODULUS
    ) {
        throw new Error("invalid SDK public statement");
    }
    return hash;
}

async function run(packageDirectory, mode, args) {
    const snarkjs = require(path.resolve(packageDirectory));
    if (mode === "witness" && args.length === 2) {
        const quiet = { info() {}, warn() {} };
        return (await snarkjs.wtns.check(...args, quiet)) === true;
    }
    if (mode !== "proofs" || args.length !== 3) {
        return false;
    }
    const [vkFile, expectedFile, changedFile] = args;
    const expected = readPublicHash(expectedFile);
    const changed = readPublicHash(changedFile);
    if (expected === changed) {
        return false;
    }
    const vk = JSON.parse(fs.readFileSync(vkFile, "utf8"));
    const samples = JSON.parse(fs.readFileSync(0, "utf8"));
    if (!Array.isArray(samples) || samples.length === 0) {
        return false;
    }
    for (const sample of samples) {
        if (
            !Array.isArray(sample.public) ||
            sample.public.length !== 1 ||
            sample.public[0] !== expected ||
            (await snarkjs.groth16.verify(vk, [expected], sample.proof)) !== true
        ) {
            return false;
        }
    }
    return (await snarkjs.groth16.verify(vk, [changed], samples[0].proof)) === false;
}

const [packageDirectory, mode, ...args] = process.argv.slice(2);
// ffjavascript may retain worker threads after verification.
run(packageDirectory, mode, args).then(
    (accepted) => process.exit(accepted ? 0 : 1),
    () => process.exit(2),
);
