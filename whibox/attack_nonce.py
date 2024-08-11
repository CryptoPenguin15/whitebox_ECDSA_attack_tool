"""
This code tries to find a repeating nonce in the ECDSA whitebox.

"""
import argparse
import os
import random
import string
import subprocess
from typing import Optional

from ecdsa.curves import Curve, NIST256p
from ecdsa.ellipticcurve import Point
from ecdsa.numbertheory import inverse_mod

from ecdsattack import Signature

ORIGINAL_FILENAME_HASH = "main_hash"
ECDSA_SIG_SIZE = 256 // 8 * 2

MAX_TRIES_WO_EFFECT = 100
DIGEST_A = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

def nonce_and_run(origin_file_name: str, digest: int):
    try:
        run_out = subprocess.check_output([
            os.path.join(".", origin_file_name), digest], stderr=subprocess.DEVNULL, timeout=11
        ).decode()
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        OSError,
        UnicodeDecodeError,
    ):
        return None
    return run_out


def get_signature(
    original_file_name: str, digest: int,
) -> Optional[Signature]:
    output = nonce_and_run(original_file_name, str(digest.to_bytes(32, "big").hex()))
    if not output:
        return None

    if len(output) == 129 and all(c in string.hexdigits for c in output[:128]):
        r = int(output[0:ECDSA_SIG_SIZE], 16)
        s = int(output[ECDSA_SIG_SIZE : 2 * ECDSA_SIG_SIZE], 16)
        return Signature(digest, r, s)
    return None


def compile_challenge(name: str, challenge_id: int):
    subprocess.run(
        [
            "gcc",
            os.path.join("drivers", name + ".c"),
            os.path.join("drivers", "mocks.c"),
            os.path.join("challenges", str(challenge_id), "source.c"),
            "-o",
            name,
            "-no-pie",
            "-fno-stack-protector",
            "-lgmp",
        ],
        stdout=None,
        stderr=subprocess.DEVNULL,
        check=True,
    )


def load_public_key(challenge_id: int) -> Point:
    with open(os.path.join("challenges", str(challenge_id), "pubkey"), encoding="utf-8") as f:
        pubkey_data = f.read()
    public_key = Point(
        NIST256p.curve, int(pubkey_data[:64], 16), int(pubkey_data[64:], 16)
    )
    return public_key


def recover_key_nonce(
    curve: Curve,
    generator: Point,
    public_key: Point,
    s1: Signature, s2: Signature
) -> Optional[int]:

    n = curve.order
    d = ((s2.s * s1.h - s1.s * s2.h) * inverse_mod(s1.r * (s1.s - s2.s), n)) % n

    if d * generator == public_key:
        return d
    return None


def ecdsa_nonce_attack(challenge_id: int):
    public_key = load_public_key(challenge_id)
    print("Target pubkey:", public_key)

    # get a couple valid signatures
    compile_challenge(ORIGINAL_FILENAME_HASH, challenge_id)

    sig = get_signature(ORIGINAL_FILENAME_HASH, DIGEST_A)
    if not sig:
        print("Check ", ORIGINAL_FILENAME_HASH)
        return

    nb_sigs = 0
    value_dict = {}
    for i in range(MAX_TRIES_WO_EFFECT):
        digest_rnd = random.getrandbits(256)
        sig = get_signature(ORIGINAL_FILENAME_HASH, digest_rnd)
        if sig:
            nb_sigs += 1
            if sig.r in value_dict:
                d = recover_key_nonce(NIST256p, NIST256p.generator, public_key,
                    sig, value_dict[sig.r])
                if d:
                    print("Found correct public point:", public_key)
                    print("Found private key:", d)
                    print("In hex:", hex(d))
                    print("# attempts = ", i)
                    return
            value_dict[sig.r] = sig
    print("# hashes without effect = ", nb_sigs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("challenge_id", help="Challenge identifier to attack", type=int)

    args = parser.parse_args()
    ecdsa_nonce_attack(args.challenge_id)


if __name__ == "__main__":
    main()
