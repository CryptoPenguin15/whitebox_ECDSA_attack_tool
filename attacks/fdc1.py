"""Differential fault in r, rd, h, rd+h

We have four equations:
s_good1 * k1 = r_good1 * x + digest1          (1)
s_bad1  * k1 = r_bad1  * x + digest1 + e*Z,   (2)
s_good2 * k2 = r_good2 * x + digest2          (3)
s_bad2  * k2 = r_bad2  * x + digest2 + e*Z,   (4)
with Z = d if the fault is on r and Z = 1 otherwise
We can solve this:
s_bad1*(1)-s_good1*(2)=> s_good1 * e*Z = s_bad1 * r_good1 * x + s_bad1 * digest1 - s_good1 * r_bad1  * x - s_good1 * digest1  (5)
s_bad2*(3)-s_good2*(4)=> s_good2 * e*Z = s_bad2 * r_good2 * x + s_bad2 * digest2 - s_good2 * r_bad2  * x - s_good2 * digest2  (6)
s_good2*(5)-s_good1*(6)=> 0 = s_good2 * s_bad1 * r_good1 * x + s_good2 * s_bad1 * digest1 - s_good2 * s_good1 * r_bad1  * x - s_good2 * s_good1 * digest1
                            - s_good1 * s_bad2 * r_good2 * x - s_good1 * s_bad2 * digest2 + s_good1 * s_good2 * r_bad2  * x + s_good1 * s_good2 * digest2

                       => 0 = x * (s_good2 * s_bad1 * r_good1 - s_good1 * s_bad2 * r_good2 + s_good1 * s_good2 * (r_bad2 - r_bad1))
                                s_good2 * s_bad1 * digest1 - s_good1 * s_bad2 * digest2 + s_good1 * s_good2 * (digest2 -digest1)
<=>  x = (s_good1 * s_good2 * (digest1 - digest2) + s_good1 * s_bad2 * digest2 - s_good2 * s_bad1 * digest1)
         / (s_good2 * s_bad1 * r_good1 - s_good1 * s_bad2 * r_good2 + s_good1 * s_good2 * (r_bad2 - r_bad1))
"""

from ecdsa.curves import NIST256p
from ecdsa.util import randrange

from .common import _ecdsa_sign
from signature import Signature


def FDC1(
    good1: Signature,
    bad1: Signature,
    good2: Signature,
    bad2: Signature,
) -> int:
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    num = (
        good1.s * good2.s * (digest1 - digest2)
        + good1.s * bad2.s * digest2
        - good2.s * bad1.s * digest1
    )
    denom = (
        good2.s * bad1.s * good1.r
        - good1.s * bad2.s * good2.r
        + good1.s * good2.s * (bad2.r - bad1.r)
    )
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n


def _ecdsa_sign_with_fault(msg: int, x: int, k: int, e: int) -> Signature:
    n = NIST256p.order

    Q = k * NIST256p.generator
    r = Q.x() % n
    kinv = pow(k, n - 2, n)
    s = (kinv * (msg + x * r + e)) % n
    return Signature(msg, r, s)


def test_fdc1():
    n = NIST256p.order

    msg1 = randrange(n)
    msg2 = randrange(n)
    k1 = randrange(n)
    k2 = randrange(n)
    x = randrange(n)

    e = randrange(n)  # error in k

    sig1 = _ecdsa_sign(msg1, x, k1)
    sig2 = _ecdsa_sign_with_fault(msg1, x, k1, e)
    sig3 = _ecdsa_sign(msg2, x, k2)
    sig4 = _ecdsa_sign_with_fault(msg2, x, k2, e)
    assert FDC1(sig1, sig2, sig3, sig4) == x
