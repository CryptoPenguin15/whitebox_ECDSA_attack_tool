"""Value fault in r (correct r returned) or rd

We have the four equations:
s_good1 * k1 = r_good1 * x + digest1 (1)
s_bad1  * k1 =       e * Z + digest1 (2)
s_good2 * k2 = r_good2 * x + digest2 (3)
s_bad2  * k2 =       e * Z + digest2 (4),
with Z = e*d or Z = d, depending on the localisation on the fault (on r or on r*d).

We can solve this:
s_bad1*(1)-s_good1*(2) => s_good1 * e * Z = s_bad1 * r_good1 * x + digest1 * (s_bad1 - s_good1) (4)
s_bad2*(3)-s_good2*(4) => s_good2 * e * Z = s_bad2 * r_good2 * x + digest2 * (s_bad2 - s_good2) (5)

s_good2*(4)-s_good1*(5) => 0 = s_good2 * s_bad1 * r_good1 * x + s_good2 * digest1 * (s_bad1 - s_good1)
                              -s_good1 * s_bad2 * r_good2 * x - s_good1 * digest2 * (s_bad2 - s_good2)

<=>                        x = (s_good1 * digest2 * (s_bad2 - s_good2) - s_good2 * digest1 * (s_bad1 - s_good1)) /
                               (s_good2 * s_bad1 * r_good1 - s_good1 * s_bad2 * r_good2)
"""

from ecdsa.curves import NIST256p
from ecdsa.util import randrange

from .common import _ecdsa_sign
from signature import Signature


def FC1(good1: Signature, bad1: Signature, good2: Signature, bad2: Signature) -> int:
    assert good1.h == bad1.h and good2.h == bad2.h

    digest1 = good1.h
    digest2 = good2.h
    denom = good2.s * bad1.s * good1.r - good1.s * bad2.s * good2.r
    num = good1.s * digest2 * (bad2.s - good2.s) - good2.s * digest1 * (
        bad1.s - good1.s
    )
    n = NIST256p.order
    if denom % n == 0:
        return 0
    return (num * pow(denom, -1, n)) % n


def _ecdsa_sign_with_fault(msg: int, x: int, k: int, e: int) -> Signature:
    n = NIST256p.order

    kinv = pow(k, n - 2, n)
    r = e  # fault in r
    s = (kinv * (msg + x * r)) % n
    return Signature(msg, r, s)


def test_fc1():
    n = NIST256p.order

    msg1 = randrange(n)
    msg2 = randrange(n)
    k1 = randrange(n)
    k2 = randrange(n)
    x = randrange(n)
    e = randrange(n)  # error

    sig1 = _ecdsa_sign(msg1, x, k1)
    sig2 = _ecdsa_sign_with_fault(msg1, x, k1, e)
    sig3 = _ecdsa_sign(msg2, x, k2)
    sig4 = _ecdsa_sign_with_fault(msg2, x, k2, e)
    assert FC1(sig1, sig2, sig3, sig4) == x
