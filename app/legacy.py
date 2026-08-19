"""Classical RSA key transport — the thing this project replaces.

Deliberately weak: a small modulus, so the break can be demonstrated live on a
laptop in under a second. At production sizes (RSA-2048) this factorisation is
infeasible classically, which is exactly the point — Shor's algorithm makes it
feasible on a quantum computer, and the same session key falls out.

Nothing here should ever be used for anything. It exists to be broken.
"""

import math
import random
import secrets

# 48-bit modulus: two 24-bit primes. Factors in milliseconds by Pollard's rho,
# so the demonstration is instant rather than a contrived wait.
LEGACY_MODULUS_BITS = 48
PUBLIC_EXPONENT = 65537


def _is_probable_prime(n, rounds=24):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_keypair(bits=LEGACY_MODULUS_BITS):
    """Returns (public=(n, e), private=(n, d)). Weak by construction."""
    half = bits // 2
    while True:
        p, q = _random_prime(half), _random_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(PUBLIC_EXPONENT, phi) == 1:
            return (n, PUBLIC_EXPONENT), (n, pow(PUBLIC_EXPONENT, -1, phi))


def wrap_session_key(session_key, public):
    """Textbook RSA over the key, chunked to fit the small modulus.

    The key is zero-padded up to a whole number of chunks so every block
    decrypts back to exactly `chunk` bytes; otherwise the final short block
    reassembles with the wrong alignment.
    """
    n, e = public
    chunk = (n.bit_length() - 1) // 8
    padded = session_key + b"\x00" * (-len(session_key) % chunk)
    return [pow(int.from_bytes(padded[i:i + chunk], "big"), e, n)
            for i in range(0, len(padded), chunk)], chunk


def unwrap_session_key(blocks, chunk, private):
    n, d = private
    out = b""
    for block in blocks:
        value = pow(block, d, n)
        out += value.to_bytes(chunk, "big")
    return out[:32]


def pollards_rho(n):
    """Returns a non-trivial factor of n. This is what Shor's algorithm
    replaces with a polynomial-time quantum routine at real key sizes."""
    if n % 2 == 0:
        return 2
    while True:
        x = random.randrange(2, n)
        y, c, d = x, random.randrange(1, n), 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def recover_private_key(public):
    """Factors the modulus and reconstructs the private exponent."""
    n, e = public
    p = pollards_rho(n)
    q = n // p
    return (n, pow(e, -1, (p - 1) * (q - 1))), (p, q)
