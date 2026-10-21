# dh_utils.py
# Shared Diffie-Hellman helpers used by both server.py (Alice) and client.py (Bob)
import math
import secrets   # OS-level cryptographically secure RNG (replaces random, which is predictable)
import hashlib


def is_prime(n):
    # p must be prime for the multiplicative group of integers modulo p
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True


def is_primitive_root(g, p):
    # g is a primitive root mod p if g^k mod p gives every value 1..p-1
    values = set()
    for k in range(1, p):
        values.add(pow(g, k, p))   # same as (g ** k) % p, but much faster
    return len(values) == p - 1


def generate_private_key(p):
    # Secret integer in the range 2..p-2
    # secrets.randbelow(n) returns 0..n-1, so randbelow(p - 3) + 2 gives 2..p-2
    return secrets.randbelow(p - 3) + 2


def generate_public_key(g, private, p):
    # Public value: A = g^a mod p (Alice) or B = g^b mod p (Bob)
    return pow(g, private, p)


def compute_shared_secret(other_public, private, p):
    # Shared secret: s = B^a mod p (Alice) or s = A^b mod p (Bob)
    return pow(other_public, private, p)


def derive_aes_key(shared_secret):
    # AES-128 needs exactly 16 bytes -> hash the shared secret and take the first 16 bytes
    return hashlib.sha256(str(shared_secret).encode()).digest()[:16]
