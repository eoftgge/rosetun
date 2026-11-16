"""The one-time SSH key of the lab's poller (stage 8d): a new Ed25519 pair for each run, made on the controller.

The controller has no SSH tools of its own to rely on and installs nothing, so the public key is derived here with the
reference construction of RFC 8032 (section 6; only the public half, no signing) and the private key is written in
the OpenSSH key format that `ssh -i` reads. Neither half is ever logged, hashed into a summary or kept in a run
directory: the public blob goes into `job.env` of the test machine, the private key into the request that sets the lab
machine up, and both are forgotten when the run ends.
"""

import base64
import hashlib
import os
import struct

P = 2 ** 255 - 19
D = -121665 * pow(121666, P - 2, P) % P
Q = 2 ** 252 + 27742317777372353535851937790883648493
SQRT_M1 = pow(2, (P - 1) // 4, P)
KEY_TYPE = b'ssh-ed25519'
# The text before the blob in an authorized_keys line is the type; the blob starts with the same type as a string.
BLOB_HEAD = struct.pack('>I', len(KEY_TYPE)) + KEY_TYPE + struct.pack('>I', 32)
PEM_BEGIN, PEM_END = '-----BEGIN OPENSSH PRIVATE KEY-----', '-----END OPENSSH PRIVATE KEY-----'
COMMENT = b'rosetun-lab-poller'


def _recover_x(y, sign):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * SQRT_M1 % P
    if (x * x - xx) % P:
        raise ValueError('not-on-the-curve')
    return P - x if x & 1 != sign else x


BASE_Y = 4 * pow(5, P - 2, P) % P
BASE = (_recover_x(BASE_Y, 0), BASE_Y, 1, _recover_x(BASE_Y, 0) * BASE_Y % P)


def _add(a, b):
    a_, b_ = (a[1] - a[0]) * (b[1] - b[0]) % P, (a[1] + a[0]) * (b[1] + b[0]) % P
    c, d = 2 * a[3] * b[3] * D % P, 2 * a[2] * b[2] % P
    e, f, g, h = b_ - a_, d - c, d + c, b_ + a_
    return e * f % P, g * h % P, f * g % P, e * h % P


def _multiply(scalar, point):
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _compress(point):
    zinv = pow(point[2], P - 2, P)
    x, y = point[0] * zinv % P, point[1] * zinv % P
    return int.to_bytes(y | (x & 1) << 255, 32, 'little')


def public_key(seed):
    """The 32-byte public key of a 32-byte seed (RFC 8032, section 5.1.5)."""
    if type(seed) is not bytes or len(seed) != 32:
        raise ValueError('invalid-seed')
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], 'little')
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return _compress(_multiply(scalar, BASE))


def _string(value):
    return struct.pack('>I', len(value)) + value


def public_blob(public):
    """The blob of an ssh-ed25519 public key: what follows the type in an authorized_keys line."""
    return _string(KEY_TYPE) + _string(public)


def private_text(seed, public, check=None):
    """The unencrypted OpenSSH private key file (openssh-key-v1) of the pair."""
    check = os.urandom(4) if check is None else check
    private = (check + check + _string(KEY_TYPE) + _string(public) + _string(seed + public) + _string(COMMENT))
    private += bytes(range(1, 8 - len(private) % 8 + 1)) if len(private) % 8 else b''
    blob = (b'openssh-key-v1\0' + _string(b'none') + _string(b'none') + _string(b'') + struct.pack('>I', 1)
            + _string(public_blob(public)) + _string(private))
    body = base64.b64encode(blob).decode('ascii')
    return PEM_BEGIN + '\n' + '\n'.join(body[i:i + 70] for i in range(0, len(body), 70)) + '\n' + PEM_END + '\n'


def new_pair(random=os.urandom):
    """(private key file text, base64 of the public blob) of a fresh key."""
    seed = random(32)
    public = public_key(seed)
    return private_text(seed, public), base64.b64encode(public_blob(public)).decode('ascii')
