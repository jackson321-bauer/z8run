"""Minimaler CBOR-/Base64url-Baukasten für den Software-Authenticator."""

import base64


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def cb_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 256:
        return bytes([(major << 5) | 24, n])
    return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")


def cb_bytes(b: bytes) -> bytes:
    return cb_head(2, len(b)) + b


def cb_text(s: str) -> bytes:
    b = s.encode()
    return cb_head(3, len(b)) + b


def cb_int(i: int) -> bytes:
    return cb_head(0, i) if i >= 0 else cb_head(1, -1 - i)


