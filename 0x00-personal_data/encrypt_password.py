#!/usr/bin/env python3
""" Encrypts and validates passwords using bcrypt """
import bcrypt


def hash_password(password: str) -> bytes:
    """ Hashes the provided password """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validates the provided password """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
