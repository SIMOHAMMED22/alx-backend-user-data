#!/usr/bin/env python3

import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import sessionmaker
import hashlib

from db import DB
from user import User


def _hash_password(password: str) -> bytes:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def _hash_password(self, password: str) -> str:
        """Hash the given password using SHA-256.

        :param password: The plaintext password to hash
        :return: The hashed password as a hexadecimal string
        """
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        return hashed_password

    def register_user(self, email: str, password: str) -> User:
        """Register a new user with the given email and password.

        :param email: The user's email address
        :param password: The user's plaintext password
        :return: The created User object
        :raises ValueError: If a user with the given email already exists
        """
        user = self._db._session.query(User).filter_by(email=email).first()
        if user is not None:
            raise ValueError(f"User {email} already exists")

        hashed_password = self._hash_password(password)
        user = User(email=email, hashed_password=hashed_password)
        self._db._session.add(user)
        self._db._session.commit()
        return user
