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
        try:
            self._db.find_user_by(email=email)
            raise ValueError("User {} already exists.".format(email))
        except NoResultFound:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
            """ validate login """
            try:
                user = self._db.find_user_by(email=email)
            except NoResultFound:
                return False

            user_passwd = user.hashed_password
            passwd = password.encode("utf-8")
            return bcrypt.checkpw(passwd, user_passwd)
