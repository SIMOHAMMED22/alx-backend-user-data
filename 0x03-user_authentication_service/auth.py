#!/usr/bin/env python3

from typing import TypeVar, Union
import uuid
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import sessionmaker
import hashlib

from db import DB
from user import User
U = TypeVar('U', bound=User)


def _hash_password(password: str) -> bytes:
    """Hash a password using bcrypt"""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def _generate_uuid() -> str:
    """ generate uuid """
    return str(uuid.uuid4())


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

    def create_session(self, email: str) -> Union[None, str]:
        """ create session """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[None, U]:
        """ get user from session id """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

        return user

    def destroy_session(self, user_id: int) -> None:
        """ destroy session """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            return None
        return None

    def get_reset_password_token(self, email: str) -> str:
        """ get reset password token """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError

        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """ update password function """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError()

        hashed = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed, reset_token=None)
