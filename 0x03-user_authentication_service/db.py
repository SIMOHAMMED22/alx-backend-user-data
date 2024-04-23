#!/usr/bin/env python3
""" module for db """


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError

from user import User, Base


class DB:
    def __init__(self):
        engine = create_engine('sqlite:///mydatabase.db')
        Base.metadata.create_all(engine)
        self._session = sessionmaker(bind=engine)()

    def add_user(self, email: str, hashed_password: str) -> User:
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user

    def find_user_by(self, **kwargs) -> User:
        try:
            user = self._session.query(User).filter_by(**kwargs).first()
            if user is None:
                raise NoResultFound
            return user
        except InvalidRequestError:
            raise InvalidRequestError("Wrong query arguments passed")
