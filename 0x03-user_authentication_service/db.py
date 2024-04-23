#!/usr/bin/env python3
""" module for db """


from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from user import User, Base


class DB:
    def __init__(self):
        """
        Constructor for initializing the DB class.
        It creates an engine to connect to the SQLite database 'mydatabase.db'
        and sets up the session for interacting with the database.
        """
        engine = create_engine('sqlite:///mydatabase.db')
        Base.metadata.create_all(engine)
        self._session = sessionmaker(bind=engine)()

    def add_user(self, email: str, hashed_password: str) -> User:
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        self._session.commit()
        return user
