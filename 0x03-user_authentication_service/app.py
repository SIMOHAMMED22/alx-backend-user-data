#!/usr/bin/env python3

import dbm
from os import abort
import uuid
import dbus
from flask import Flask, jsonify, make_response, request
from flask.json import jsonify as flask_jsonify
from mysqlx import DbDoc
from werkzeug.exceptions import BadRequest
from sqlalchemy.orm.exc import NoResultFound

from auth import Auth
from db import DB
from user import User

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    """Return a JSON payload with a welcome message.
    """
    return flask_jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")

AUTH = Auth()


@app.route("/users", methods=["POST"])
def users():
    """Register a new user with the given email and password.

    :return: A JSON payload with a success message and the registered email
    :raises BadRequest: If the user is already registered
    """
    # Get the email and password from the request form data
    email = request.form.get("email")
    password = request.form.get("password")

    # Check if the email and password are present
    if email is None or password is None:
        raise BadRequest("Both email and password are required")

    # Register the user
    try:
        user = AUTH.register_user(email, password)
    except ValueError as e:
        # If the user is already registered, catch the exception
        # and return a 400 status code
        if str(e) == f"User {email} already exists":
            return flask_jsonify({"message": "email already registered"}), 400
        else:
            # If an unexpected exception is raised, propagate it
            raise

    # Return a JSON payload with a success message and the registered email
    return flask_jsonify({"email": user.email, "message": "user created"})

@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
        """Handle requests to get a reset password token.

        :return: A JSON payload with the user's email and reset token if the email is registered, or a 403 HTTP status if the email is not registered.
        :rtype: flask.Response
        """
        email = request.form.get("email")

        if email is None:
            abort(403, description="Email is required")

        try:
            user = dbus._session.query(User).filter_by(email=email).first()
        except NoResultFound:
            abort(403, description="Email is not registered")

        reset_token = str(uuid.uuid4())
        user.reset_token = reset_token
        DbDoc._session.commit()

        response = make_response(jsonify({"email": user.email, "reset_token": reset_token}))
        response.status_code = 200

        return response
