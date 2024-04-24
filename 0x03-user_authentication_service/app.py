#!/usr/bin/env python3

from flask import Flask, request
from flask.json import jsonify as flask_jsonify
from werkzeug.exceptions import BadRequest

app = Flask(__name__)
from auth import Auth


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
        # If the user is already registered, catch the exception and return a 400 status code
        if str(e) == f"User {email} already exists":
            return flask_jsonify({"message": "email already registered"}), 400
        else:
            # If an unexpected exception is raised, propagate it
            raise

    # Return a JSON payload with a success message and the registered email
    return flask_jsonify({"email": user.email, "message": "user created"})
