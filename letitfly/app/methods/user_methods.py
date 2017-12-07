import jwt
from flask import current_app
from datetime import datetime, timedelta
from werkzeug.security import safe_str_cmp
from app.models.users_model import User

"""
NOTE:
This file handles user information queries from the database.
"""

def validate_password(self, password):
        """
        Checks the password against it's hash to validates the user's password
        """
        return safe_str_cmp(
                self.password.encode('utf-8'),
                password.encode('utf-8'))


def generate_token(user_id):
        """Generates the access token to be used as the Authorization header"""

        try:
            # set up a payload with an expiration time
            payload = {
                'exp': datetime.utcnow() + timedelta(hours=24),
                'iat': datetime.utcnow(),
                'sub': user_id
            }
            # create the byte string token using the payload and the SECRET key
            jwt_string = jwt.encode(
                payload,
                current_app.config.get('SECRET'),
                algorithm='HS256'
            )
            return jwt_string

        except Exception as e:
            # return an error in string format if an exception occurs
            return str(e)


def find_user_by_user_id(user_id):
    """Find one user by user_id (Primary Key)"""
    try:
        return User.query.filter_by(
                user_id=user_id
                ).first()
    except Exception as e:
        # return an error in string format if an exception occurs
        return str(e)


def decode_token(token):
    """Decode the access token from the Authorization header."""
    try:
        payload = jwt.decode(token, current_app.config.get('SECRET'))
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return "Expired token. Please log in to get a new token"
    except jwt.InvalidTokenError:
        return "Invalid token. Please register or login"