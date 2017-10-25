from app.models.database import db
from app import db
from flask import current_app
import jwt
from datetime import datetime, timedelta
from werkzeug.security import safe_str_cmp


class User(db.Model):
    """This class represents the customers and drivers table"""

    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    credit_card = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    driver = db.Column(db.Boolean)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(25), nullable=False)
    date_created = db.Column(db.String(50))
    date_modified = db.Column(db.String(50))

    def __init__(self, first_name, last_name, credit_card, email,
                 driver, username, password, date_created,
                 date_modified):
        """Iniitalize with user info"""
        self.first_name = first_name
        self.last_name = last_name
        self.credit_card = credit_card
        self.email = email
        self.driver = driver
        self.username = username
        self.password = password
        self.date_created = date_created
        self.date_modified = date_modified

    def save(self):
        """Add user to database"""
        db.session.add(self)
        db.session.commit()

    def delete(self):
        """Delete user from database"""
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        """Represent user by name"""
        return "{} {}".format(self.first_name, self.last_name)

    def tojson(self):
        """Represent user data as JSON object"""
        return {
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'driver': self.driver
        }

    def validate_password(self, password):
        """
        Checks the password against it's hash to validates the user's password
        """
        return safe_str_cmp(
                self.password.encode('utf-8'),
                password.encode('utf-8'))

    def is_driver(self):
        """
        Returns True if self is a driver
        False if self is a customer
        """
        return self.driver

    def generate_token(self, user_id):
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

    @staticmethod
    def find_user_by_user_id(user_id):
        """Find one user by user_id (Primary Key)"""
        try:
            return User.query.filter_by(
                    user_id=user_id
                    ).first()
        except Exception as e:
            # return an error in string format if an exception occurs
            return str(e)

    @staticmethod
    def decode_token(token):
        """Decode the access token from the Authorization header."""
        try:
            payload = jwt.decode(token, current_app.config.get('SECRET'))
            return payload['sub']
        except jwt.ExpiredSignatureError:
            return "Expired token. Please log in to get a new token"
        except jwt.InvalidTokenError:
            return "Invalid token. Please register or login"
