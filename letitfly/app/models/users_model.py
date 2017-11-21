from app.models.database import db
from flask import current_app
import jwt
from app.models.drives_model import Rides
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
    password = db.Column(db.String(25), nullable=False)
    date_created = db.Column(db.String(50))
    date_modified = db.Column(db.String(50))

    def __init__(self,
                 first_name,
                 last_name,
                 email,
                 username,
                 password,
                 credit_card,
                 driver,
                 date_created,
                 date_modified):
        """Iniitalize with user info"""
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.username = username
        self.password = password
        self.credit_card = credit_card
        self.driver = driver
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

    def is_driver(self):
        """
        Returns True if self is a driver
        False if self is a customer
        """
        return self.driver

    def has_incompleted_ride(self):
        """
        Check if the user has incompleted ride
        Return false if the user does not have any incompleted ride
        (means all rides are completed)
        true if user has incompleted ride
        """
        rides = Rides.find_ride_by_email(self.email)
        for ride in rides:
            if ride.is_completed() is False:
                return True
        return False

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
