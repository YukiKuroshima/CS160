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


def post(args):
    """
    Creates new user
    :args: user data
    """

    # validate credit card format
    potential_credit_card = args['credit_card']
    if (potential_credit_card.isdigit()) and \
       (len(potential_credit_card) is 15 or len(potential_credit_card) is 16):
        credit_card = potential_credit_card
    else:
        return None

    first_name = args['first_name']

    last_name = args['last_name']

    email = args['email']

    driver = args['driver']

    username = args['username']

    password = args['password']

    date_created = str(datetime.now())

    date_modified = date_created

    if credit_card and email and username and password \
       and first_name and last_name and driver:
            user = User(
                        first_name=first_name, last_name=last_name,
                        email=email, driver=driver, username=username,
                        password=password, date_created=date_created,
                        date_modified=date_modified
                        )

            user.save()

            return user.tojson()

    else:
        return None


def delete(args):
    """
    Deletes a user
    :args: data to find user in database
    """

    # find user
    user = User.query.filter_by(email=args['email']).first()

    if user:
        user.delete()
        return 'User deleted.'

    else:
        return None


def put(args):
    """
    Edit user info
    :args: user info
    """

    # find user in database
    user = User.query.filter_by(email=args['email']).first()

    # makes user info updates
    if user:
        for key in args:
            if hasattr(user, key):
                user.key = args[key]

        # note when user info updated
        user.date_modified = str(datetime.now())

        # save changes
        user.save()

        return user.tojson()

    else:
        return None


def get(args):
    """
    Edit user info
    :args: user info
    """

    # find user in database
    user = User.query.filter_by(email=args['email']).first()

    # makes user info updates
    if user:
        for key in args:
            if hasattr(user, key):
                user.key = args[key]

        # note when user info updated
        user.date_modified = str(datetime.now())

        # save changes
        user.save()

        return user.tojson()

    else:
        return None


# map which method to carry out
user_request = {
    "CREATE": post,
    "REMOVE": delete,
    "EDIT": put,
    "RETRIEVE": get
}


def manipulation(args):
    """
    Selects correct method via dict
    :args: arguments
    """
    response = user_request[args['request']](args) # need args to include http request
    return response
