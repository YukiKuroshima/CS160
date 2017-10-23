from app import db


class Users(db.Model):
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

    def __init__(self, first_name, last_name, credit_card, email,
                 driver, username, password):
        """Iniitalize with name"""
        self.first_name = first_name
        self.last_name = last_name
        self.credit_card = credit_card
        self.email = email
        self.driver = driver
        self.username = username
        self.password = password

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