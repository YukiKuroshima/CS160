from app import db
import datetime


class Rides(db.Model):
    """This table represents all the existing drives"""

    __tablename__ = 'drives'

    ride_id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey(
        'users.user_id'), nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey(
        'users.user_id'))
    start_location = db.Column(db.String(100), nullable=False)
    end_location = db.Column(db.String(100), nullable=False)
    current_lat = db.Column(db.String(100))
    current_lng = db.Column(db.String(100))
    time_finished = db.Column(db.String(50))
    # True if picked up (Customer may or may not arrive the destination)
    # False if not yet picked up
    picked_up = db.Column(db.Boolean, default=False)

    customer = db.relationship(
            'User',
            backref='customer_obj',
            foreign_keys=[customer_id]
            )

    driver = db.relationship(
            'User',
            backref='driver_obj',
            foreign_keys=[driver_id]
            )

    def save(self):
        """Add ride to database"""
        db.session.add(self)
        db.session.commit()

    def delete(self):
        """Delete ride from database"""
        db.session.delete(self)
        db.session.commit()

    def get_self_ride_id(self):
        return self.ride_id

    def set_current_to_time_finished(self):
        self.time_finished = datetime.datetime.now()
        self.save()

    def is_completed(self):
        """
        Return True if the ride is completed
        """
        return self.driver_id is not None and \
               self.picked_up is True and \
               self.time_finished is not None

    @staticmethod
    def find_rides_by_email(self, email):
        return Rides.query.filter_by(
                email=email
                ).all()

    """
    Find all imcomplted (Not picked up yet) ride requests and
    return them as a list
    """
    @staticmethod
    def find_all_not_picked_up_rides_in_json():
        try:
            rides = Rides.query.filter_by(
                    picked_up=False
                    ).all()
            rides_json = []
            for ride in rides:
                rides_json.append(ride.tojson())
            return rides_json
        except Exception as e:
            # return an error in string format if an exception occurs
            return str(e)

    @staticmethod
    def find_all_no_driver_assigned_rides_in_json():
        rides = Rides.query.filter_by(
                driver_id=None
                ).all()
        rides_json = []
        for ride in rides:
            rides_json.append(ride.tojson())
        return rides_json

    def __repr__(self):
        """Represent user by name"""
        return "{} {}".format(self.start_location, self.end_location)

    def tojson(self):
        """Represent ride data as JSON object"""
        return {
                'ride_id': self.ride_id,
                'customer_id': self.customer_id,
                'driver_id': self.driver_id,
                'start_location': self.start_location,
                'end_location': self.end_location,
                'time_finished': self.time_finished,
                'picked_up': self.picked_up
                }
