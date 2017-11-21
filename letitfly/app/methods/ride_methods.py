from datetime import datetime
from app.models.users_model import Ride

"""
Find all imcomplted (Not picked up yet) ride requests and
return them as a list
"""
def find_all_not_picked_up_rides_in_json():
    try:
        rides = Rides.query.filter_by(
                # picked_up=False
                ).all()
        rides_json = [ride.tojson() for ride in rides]
        return rides_json
    except Exception as e:
        # return an error in string format if an exception occurs
        return str(e)
