import json


"""Helper methods for user test cases"""


def jsonify(data):
    """Return data as json object"""
    return json.loads(data.decode('utf-8'))


def create_n_users(size):
    """Create n users and return as a list"""
    users = []
    for i in range(size):
        users.append({
            "first_name": "First%d" % i,
            "last_name": "First%d" % i,
            "credit_card": i,
            "email": "%dgmai.com" % i,
            "username": "username%d" % i,
            "driver": False,
            "password": "%d" % i
            })
    return users


def create_n_ride_data(size):
    """Create n ride request and return as a list"""
    ride_data = []
    for i in range(size):
        ride_data.append({
            "start_location": "Start from here%d" % i,
            "end_location": "End here%d" % i,
            })
    return ride_data


def register(self, data):
    """Register user with given data"""
    return self.client().post(
            '/register',
            data=json.dumps(data),
            content_type='application/json'
            )


def auth(self, data):
    """Authenticate user with given data"""
    return self.client().post(
            '/auth',
            data=json.dumps(data),
            content_type='application/json'
            )


def register_and_auth(self, data):
    """Register and auth a user and return the token"""
    register(self, data)
    username = data['username']
    password = data['password']
    auth_data = {
            "username": username,
            "password": password
            }
    res = auth(self, auth_data)
    res_in_json = jsonify(res.data)
    return res_in_json['access_token']


def register_and_auth_users(self, data):
    """
    Register and auth multiple users and return the tokens as array
    :data: list of user dates
    """
    tokens = []
    for user_info in data:
        tokens.append(register_and_auth(self, user_info))
    return tokens


def request_a_ride(self, data, token):
    """
    Request a ride for user with given data and token
    :data: user data
    :token: authentication token
    """
    res = self.client().post(
            '/request',
            data=json.dumps(data),
            content_type='application/json',
            headers=dict(Authorization="Bearer " + token)
            )
    return res

"""
Put n of ride request into database
data: List of request data
* start_location
* end_location

tokens: List of JWTs

return: void
"""


def request_rides(self, data, tokens):
    """Request ride"""
    for ride_req, token in zip(data, tokens):
        request_a_ride(self, ride_req, token)


def search_rides(self, token):
    """Search for rides"""
    return self.client().get(
            '/search',
            headers=dict(Authorization="Bearer " + str(token))
            )
