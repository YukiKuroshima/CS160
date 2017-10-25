import unittest
import json
from app import create_app, db


class UserAPITestCase(unittest.TestCase):
    def setUp(self):
        """Define test variables and initialize app."""
        self.app = create_app(config_name="testing")
        self.client = self.app.test_client
        self.user_data = {
                "first_name": "a",
                "last_name": "a",
                "credit_card": 1234,
                "email": "1.@.1c12om",
                "driver": False,
                "username": "n1a2me",
                "password": "a"
                }
        self.driver_data = {
                "first_name": "a",
                "last_name": "a",
                "credit_card": 1234,
                "email": "1.@.1c12om",
                "driver": True,
                "username": "n1a2me",
                "password": "a"
                }
        self.missing_value_user_data = {
                "first_name": "a",
                "last_name": "a",
                # "credit_card": 1234, "email": "1.@.1c12om",
                "driver": False,
                "username": "n1a2me",
                "password": "a"
                }
        self.user_auth_data = {
                "username": "n1a2me", "password": "a"
                }
        self.missing_value_user_auth_data = {
                "password": "a"
                }
        self.wrong_username_user_auth_data = {
                "username": "1n1a2me",
                "password": "a"
                }
        self.wrong_pw_user_auth_data = {
                "username": "1n1a2me",
                "password": "a"
                }
        self.missing_start_location = {
                # "start_location": "Start from here test",
                "end_location": "End here test"
                }
        self.missing_end_location = {
                "start_location": "Start from here test"
                # "end_location": "End here test"
                }
        self.location_data = {
                "start_location": "Start from here test",
                "end_location": "End here test"
                }
        # binds the app to the current context
        with self.app.app_context():
            # create all tables
            db.drop_all()
            db.create_all()

    """Helper methods"""
    def jsonify(self, data):
        return json.loads(data.decode('utf-8'))

    """
    Create n users and return as a list
    """
    def create_n_users(self, size):
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

    """
    Create n ride request and return as a list
    """
    def create_n_ride_data(self, size):
        ride_data = []
        for i in range(size):
            ride_data.append({
                "start_location": "Start from here%d" % i,
                "end_location": "End here%d" % i,
                })
        return ride_data

    def register(self, data):
        return self.client().post(
                '/register',
                data=json.dumps(data),
                content_type='application/json'
                )

    def auth(self, data):
        return self.client().post(
                '/auth',
                data=json.dumps(data),
                content_type='application/json'
                )

    """Register and auth a user and return the token"""
    def register_and_auth(self, data):
        self.register(data)
        username = data['username']
        password = data['password']
        auth_data = {
                "username": username,
                "password": password
                }
        res = self.auth(auth_data)
        res_in_json = self.jsonify(res.data)
        return res_in_json['access_token']

    """Register and auth multiple users and return the tokens as array"""
    # Data: List of user datas
    def register_and_auth_users(self, data):
        tokens = []
        for user_info in data:
            tokens.append(self.register_and_auth(user_info))
        return tokens

    def request_a_ride(self, data, token):
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
        for ride_req, token in zip(data, tokens):
            self.request_a_ride(ride_req, token)

    def search_rides(self, token):
        print("search rides " + str(type(token)))
        print("search rides " + token)
        return self.client().get(
                '/search',
                headers=dict(Authorization="Bearer " + str(token))
                )

    """Testing cases"""

    """Testing POST /register"""
    def test_GET_hello(self):
        """Test it can call GET /hello and get hello"""
        res = self.client().get('/hello')
        self.assertEqual(res.status_code, 200)
        self.assertIn('hello', str(res.data))

    def test_POST_register(self):
        """Test it returns 201 """
        res = self.register(self.user_data)
        res_in_json = self.jsonify(res.data)
        print(res_in_json)
        self.assertEqual(res.status_code, 201)
        self.assertIn('New user created', str(res_in_json['message']))

    def test_POST_register_missing_attr(self):
        """Test it returns 400 when one or more value is missing"""
        res = self.register(self.missing_value_user_data)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn('Missing value', str(res_in_json['err']))

    def test_POST_register_dup_attr(self):
        """Test it returns 400 when email or
        username already taken (duplicate)"""
        self.register(self.user_data)
        res = self.register(self.user_data)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn('Duplicate value', str(res_in_json['err']))

    """Testing POST /auth"""
    def test_POST_auth(self):
        """Test it returns 200 with correct username and password"""
        self.register(self.user_data)
        res = self.auth(self.user_auth_data)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 200)
        self.assertIn(
                'You logged in successfully',
                str(res_in_json['message']))
        self.assertIsNotNone(res_in_json['access_token'])

    def test_POST_auth_missing_value(self):
        """Test it returns 500 for missing value"""
        res = self.auth(self.missing_value_user_auth_data)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 500)
        self.assertIn(
                'username',
                str(res_in_json['err']))

    def test_POST_auth_wrong_username(self):
        """Test it returns 401 for wrong username"""
        self.register(self.user_data)
        res = self.auth(self.wrong_username_user_auth_data)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 401)
        self.assertIn(
            'Invalid username or password',
            str(res_in_json['err']))

    def test_POST_auth_wrong_password(self):
        """Test it returns 401 for wrong password"""
        self.register(self.user_data)
        res = self.auth(self.wrong_username_user_auth_data)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 401)
        self.assertIn(
            'Invalid username or password',
            str(res_in_json['err']))

    """Testing POST /request"""
    def test_POST_request(self):
        """Test it returns 201"""
        token = self.register_and_auth(self.user_data)
        res = self.request_a_ride(self.location_data, token)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 201)
        self.assertIn(
                'Ride requested successfully',
                str(res_in_json['message']))
        self.assertIsInstance(res_in_json['ride_id'], int)

    def test_POST_request_missing_start_location(self):
        """Test it returns 400 for missing start location"""
        token = self.register_and_auth(self.user_data)
        res = self.request_a_ride(self.missing_start_location, token)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn(
                'Missing value',
                str(res_in_json['err']))
        self.assertIn(
                'start_location',
                str(res_in_json['info']))

    def test_POST_request_missing_end_location(self):
        """Test it returns 400 for missing start location"""
        token = self.register_and_auth(self.user_data)
        res = self.request_a_ride(self.missing_end_location, token)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn(
                'Missing value',
                str(res_in_json['err']))
        self.assertIn(
                'end_location',
                str(res_in_json['info']))

    def test_POST_request_no_jwt(self):
        """Test it returns 400"""
        res = self.client().post(
                '/request',
                )
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn(
                'No access token found', str(res_in_json['err']))

    def test_GET_search(self):
        """Test it returns 200 and query result"""
        SIZE = 5
        # Regi and auth one driver
        driver_token = self.register_and_auth(self.driver_data)
        # Create 5 users
        users = self.create_n_users(SIZE)
        # Regi and auth 5 users
        user_tokens = self.register_and_auth_users(users)
        # Create 5 ride data
        ride_data = self.create_n_ride_data(SIZE)
        # Request 5 rides
        self.request_rides(ride_data, user_tokens)
        # Make API call to get all ride req data
        res = self.search_rides(driver_token)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 200)
        self.assertIn(
                'Ride query return successfully',
                str(res_in_json['message']))
        self.assertIs(SIZE, len(res_in_json['rides']))

    def test_GET_search_none_driver_cannot_get_result(self):
        """Test it returns 400 for customre (none driver)"""
        user_token = self.register_and_auth(self.user_data)
        res = self.search_rides(user_token)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn(
                'You are not driver. Only driver can see the requests',
                str(res_in_json['err']))

    def test_GET_search_empty_list(self):
        """Test it returns 200 and empty list if there is no request"""
        # Regi and auth one driver
        driver_token = self.register_and_auth(self.driver_data)
        # Make API call to get all ride req data
        res = self.search_rides(driver_token)
        res_in_json = self.jsonify(res.data)
        self.assertEqual(res.status_code, 200)
        self.assertIn(
                'Ride query return successfully',
                str(res_in_json['message']))

    def tearDown(self):
        """teardown all initialized variables."""
        with self.app.app_context():
            # drop all tables
            db.session.remove()
            db.drop_all()


# Make the tests conveniently executable
if __name__ == "__main__":
    unittest.main()
