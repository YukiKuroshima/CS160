import unittest
from app import create_app, db
from test_methods import *


class UserAPITestCase(unittest.TestCase):

    # """Helper methods"""
    # def jsonify(self, data):
    #     return json.loads(data.decode('utf-8'))

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

    def tearDown(self):
        """teardown all initialized variables."""
        with self.app.app_context():
            # drop all tables
            db.session.remove()
            db.drop_all()

    """Testing cases"""

    """Testing POST /test_methods.register"""
    def test_GET_hello(self):
        """Test it can call GET /hello and get hello"""
        res = self.client().get('/hello')
        self.assertEqual(res.status_code, 200)
        self.assertIn('hello', str(res.data))

    def test_POST_register(self):
        """Test it returns 201 """
        res = register(self, self.user_data)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 201)
        self.assertIn('New user created', str(res_in_json['message']))

    def test_POST_register_missing_attr(self):
        """Test it returns 400 when one or more value is missing"""
        res = register(self, self.missing_value_user_data)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn('missing', str(res_in_json['err']))

    def test_POST_register_dup_attr(self):
        """Test it returns 400 when email or
        username already taken (duplicate)"""
        res = register(self, self.user_data)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 201)
        self.assertIn('New user created', str(res_in_json['message']))
        res2 = register(self, self.driver_data)
        res_in_json2 = jsonify(res2.data)
        self.assertIn('Duplicate', str(res_in_json2['err']))

    """Testing POST /request"""
    def test_POST_request(self):
        """Test it returns 201"""
        token = register_and_auth(self, self.user_data)
        res = request_a_ride(self, self.location_data, token)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 201)
        self.assertIn(
                'Ride requested successfully',
                str(res_in_json['message']))
        self.assertIsInstance(res_in_json['ride_id'], int)

    def test_POST_request_missing_start_location(self):
        """Test it returns 400 for missing start location"""
        token = register_and_auth(self, self.user_data)
        res = request_a_ride(self, self.missing_start_location, token)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn(
                'Missing value',
                str(res_in_json['err']))
        self.assertIn(
                'start_location',
                str(res_in_json['info']))

    def test_POST_request_missing_end_location(self):
        """Test it returns 400 for missing start location"""
        token = register_and_auth(self, self.user_data)
        res = request_a_ride(self, self.missing_end_location, token)
        res_in_json = jsonify(res.data)
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
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn(
                'No access token found', str(res_in_json['err']))

    def test_GET_search(self):
        """Test it returns 200 and query result"""
        SIZE = 5
        # Regi and auth one driver
        driver_token = register_and_auth(self, self.driver_data)
        # Create 5 users
        users = create_n_users(SIZE)
        # Regi and auth 5 users
        user_tokens = register_and_auth_users(self, users)
        # Create 5 ride data
        ride_data = create_n_ride_data(SIZE)
        # Request 5 rides
        request_rides(self, ride_data, user_tokens)
        # Make API call to get all ride req data
        res = search_rides(self, driver_token)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 200)
        self.assertIn(
                'Ride query return successfully',
                str(res_in_json['message']))
        self.assertIs(SIZE, len(res_in_json['rides']))

    def test_GET_search_none_driver_cannot_get_result(self):
        """Test it returns 400 for customre (none driver)"""
        user_token = register_and_auth(self, self.user_data)
        res = search_rides(self, user_token)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 400)
        self.assertIn(
                'You are not driver. Only driver can see the requests',
                str(res_in_json['err']))

    def test_GET_search_empty_list(self):
        """Test it returns 200 and empty list if there is no request"""
        # Regi and auth one driver
        driver_token = register_and_auth(self, self.driver_data)
        # Make API call to get all ride req data
        res = search_rides(self, driver_token)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 200)
        self.assertIn(
                'Ride query return successfully',
                str(res_in_json['message']))


# Make the tests conveniently executable
if __name__ == "__main__":
    unittest.main()
