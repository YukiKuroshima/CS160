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
        self.missing_value_user_data = {
                "first_name": "a",
                "last_name": "a",
                # "credit_card": 1234, "email": "1.@.1c12om",
                "driver": False,
                "username": "n1a2me",
                "password": "a"
                }
        self.user_auth_data = {
                "username": "n1a2me",
                "password": "a"
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

    def request_a_ride(self, data, token):
        return self.client().post(
                '/request',
                data=json.dumps(data),
                content_type='application/json',
                headers=dict(Authorization="Bearer " + token)
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
        print(res_in_json)
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
        print(res_in_json)
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
                'No access token found',
                str(res_in_json['err']))

    def tearDown(self):
        """teardown all initialized variables."""
        with self.app.app_context():
            # drop all tables
            db.session.remove()
            db.drop_all()


# Make the tests conveniently executable
if __name__ == "__main__":
    unittest.main()
