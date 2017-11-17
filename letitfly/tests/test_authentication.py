import unittest
from app import create_app, db
from test_methods import jsonify, auth, register


class AuthAPITestCase(unittest.TestCase):
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

    def test_POST_auth(self):
        """Test it returns 200 with correct username and password"""
        res = register(self, self.user_data)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 201)
        self.assertIn('New user created', str(res_in_json['message']))
        res2 = auth(self, self.user_auth_data)
        res_in_json2 = jsonify(res2.data)
        print(res_in_json2)
        self.assertEqual(res2.status_code, 200)
        self.assertIn(
                'You logged in successfully',
                str(res_in_json2['message']))
        self.assertIsNotNone(res_in_json2['access_token'])

    def test_POST_auth_missing_value(self):
        """Test it returns 500 for missing value"""
        res = auth(self, self.missing_value_user_auth_data)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 500)
        self.assertIn(
                'username',
                str(res_in_json['err']))

    def test_POST_auth_wrong_username(self):
        """Test it returns 401 for wrong username"""
        res = auth(self, self.wrong_username_user_auth_data)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 401)
        self.assertIn(
            'Invalid username or password',
            str(res_in_json['err']))

    def test_POST_auth_wrong_password(self):
        """Test it returns 401 for wrong password"""
        res = auth(self, self.wrong_username_user_auth_data)
        res_in_json = jsonify(res.data)
        self.assertEqual(res.status_code, 401)
        self.assertIn(
            'Invalid username or password',
            str(res_in_json['err']))