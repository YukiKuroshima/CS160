from flask_api import FlaskAPI, status
from flask_sqlalchemy import SQLAlchemy
from flask import Blueprint, render_template, abort, request, make_response, jsonify, redirect, session, url_for # Blueprints
import datetime

from app.models.database import db
from app.models.users_model import User
from app.models.drives_model import Rides
from app.methods.user_methods import *
from app.methods.ride_methods import *
from instance.config import app_config


def create_app(config_name):
    # creates flask application
    app = FlaskAPI(
            __name__,
            instance_relative_config=True,
            static_url_path='/assets',
            static_folder='../html/light-bootstrap-dashboard-master/assets',
            template_folder='../html/light-bootstrap-dashboard-master',
            )

    # register blueprint here

    # set configurations
    app.config.from_object(app_config[config_name])
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

    # initialize database with application
    db.init_app(app)

    # POST /authenticate
    """
    Sample
    POST /authenticate
    Host: localhost:5000
    Content-Type: application/json
    {
        "username": "joe",
        "password": "pass"
    }
    """
    @app.route('/auth', methods=['POST', 'GET'])
    def authenticate():
        session.clear()
        if request.method == 'POST':
            try:
                # Get the user object using their email (unique to every user)

                user = User.query.filter_by(
                        email=request.form.get('email')
                        ).first()

                # Try to authenticate the found user using their password
                if user and validate_password(user, request.form.get('password')):
                    # Generate the access token.
                    # This will be used as the authorization header
                    access_token = generate_token(user.user_id)
                    if access_token:
                        # redirect_to_index = redirect('/request')
                        # response = make_response(redirect_to_index)
                        # response.set_cookie('access_token', value=access_token.decode())
                        # return response
                        session['email'] = request.form.get('email')
                        return redirect('request')

                else:
                    # User does not exist. Therefore, we return an error message
                    response = {
                            'err': 'Invalid username or password, Please try again'
                            }

                    return render_template('login.html', responsecode=401, response="Invalid username or password, Please try again")

            except Exception as e:
                # Create a response containing an string error message
                response = {'err': str(e)}
                # Return a server error using the HTTP Error
                # Code 500 (Internal Server Error)
                return make_response(jsonify(response)), 500
        else:
            return render_template('login.html')

    # POST /register
    """
    Sample json data
    {
        "first_name": "a",
        "last_name": "a12",
        "credit_card": 1234,
        "email": "1.@.1c22o1m1",
        "driver": false,
        "username": "na21211me",
        "password": "a"
    }
    """
    @app.route('/register', methods=['POST', 'GET'])
    def register():

        session.clear()
        
        if request.method == 'POST':
            first_name = request.form.get('firstname')
            last_name = request.form.get('lastname')
            credit_card = request.form.get('creditcard')
            email = request.form.get('email')
            driver = True if request.form.get('driver') else False
            username = request.form.get('username')
            password = request.form.get('password')

            if len(first_name) > 50 or len(last_name) > 50 or len(username) > 20 or len(password) > 22:
                response = {'err': 'First and last name cannot exceed 50 characters in length.'
                'Username cannot exceed 20 characters. Password cannot exceed 22 characters.'}
                return render_template('register.html', content=response)

            if '@' not in email:
                response = {'err': 'Invalid email'}
                return render_template('register.html', content=response)

            if len(credit_card) > 16 or len(credit_card) < 15 or not str(credit_card).isdigit():
                response = {'err': 'Invalid credit card number'}
                return render_template('register.html', content=response)

            try:

                temp_user = User(
                        first_name=first_name,
                        last_name=last_name,
                        credit_card=credit_card,
                        email=email,
                        driver=driver,
                        username=username,
                        password=password,
                        date_created=str(datetime.datetime.now()),
                        date_modified=str(datetime.datetime.now())
                        )

                temp_user.save()
                # access_token = temp_user.generate_token(temp_user.user_id)

                session['email'] = request.form.get('email')
                return redirect('request')
            except Exception as e:
                response = {'err': 'All fields must be filled out and email must be unique. %s' % e}
                return response, status.HTTP_400_BAD_REQUEST
                # return render_template('login.html', content=content)
            '''
            except exc.OperationalError as e:
                # SQLalchemy missing value
                content = {'err': 'Missing value', 'info': 'Error: %s' % e}
                return render_template('register.html', content=content)
            except exc.IntegrityError as e:
                # SQLalchemy insertion error (such as duplicate value)
                content = {'err': 'Duplicate value', 'info': 'Error: %s' % e}
                return render_template('register.html', content=content)
                '''
        else:
            content = {'err': 'All fields must be filled out and email must be unique.'}
            return render_template('register.html', content=content)


    @app.route("/logout", methods=['POST', 'GET'])
    def logout():
        #log out of user session
        session.clear()
        return redirect('auth')

    @app.route("/request", methods=['POST', 'GET'])
    def request_ride():
        # access_token = parse_access_token(request)
        # Access token found
        
        if 'email' in session:
            # user_id = User.decode_token(request.cookies.get(''))
            # user_id = User.decode_token(access_token)
            # Token is valid
            if request.method == 'POST':
                # Decode access token and get user_id that
                # belongs to the user who requested the ride
                ride_data = request.data
                user = User.query.filter_by(
                        email=session['email']
                        ).first()
                temp_ride = Rides(
                        customer=user,
                        # driver is null at this moment
                        start_location=ride_data['start_location'],
                        end_location=ride_data['end_location'],
                        )
                temp_ride.save()
                response = {
                        'message': 'Ride request created'
                        }
                return response, status.HTTP_201_CREATED
            else:
                return render_template('maps.html', requestingFlag=True)
        else:
            return render_template('register.html', requestingFlag=True)

    @app.route("/waiting", methods=['GET'])
    def waiting():
        # Access token found
        if 'email' in session:
            # Token is valid
            # Find client
            user = User.query.filter_by(
                    email=session['email']
                    ).first()
            # Find the ride assosiated with the client
            ride = Rides.query.filter_by(
                    customer_id=user.user_id,
                    time_finished=None
                    ).first()

            # If the ride.driver is null and
            # not picked up
            # not finished
            if ride.driver_id is None and \
               ride.picked_up is False and \
               ride.time_finished is None:
                # Render html with message Looking for driver to pick you up
                # Refresh the page periodically
                return render_template(
                        'waitmap.html',
                        requestedFlag=True,
                        start=ride.start_location,
                        end=ride.end_location,
                        )
            # Else if the ride.driver is NOT null
            # Not yet picked up
            # Not yet finished
            elif ride.driver_id is not None and \
                 ride.picked_up is False:
                # ride.time_finished is None:
                # Render html with driver found
                # Show where the driver is
                # Refresh the page periodically
                # TODO If driver_id is NOT null and picked_up = True
                # Show rider is picked up
                # TODO if driver id is NOT null and picked up = True and finished_date is NOT null
                # Show the rider amount they paid
                return render_template(
                        'waitmap.html',
                        driverFoundFlag=True,
                        start=ride.start_location,
                        driverpos={'lat': ride.current_lat, 'lng': ride.current_lng},
                        end=ride.end_location,
                        )

        # Token is invalid
        # Access token NOT found
        else:
            return render_template('maps.html', requestingFlag=True)

    """
    GET /search
    Find all the imcompleted ride requests
    Only driver can access this API
    Return JSON: List of imcompleted ride requests
    """
    @app.route("/search", methods=['GET', 'POST'])
    def seach_ride():
        # Access token found
        if 'email' in session:
            # If POST: Called when driver chooses a ride
            if request.method == 'POST':

                # request should contain driver's current location
                # and ride_id
                # Find the ride data by ride_id
                ride = Rides.query.filter_by(
                        ride_id=request.data['id']
                        ).first()
                # Assign the driver to the ride
                user = User.query.filter_by(
                        email=session['email']
                        ).first()
                ride.driver_id = user.user_id
                ride.current_lat = str(request.data['lat'])
                ride.current_lng = str(request.data['lng'])
                ride.save()

                # Save the ride id to session
                session['ride_id'] = ride.ride_id

                # Redirect to pick up page (Shows the route to the user)
                # MUST use js to refirect
                response = {'info': 'Ride appcepted'}
                return response, status.HTTP_200_OK

            # If GET
            else:
                # Render maps.html with all none picked up riders
                # Get user data
                user = User.query.filter_by(
                        email=session['email']
                        ).first()
                # User must be a driver
                if user.is_driver():
                    # If driver
                    # get all none picked up user data
                    rides = Rides.find_all_no_driver_assigned_rides_in_json()
                    # render html with ride_id and user locations
                    return render_template(
                            'drivermap.html',
                            searchFlag=True,
                            rides=rides
                            )
                else:
                    return redirect('request')

        else:
            response = {'err': 'No access token found'}
            status_code = status.HTTP_400_BAD_REQUEST
            return response, status_code

    @app.route("/pickup", methods=['GET', 'POST'])
    def pickup():
        # Access token found
        if 'email' in session:
            # If POST: Called when driver chooses a ride
            if request.method == 'POST':
                # Picked up
                # Driver can pick up a rider only if
                # Distance between driver and rider is less than 1 mile
                # Distance check is already done by javascript in frontend
                # When the program goes here, distance between drivre and rider is less than 1 mile
                # Change the status to picked_up = True
                # Show the route to the destination
                # Redirect to drive
                # Redirect must be done by JS here
                ride = Rides.query.filter_by(
                        ride_id=session['ride_id']
                        ).first()
                ride.picked_up = True
                ride.save()
                response = {'info': 'Rider picked up'}
                return response, status.HTTP_200_OK

            else:
                # Show the route to the user
                # Show picked up button
                # Get ride data and send user location by user id and pick_up = false
                ride = Rides.query.filter_by(
                        ride_id=session['ride_id']
                        ).first()

                return render_template(
                        'drivermap.html',
                        pickupFlag=True,
                        ride=ride.tojson()
                        )

        else:
            response = {'err': 'No access token found'}
            status_code = status.HTTP_400_BAD_REQUEST
            return response, status_code

    @app.route("/drive", methods=['GET', 'POST'])
    def drive():
        # Access token found
        if 'email' in session:
            # If POST: Called when driver chooses a ride
            # driver can see the the route to the destination from current location
            # Set the finished date so rider can also see the amount they paid
            if request.method == 'POST':
                # Driver dropping off the client
                # Set the finish time
                # Render to payment
                # rendering must be done by the js
                ride = Rides.query.filter_by(
                        ride_id=session['ride_id']
                        ).first()
                ride.set_current_to_time_finished()
                response = {'info': 'Dropped off a rider'}
                return response, status.HTTP_200_OK

            else:
                # Driver can see the route to the destination
                # [When I have time] Update the driver location periodically
                ride = Rides.query.filter_by(
                        ride_id=session['ride_id']
                        ).first()

                return render_template(
                        'drivermap.html',
                        driveFlag=True,
                        ride=ride.tojson()
                        )

        else:
            response = {'err': 'No access token found'}
            status_code = status.HTTP_400_BAD_REQUEST
            return response, status_code


            '''def get_ride_history():
    access_token = parse_access_token(request)
    if(access_token):
        user_id = User.decode_token(access_token)
        if not isinstance(user_id, str):
            try:
                rides = Rides.query.filter_by(customer_id=user_id).all()
                rides_json = [ride.tojson() for ride in rides]
                response = {
                        'message': 'Ride history returned successfully',
                        'rides': rides_json
                }
                status_code = status.HTTP_200_OK
            except Exception as e:
                response = {
                        'err': 'Something went wrong',
                        'info': 'Error %s' % e
                }
                status_code = status.HTTP_400_BAD_REQUEST
            finally:
                return response, status_code'''

    @app.route("/history", methods=['GET'])
    def history():
        if 'email' in session:
            rides = Rides.query.filter_by(customer_id=session['user_id']).all()
            return render_template('table.html', content=rides)
        else:
            redirect('auth')

    @app.route("/payment", methods=['GET'])
    def payment():
        # Access token found
        if 'email' in session:
            # Driver can see the money they earned
            # Driver can click a button to go /search
            # to find another ride and start ride again
            ride = Rides.query.filter_by(
                    ride_id=session['ride_id']
                    ).first()
            return render_template(
                    'drivermap.html',
                    ride=ride.tojson(),
                    paymentFlag=True,
                    )

        else:
            response = {'err': 'No access token found'}
            status_code = status.HTTP_400_BAD_REQUEST
            return response, status_code

    return app
