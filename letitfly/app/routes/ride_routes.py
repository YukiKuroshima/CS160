from flask_api import status
from flask import render_template, request, redirect, session, make_response

from app.models.users_model import User
from app.models.drives_model import Rides
from app.methods.authentication_methods import parse_access_token


def request_ride():
            # access_token = parse_access_token(request)
            # Access token found
            if 'email' in session:
                # user_id = User.decode_token(request.cookies.get(''))
                # user_id = User.decode_token(access_token)
                # Token is valid
                print('Logged in as: ' + session['email'])
                if request.method == 'POST':
                    try:
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
                                'message': 'Ride requested successfully',
                                'ride_id': temp_ride.get_self_ride_id()
                                }
                        status_code = status.HTTP_201_CREATED
                        return render_template('maps.html', requestedFlag=True)
                    except KeyError as e:
                        response = {
                                'err': 'Missing value',
                                'info': 'Error: %s' % e
                                }
                        status_code = status.HTTP_400_BAD_REQUEST
                    except Exception as e:
                        print(e)
                        response = {
                                'err': 'Something went wrong',
                                'info': 'Error: %s' % e
                                }
                        status_code = status.HTTP_400_BAD_REQUEST
                    finally:
                        print(response)
                        return response, status_code
                else:
                    return render_template('maps.html', requestingFlag=True)
            # Token is invalid
            # Access token NOT found
            response = {'err': 'Bad token. Please re-login'}
            print(response)
            return render_template('login.html')


def get_ride_history():
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
                return response, status_code



def search_for_ride():
        access_token = parse_access_token(request)
        # Access token found
        if(access_token):
            user_id = User.decode_token(access_token)
            # Token is valid
            if not isinstance(user_id, str):
                try:
                    # Decode access token and get user_id that
                    # belongs to the user who requested the ride
                    user = User.find_user_by_user_id(user_id)
                    # Check if the user is driver or not
                    if user.is_driver():
                        # If driver, resume
                        rides_json = Rides.find_all_not_picked_up_rides_in_json()
                        response = {
                                'message': 'Ride query return successfully',
                                'rides': rides_json
                                }
                        status_code = status.HTTP_200_OK
                    else:
                        # If customer, reject
                        response = {
                                'err': 'You are not driver. Only driver can see the requests'
                                }
                        status_code = status.HTTP_400_BAD_REQUEST
                except KeyError as e:
                    response = {
                            'err': 'Missing value',
                            'info': 'Error: %s' % e
                            }
                    status_code = status.HTTP_400_BAD_REQUEST
                except Exception as e:
                    response = {
                            'err': 'Something went wrong',
                            'info': 'Error: %s' % e
                            }
                    status_code = status.HTTP_400_BAD_REQUEST
                finally:
                    return response, status_code

            # Token is invalid
            else:
                response = {'err': user_id}
                status_code = status.HTTP_400_BAD_REQUEST
                return response, status_code
        # Access token NOT found
        else:
            response = {'err': 'No access token found'}
            status_code = status.HTTP_400_BAD_REQUEST
            return response, status_code
