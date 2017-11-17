from sqlalchemy import exc
from flask import render_template, request, redirect, session, make_response, jsonify

from app.models.users_model import User
from app.methods.authentication_methods import *


def authenticate():
        if request.method == 'POST':
            try:
                # Get the user object using their email (unique to every user)

                user = User.query.filter_by(
                        email=request.form.get('email')
                        ).first()

                # Try to authenticate the found user using their password
                if user and validate_password(user, request.form.get('password')):
                    print('PW correct')
                    # Generate the access token.
                    # This will be used as the authorization header
                    access_token = generate_token(user, user.user_id)
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
                    return make_response(jsonify(response)), 401

            except Exception as e:
                # Create a response containing an string error message
                response = {'err': str(e)}
                # Return a server error using the HTTP Error
                # Code 500 (Internal Server Error)
                return make_response(jsonify(response)), 500
        else:
            return render_template('login.html')


def register():
        if request.method == 'POST':
            try:
                temp_user = User(
                        first_name=request.form.get('firstname'),
                        last_name=request.form.get('lastname'),
                        credit_card=request.form.get('creditcard'),
                        email=request.form.get('email'),
                        driver=True if request.form.get('driver') else False,
                        username=request.form.get('username'),
                        password=request.form.get('password'),
                        date_created='S',
                        date_modified='S',
                        )
                temp_user.save()
                # access_token = temp_user.generate_token(temp_user.user_id)

                session['email'] = request.form.get('email')
                return redirect('request')
            except exc.OperationalError as e:
                # SQLalchemy missing value
                content = {'err': 'Missing value', 'info': 'Error: %s' % e}
                print(content)
                return render_template('register.html', content=content)
            except exc.IntegrityError as e:
                # SQLalchemy insertion error (such as duplicate value)
                content = {'err': 'Duplicate value', 'info': 'Error: %s' % e}
                print(content)
                return render_template('register.html', content=content)
        else:
            return render_template('register.html')
