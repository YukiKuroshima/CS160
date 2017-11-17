from flask import Flask
from app import app
from datetime import datetime, timedelta
from methods import user_methods
from app.models.database import db
from app import db
from flask import current_app


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = request.form
    if request.method == 'POST' and form.validate():
        user = User(request.form['first_name'],
                    request.form['last_name'],
                    request.form['email'],
                    request.form['password'],
                    request.form['credit_card'],
                    request.form['driver'],
                    datetime.now(),
                    datetime.now())
        user_methods