from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
from website import app_language, languages

auth = Blueprint('auth', __name__)


@auth.route('/login/<language>', methods=['GET', 'POST'])
def login(language):
    if(language not in languages):
        language = app_language
    if request.method == 'POST':
        submitType = request.form['submit_button']
        if submitType == 'login':
            email = request.form.get('email')
            password = request.form.get('password')
            user = User.query.filter_by(email=email).first()
            if user:
                if check_password_hash(user.password, password):
                    flash('Logged in successfully!', category='success')
                    login_user(user, remember=True)
                    return redirect(url_for('views.home', language=language))
                else:
                    flash('Incorrect password, try again.', category='error')
            else:
                flash('Email does not exist.', category='error')
        elif submitType == 'signup':
            email = request.form.get('signupEmail')
            first_name = " "
            password1 = request.form.get('signupPass1')
            password2 = request.form.get('signupPass2')

            user = User.query.filter_by(email=email).first()
            if user:
                flash('Email already exists.', category='error')
            elif len(email) < 4:
                flash('Email must be greater than 3 characters.', category='error')
            elif password1 != password2:
                flash('Passwords don\'t match.', category='error')
            elif len(password1) < 7:
                flash('Password must be at least 7 characters.', category='error')
            else:
                new_user = User(email=email, first_name=first_name, password=generate_password_hash(
                    password1, method='sha256'))
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('views.home', language=language))
    return render_template("cryptorithm.html", user=current_user, language=language, **languages[language])



@auth.route('/logout/<language>', methods=['GET'])
@login_required
def logout(language):
    logout_user()
    if(language not in languages):
        language = app_language
    return redirect(url_for('auth.login', language=language))