from flask import Flask, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
import glob
import json

db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    db.init_app(app)

    global app_language
    app_language = 'en'

    global languages
    languages = {}

    language_list = glob.glob("api/language/*.json")
    for lang in language_list:
        filename = lang.split('\\')
        lang_code = filename[1].split('.')[0]

        with open(lang, 'r', encoding='utf8') as file:
            languages[lang_code] = json.loads(file.read())

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')

    from .models import User, Data
    
    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))
    
    @login_manager.unauthorized_handler
    def unauthorized():
        return redirect(url_for('auth.login', language=app_language))
    

    return app


def create_database(app):
    if not path.exists('api/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')