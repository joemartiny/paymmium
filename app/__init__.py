from flask import Flask
from flask_bootstrap import Bootstrap
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from config import DevelopmentConfig
from flask_seasurf import SeaSurf


db = SQLAlchemy()
bootstrap = Bootstrap()
login_manager = LoginManager()
mail = Mail()
csrf = SQLAlchemy()
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(DevelopmentConfig)
    db.init_app(app)
    bootstrap.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.session_protection = 'strong'

    from app.auth.app import app as app_blueprint
    app.register_blueprint(app_blueprint, url_prefix='/app')
    from app.auth.web import web as web_blueprint
    app.register_blueprint(web_blueprint)

    from app.main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
