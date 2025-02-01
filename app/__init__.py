from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from config import Config
import os

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Create uploads folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    from app.models import User, File

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.routes import admin_bp, main_bp, user_bp
    app.register_blueprint(admin_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(user_bp)

    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username=app.config['ADMIN_USERNAME']).first()
        if not admin:
            admin = User(
                username=app.config['ADMIN_USERNAME'],
                password=app.config['ADMIN_PASSWORD'],
                is_admin=True
            )
            db.session.add(admin)
            try:
                db.session.commit()
                print(f"Admin user created successfully with username: {app.config['ADMIN_USERNAME']}")
            except Exception as e:
                db.session.rollback()
                print(f"Error creating admin user: {e}")
        else:
            print(f"Admin user already exists with username: {admin.username}")

    return app 