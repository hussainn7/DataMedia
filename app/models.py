from datetime import datetime
from app import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='owner', lazy=True)

    def __init__(self, username, password, is_admin=False):
        self.username = username
        self.set_password(password)
        self.is_admin = is_admin
        self.created_date = datetime.utcnow()

    def set_password(self, password):
        self.password = password

    def check_password(self, password):
        return self.password == password

class File(db.Model):
    __tablename__ = 'files'  # Explicitly name the table
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255))
    type = db.Column(db.String(50))
    has_title = db.Column(db.Boolean, default=False)
    has_keys = db.Column(db.Boolean, default=False)
    location = db.Column(db.String(255))
    vin = db.Column(db.String(50))
    description = db.Column(db.Text)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)
    public_url = db.Column(db.String(255))
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    created_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __init__(self, name):
        self.name = name
        self.created_date = datetime.utcnow()

class Column(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # text, number, date, etc.
    required = db.Column(db.Boolean, default=False)
    created_date = db.Column(db.DateTime, default=datetime.utcnow) 