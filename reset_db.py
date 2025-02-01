from app import create_app, db
from app.models import User

app = create_app()

with app.app_context():
    # Drop all tables
    db.drop_all()
    
    # Create all tables
    db.create_all()
    
    # Create admin user
    admin = User(username='admin', password='a', is_admin=True)
    db.session.add(admin)
    db.session.commit()
    
    print("Database has been reset and admin user created!") 