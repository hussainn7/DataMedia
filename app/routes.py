from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, current_app, jsonify
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename
import os
import uuid
from app import db
from app.models import File, Folder, User, Column
from config import Config
from datetime import datetime

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
main_bp = Blueprint('main', __name__)
user_bp = Blueprint('user', __name__, url_prefix='/user')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_admin:
            login_user(user)
            flash('Logged in successfully as admin.')
            return redirect(url_for('admin.dashboard'))
        else:
            flash('Invalid admin credentials')
    
    return render_template('admin/login.html')

@admin_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('admin.login'))

@admin_bp.route('/admin/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for('main.dashboard'))

    # Get search parameters
    search_vin = request.args.get('search_vin', '')
    filter_type = request.args.getlist('filter_type')
    has_title = request.args.get('has_title')
    has_keys = request.args.get('has_keys')

    # Start with base query
    query = File.query

    # Apply filters
    if search_vin:
        query = query.filter(File.vin.ilike(f'%{search_vin}%'))
    
    
    if filter_type:
        query = query.filter(File.type.in_(filter_type))
    
    if request.args and not has_title:
        query = query.filter(File.has_title == False)
    elif has_title == 'yes':
        query = query.filter(File.has_title == True)
    
    if request.args and not has_keys:
        query = query.filter(File.has_keys == False)
    elif has_keys == 'yes':
        query = query.filter(File.has_keys == True)

    # Get files and sort
    files = query.order_by(File.created_date.desc()).all()
    
    return render_template('admin/dashboard.html', files=files)

@admin_bp.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if not current_user.is_admin:
        return redirect(url_for('main.dashboard'))

    file = request.files.get('file')
    if not file:
        flash('No file uploaded')
        return redirect(url_for('admin.dashboard'))

    if file and allowed_file(file.filename):
        # Get form data - changed vehicle_type to match the form name 'type'
        file_type = request.form.get('type')  # Changed from vehicle_type
        has_title = request.form.get('has_title') == 'yes'
        has_keys = request.form.get('has_keys') == 'yes'
        location = request.form.get('location', '')
        vin = request.form.get('vin', '')
        description = request.form.get('description', '')

        # Save file
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        folder_name = f"uploads_{datetime.now().strftime('%Y%m')}"
        folder_path = os.path.join(current_app.config['UPLOAD_FOLDER'], folder_name)
        
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            
        file_path = os.path.join(folder_path, unique_filename)
        file.save(file_path)
        
        new_file = File(
            filename=unique_filename,
            original_filename=filename,
            type=file_type,  # Using the correct form field name
            has_title=has_title,
            has_keys=has_keys,
            location=location,
            vin=vin,
            description=description,
            file_type='document',
            file_size=os.path.getsize(file_path),
            public_url=url_for('main.get_file', folder=folder_name, filename=unique_filename, _external=True),
            user_id=current_user.id
        )
        
        db.session.add(new_file)
        db.session.commit()
        
        flash('File uploaded successfully')
        return redirect(url_for('admin.dashboard'))
    
    flash('Invalid file type')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/folder/create', methods=['POST'])
@login_required
def create_folder():
    folder_name = request.form.get('folder_name')
    if folder_name:
        folder = Folder(name=folder_name)
        db.session.add(folder)
        db.session.commit()
        os.makedirs(os.path.join(Config.UPLOAD_FOLDER, folder_name), exist_ok=True)
    return redirect(url_for('admin.dashboard'))

@main_bp.route('/file/<folder>/<filename>')
def get_file(folder, filename):
    return send_from_directory(os.path.join(Config.UPLOAD_FOLDER, folder), filename)

@main_bp.route('/')
def index():
    return render_template('index.html')

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('user.dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@main_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('main.register'))
            
        user = User(username=username, password=password)  
        
        # Create user's folder
        folder_name = f"user_{username}"
        folder = Folder(name=folder_name)
        db.session.add(folder)
        
        db.session.add(user)
        db.session.commit()
        
        os.makedirs(os.path.join(Config.UPLOAD_FOLDER, folder_name), exist_ok=True)
        flash('Registration successful')
        return redirect(url_for('main.login'))
        
    return render_template('register.html')

@user_bp.route('/dashboard')
@login_required
def dashboard():
    # Get search parameters
    search_vin = request.args.get('search_vin', '')
    filter_type = request.args.getlist('filter_type')
    has_title = request.args.get('has_title')
    has_keys = request.args.get('has_keys')

    # Start with base query
    query = File.query

    # Apply filters
    if search_vin:
        query = query.filter(File.vin.ilike(f'%{search_vin}%'))
    
    if filter_type:
        query = query.filter(File.type.in_(filter_type))
    
    # If filter is applied but checkbox not checked, show only items without title/keys
    if request.args and not has_title:
        query = query.filter(File.has_title == False)
    elif has_title == 'yes':
        query = query.filter(File.has_title == True)
    
    if request.args and not has_keys:
        query = query.filter(File.has_keys == False)
    elif has_keys == 'yes':
        query = query.filter(File.has_keys == True)

    # Get files and sort
    user_files = query.filter_by(user_id=current_user.id).all()
    admin_files = query.join(User).filter(User.is_admin == True).all()
    
    files = user_files + admin_files
    files.sort(key=lambda x: x.created_date if x.created_date else datetime.min, reverse=True)
    
    return render_template('user/dashboard.html', files=files)

@user_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('user.dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('user.dashboard'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        
        folder_path = os.path.join(Config.UPLOAD_FOLDER, str(current_user.id))
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            
        file_path = os.path.join(folder_path, unique_filename)
        file.save(file_path)
        
        # Get form data - updated to match admin form field names
        file_type = request.form.get('type')  # Changed from type to match admin
        has_title = request.form.get('has_title') == 'yes'
        has_keys = request.form.get('has_keys') == 'yes'
        location = request.form.get('location', '')
        vin = request.form.get('vin', '')
        description = request.form.get('description', '')  # Added description
        
        new_file = File(
            filename=unique_filename,
            original_filename=filename,
            type=file_type,
            has_title=has_title,
            has_keys=has_keys,
            location=location,
            vin=vin,
            description=description,  # Added description
            file_type=file.content_type,
            file_size=os.path.getsize(file_path),
            public_url=url_for('main.get_file', folder=str(current_user.id), filename=unique_filename, _external=True),
            user_id=current_user.id
        )
        
        db.session.add(new_file)
        db.session.commit()
        
        flash('File uploaded successfully')
    return redirect(url_for('user.dashboard'))

@admin_bp.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    file = File.query.get_or_404(file_id)
    file_path = os.path.join(Config.UPLOAD_FOLDER, file.folder, file.filename)
    
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(file)
        db.session.commit()
        return jsonify({'message': 'File deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/users')
@login_required
def list_users():
    if not current_user.is_admin:
        return redirect(url_for('admin.dashboard'))
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@main_bp.route('/create-admin')
def create_admin():
    if User.query.filter_by(username='admin').first():
        return 'Admin already exists'
    
    admin = User(
        username='admin',
        password=Config.ADMIN_PASSWORD,  
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()
    return 'Admin created successfully'

@main_bp.route('/reset-db')
def reset_db():
    # Drop all tables
    with current_app.app_context():
        db.drop_all()
        db.create_all()
        
        # Create admin user
        admin = User(
            username=Config.ADMIN_USERNAME,
            password=Config.ADMIN_PASSWORD,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
        
    return 'Database has been reset successfully!'

@admin_bp.route('/columns', methods=['GET', 'POST'])
@login_required
def manage_columns():
    if not current_user.is_admin:
        return redirect(url_for('admin.dashboard'))
        
    if request.method == 'POST':
        name = request.form.get('name')
        column_type = request.form.get('type')
        required = request.form.get('required') == 'on'
        
        new_column = Column(
            name=name,
            type=column_type,
            required=required
        )
        db.session.add(new_column)
        db.session.commit()
        flash('Column added successfully')
        
    columns = Column.query.all()
    return render_template('admin/columns.html', columns=columns)

@main_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@admin_bp.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('You have been logged out from admin panel.')
    return redirect(url_for('main.index')) 