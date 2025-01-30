from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, current_app, jsonify
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename
import os
import uuid
from app import db
from app.models import File, Folder, User
from config import Config

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
main_bp = Blueprint('main', __name__)
user_bp = Blueprint('user', __name__, url_prefix='/user')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.is_admin and user.password == request.form['password']:
            login_user(user)
            return redirect(url_for('admin.dashboard'))
        flash('Invalid credentials')
    return render_template('admin/login.html')

@admin_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('admin.login'))

@admin_bp.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for('main.login'))
    files = File.query.all()
    folders = Folder.query.all()
    users = User.query.filter_by(is_admin=False).all()  # Get non-admin users
    total_files = len(files)
    total_size = sum(f.file_size for f in files)
    return render_template('admin/dashboard.html', 
                         files=files, 
                         folders=folders,
                         users=users,
                         total_files=total_files,
                         total_size=total_size)

@admin_bp.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if not current_user.is_admin:
        return redirect(url_for('admin.dashboard'))
        
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('admin.dashboard'))
    
    file = request.files['file']
    folder = request.form.get('folder', 'default')
    
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('admin.dashboard'))
    
    if file and allowed_file(file.filename):
        target_user = None
        if folder.startswith('user_'):
            username = folder[5:] 
            target_user = User.query.filter_by(username=username).first()
        
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        folder_path = os.path.join(Config.UPLOAD_FOLDER, folder)
        
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            
        file_path = os.path.join(folder_path, unique_filename)
        file.save(file_path)
        
        new_file = File(
            filename=unique_filename,
            original_filename=filename,
            folder=folder,
            file_type=file.content_type,
            file_size=os.path.getsize(file_path),
            public_url=url_for('main.get_file', folder=folder, filename=unique_filename, _external=True),
            user_id=target_user.id if target_user else current_user.id  
        )
        
        db.session.add(new_file)
        db.session.commit()
        
        flash('File uploaded successfully')
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
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.password == request.form['password']:  
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('user.dashboard'))
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
    user_files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('user/dashboard.html', files=user_files)

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
        folder_name = f"user_{current_user.username}"
        folder_path = os.path.join(Config.UPLOAD_FOLDER, folder_name)
        
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
            
        file_path = os.path.join(folder_path, unique_filename)
        file.save(file_path)
        
        new_file = File(
            filename=unique_filename,
            original_filename=filename,
            folder=folder_name,
            file_type=file.content_type,
            file_size=os.path.getsize(file_path),
            public_url=url_for('main.get_file', folder=folder_name, filename=unique_filename, _external=True),
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