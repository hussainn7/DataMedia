from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, current_app, jsonify, abort
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.utils import secure_filename
import os
import uuid
from app import db
from app.models import File, Folder, User, Column
from config import Config
from datetime import datetime
import requests

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
main_bp = Blueprint('main', __name__)
user_bp = Blueprint('user', __name__, url_prefix='/user')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS

@admin_bp.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username, is_admin=True).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin.dashboard'))
            
        flash('Invalid username or password')
    
    return render_template('admin/login.html')

@admin_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('admin.login'))

@admin_bp.route('/admin/dashboard')
@login_required
def dashboard():
    try:
        # Get search parameters
        search_vin = request.args.get('search_vin', '').strip()
        filter_types = request.args.getlist('filter_type')
        has_title = request.args.get('has_title', 'no') == 'yes'  # Defaults to 'no'
        has_keys = request.args.get('has_keys', 'no') == 'yes'  # Defaults to 'no'
        
        # Start with base query
        query = File.query
        
        # Apply VIN search if provided
        if search_vin:
            query = query.filter(File.vin.ilike(f'%{search_vin}%'))
        
        # Apply type filters if selected
        if filter_types:
            query = query.filter(File.type.in_(filter_types))
        
        # Apply title/keys filters if selected
        if has_title:
            query = query.filter(File.has_title == True)
        if has_keys:
            query = query.filter(File.has_keys == True)
            
        # Order by most recent first
        query = query.order_by(File.created_date.desc())
        
        # Execute query
        files = query.all()
        
        print(f"Search params - VIN: {search_vin}, Types: {filter_types}, "
              f"Has Title: {has_title}, Has Keys: {has_keys}")
        print(f"Found {len(files)} matching records")
        
        return render_template('admin/dashboard.html', files=files)
        
    except Exception as e:
        print(f"Error in dashboard: {str(e)}")
        flash('Error loading dashboard')
        return render_template('admin/dashboard.html', files=[])


@admin_bp.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    try:
        print("\n=== Starting file upload process ===")
        
        # Log all form data
        print("Form data received:")
        print(f"VIN: {request.form.get('vin')}")
        print(f"Type: {request.form.get('type')}")
        print(f"Has Title: {request.form.get('has_title')}")
        print(f"Has Keys: {request.form.get('has_keys')}")
        print(f"Location: {request.form.get('location')}")
        print(f"Description: {request.form.get('description')}")
        
        # Log files received
        print("\nFiles received:")
        print(f"Files in request: {request.files}")
        print(f"File list: {request.files.getlist('file[]')}")
        
        # Get form data
        vin = request.form.get('vin')
        file_type = request.form.get('type')
        has_title = request.form.get('has_title') == 'yes'
        has_keys = request.form.get('has_keys') == 'yes'
        location = request.form.get('location', '')
        description = request.form.get('description', '')
        
        if not vin:
            print("Error: No VIN provided")
            flash('VIN is required')
            return redirect(url_for('admin.dashboard'))
        
        # Decode VIN
        print(f"\nDecoding VIN: {vin}")
        carfax_info = decode_vin(vin)
        print(f"Decoded VIN info: {carfax_info}")
        
        # Create upload directory
        upload_folder = os.path.join(current_app.root_path, 'static', 'uploads', vin)
        print(f"\nCreating upload folder: {upload_folder}")
        os.makedirs(upload_folder, exist_ok=True)
        
        # Check for existing entry
        vin_entry = File.query.filter_by(vin=vin).first()
        print(f"\nExisting VIN entry found: {vin_entry is not None}")
        
        if not vin_entry:
            print("Creating new VIN entry")
            vin_entry = File(
                vin=vin,
                type=file_type,
                has_title=has_title,
                has_keys=has_keys,
                location=location,
                description=description,
                user_id=current_user.id,
                filename=f"VIN_{vin}",
                created_date=datetime.utcnow(),
                carfax=carfax_info
            )
            db.session.add(vin_entry)
        else:
            print("Updating existing VIN entry")
            vin_entry.type = file_type
            vin_entry.has_title = has_title
            vin_entry.has_keys = has_keys
            vin_entry.location = location
            vin_entry.description = description
            vin_entry.carfax = carfax_info
        
        # Process files
        files = request.files.getlist('file[]')
        if not files or not files[0].filename:
            print("Error: No files selected")
            flash('No files selected')
            return redirect(url_for('admin.dashboard'))
        
        saved_files = []
        for file in files:
            if file.filename:
                secure_name = secure_filename(file.filename)
                file_path = os.path.join(upload_folder, secure_name)
                print(f"\nSaving file: {file.filename}")
                print(f"To path: {file_path}")
                file.save(file_path)
                saved_files.append(secure_name)
                print(f"File saved successfully: {secure_name}")
        
        if saved_files:
            vin_entry.filename = saved_files[0]
            print(f"Updated entry filename to: {saved_files[0]}")
        
        print("\nCommitting to database...")
        db.session.commit()
        print("Database commit successful")
        print(f"Final entry - Type: {vin_entry.type}, Carfax: {vin_entry.carfax}")
        
        flash('Files uploaded successfully')
        return redirect(url_for('admin.dashboard'))
        
    except Exception as e:
        print(f"\nERROR during upload: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        db.session.rollback()
        flash(f'Error during upload: {str(e)}')
        return redirect(url_for('admin.dashboard'))

def get_file_size(vin, filename):
    filepath = os.path.join(current_app.root_path, 'static', 'uploads', vin, filename)
    size_bytes = os.path.getsize(filepath)
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes/1024:.1f} KB"
    else:
        return f"{size_bytes/(1024*1024):.1f} MB"

def get_file_modified_time(vin, filename):
    filepath = os.path.join(current_app.root_path, 'static', 'uploads', vin, filename)
    mtime = os.path.getmtime(filepath)
    return datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')

@admin_bp.route('/vin_folder/<vin>')
@login_required
def vin_folder(vin):
    folder_path = os.path.join(current_app.root_path, 'static', 'uploads', vin)
    if not os.path.exists(folder_path):
        flash('Folder not found')
        return redirect(url_for('admin.dashboard'))
    
    files = sorted(os.listdir(folder_path))
    return render_template('admin/vin_folder.html', 
                         vin=vin, 
                         files=files,
                         get_file_size=get_file_size,
                         get_file_modified_time=get_file_modified_time)

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


@admin_bp.route('/save-vin-info', methods=['POST'])
@login_required
def save_vin_info():
    try:
        vin = request.form.get('vin')
        carfax = request.form.get('carfax')
        
        print(f"Received save request - VIN: {vin}, Carfax: {carfax}")
        
        file = File.query.filter_by(vin=vin).first()
        print(f"Found file record: {file}")
        
        if file:
            file.carfax = carfax
            db.session.commit()
            print(f"Updated carfax for VIN {vin} to: {carfax}")
            return jsonify({'success': True})
        else:
            print(f"No file found for VIN: {vin}")
            return jsonify({'success': False, 'error': 'No file found for VIN'})
            
    except Exception as e:
        print(f"Error in save_vin_info: {str(e)}")
        return jsonify({'success': False, 'error': str(e)})


@admin_bp.route('/get-car-info', methods=['POST'])
@login_required
def get_car_info():
    try:
        print("Received request for VIN lookup")

        # Check if request JSON is received
        if not request.is_json:
            print("Error: Request does not contain JSON data")
            return jsonify({'error': 'Invalid request format'}), 400

        data = request.get_json()
        print(f"Received JSON Data: {data}")

        vin = data.get('vin')
        if not vin:
            print("Error: VIN is missing in request")
            return jsonify({'error': 'VIN is required'}), 400

        file = File.query.filter_by(vin=vin).first()
        print(f"Database Lookup Result: {file}")

        if file:
            carfax_info = file.carfax if file.carfax else "No Carfax Data"
            print(f"Returning car model: {carfax_info}")
            return jsonify({'model': carfax_info}), 200
        else:
            print("No record found for this VIN")
            return jsonify({'error': 'No record found for this VIN'}), 404

    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return jsonify({'error': str(e)}), 500





@main_bp.route('/file/<folder>/<filename>')
def get_file(folder, filename):
    return send_from_directory(os.path.join(Config.UPLOAD_FOLDER, folder), filename)

@main_bp.route('/')
def index():
    return redirect(url_for('admin.admin_login'))

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

@admin_bp.route('/rename_file/<vin>', methods=['POST'])
@login_required
def rename_file(vin):
    try:
        print(f"Attempting to rename file for VIN: {vin}")
        data = request.get_json()
        print(f"Received data: {data}")
        
        old_name = data.get('old_name')
        new_name = secure_filename(data.get('new_name'))
        
        print(f"Old name: {old_name}")
        print(f"New name: {new_name}")
        
        if not old_name or not new_name:
            print("Missing filename data")
            return jsonify({'error': 'Missing filename'}), 400
            
        folder_path = os.path.join(current_app.root_path, 'static', 'uploads', vin)
        old_path = os.path.join(folder_path, old_name)
        new_path = os.path.join(folder_path, new_name)
        
        print(f"Old path: {old_path}")
        print(f"New path: {new_path}")
        
        if not os.path.exists(old_path):
            print(f"File not found: {old_path}")
            return jsonify({'error': 'File not found'}), 404
            
        if os.path.exists(new_path):
            print(f"New filename already exists: {new_path}")
            return jsonify({'error': 'New filename already exists'}), 400
            
        os.rename(old_path, new_path)
        print(f"Successfully renamed file from {old_name} to {new_name}")
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error during rename: {str(e)}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/delete_vin_file/<vin>', methods=['POST'])
@login_required
def delete_vin_file(vin):
    data = request.get_json()
    filename = data.get('filename')
    file_path = os.path.join(current_app.root_path, 'static', 'uploads', vin, filename)
    
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            flash('File deleted successfully', 'success')
        else:
            flash('File not found', 'error')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}', 'error')
    
    return jsonify(success=True)

@main_bp.route('/public/view/<vin>/<filename>')
def public_view(vin, filename):
    """Public route for viewing files without authentication"""
    try:
        # Sanitize the input
        vin = secure_filename(vin)
        filename = secure_filename(filename)
        
        # Construct the file path
        upload_folder = os.path.join(current_app.root_path, 'static', 'uploads', vin)
        
        # Check if file exists
        if not os.path.exists(os.path.join(upload_folder, filename)):
            abort(404)
            
        # Return the file
        return send_from_directory(upload_folder, filename)
        
    except Exception as e:
        print(f"Error serving public file: {str(e)}")
        abort(404)

# Update the template URL generation
def generate_public_url(vin, filename):
    """Generate a public URL for a file"""
    return url_for('public_view', vin=vin, filename=filename, _external=True)

@main_bp.route('/public/folder/<vin>')
def public_folder_view(vin):
    """Public route for viewing all files in a VIN folder"""
    try:
        # Sanitize the input
        vin = secure_filename(vin)
        
        # Construct the folder path
        upload_folder = os.path.join(current_app.root_path, 'static', 'uploads', vin)
        
        # Debug print
        print(f"Checking folder: {upload_folder}")
        
        # Check if folder exists
        if not os.path.exists(upload_folder):
            print(f"Folder not found: {upload_folder}")
            abort(404)
            
        # Get all files in the folder
        files = []
        try:
            files = [f for f in os.listdir(upload_folder) 
                    if os.path.isfile(os.path.join(upload_folder, f))]
            print(f"Found files: {files}")
        except Exception as e:
            print(f"Error listing files: {str(e)}")
            files = []

        # Helper functions
        def get_file_size(vin, filename):
            try:
                file_path = os.path.join(current_app.root_path, 'static', 'uploads', vin, filename)
                size_bytes = os.path.getsize(file_path)
                if size_bytes < 1024:
                    return f"{size_bytes} B"
                elif size_bytes < 1024 * 1024:
                    return f"{size_bytes/1024:.1f} KB"
                else:
                    return f"{size_bytes/(1024*1024):.1f} MB"
            except Exception as e:
                print(f"Error getting file size: {str(e)}")
                return "N/A"

        def get_file_modified_time(vin, filename):
            try:
                file_path = os.path.join(current_app.root_path, 'static', 'uploads', vin, filename)
                mtime = os.path.getmtime(file_path)
                return datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M')
            except Exception as e:
                print(f"Error getting modified time: {str(e)}")
                return "N/A"
        
        # Render template with helper functions
        return render_template('public/folder_view.html', 
                             vin=vin, 
                             files=files,
                             get_file_size=get_file_size,
                             get_file_modified_time=get_file_modified_time)
        
    except Exception as e:
        print(f"Error in public_folder_view: {str(e)}")
        return f"Error: {str(e)}", 500  # Return error message instead of abort 

def decode_vin(vin):
    try:
        url = f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinExtended/{vin}?format=json"
        response = requests.get(url)
        data = response.json()
        
        make = None
        model = None
        year = None
        
        for result in data.get('Results', []):
            if result.get('Variable') == 'Make':
                make = result.get('Value')
            elif result.get('Variable') == 'Model':
                model = result.get('Value')
            elif result.get('Variable') == 'Model Year':
                year = result.get('Value')
        
        if make and model and year:
            return f"{year} {make} {model}"
        return None
    except Exception as e:
        print(f"Error decoding VIN {vin}: {str(e)}")
        return None

@admin_bp.route('/update-all-carfax')
@login_required
def update_all_carfax():
    try:
        # Get all files with VINs but no carfax info
        files = File.query.filter(
            File.vin.isnot(None),
            (File.carfax.is_(None) | File.carfax == '')
        ).all()
        
        updated_count = 0
        for file in files:
            print(f"Processing VIN: {file.vin}")
            carfax_info = decode_vin(file.vin)
            if carfax_info:
                file.carfax = carfax_info
                updated_count += 1
                print(f"Updated carfax for VIN {file.vin} to: {carfax_info}")
        
        db.session.commit()
        flash(f'Successfully updated {updated_count} carfax entries')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating carfax entries: {str(e)}")
        flash(f'Error updating carfax entries: {str(e)}')
    
    return redirect(url_for('admin.dashboard')) 