from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended.exceptions import JWTExtendedException
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import bcrypt
import os
import uuid
import time
import sys
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
import logging

# Cấu hình logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://user:password@db:3370/portfolio'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB max upload
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your_email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your_app_password')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'your_email@gmail.com')

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions but delay connecting to DB
db = SQLAlchemy()
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
jwt = JWTManager(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# JWT error handlers
@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'message': 'Invalid token',
        'error': str(error)
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'message': 'Token has expired',
        'error': 'token_expired'
    }), 401

@jwt.unauthorized_loader
def unauthorized_loader_callback(error):
    return jsonify({
        'message': 'Missing Authorization Header',
        'error': str(error)
    }), 401

@jwt.token_verification_failed_loader
def verification_failed_callback(jwt_header, jwt_payload):
    return jsonify({
        'message': 'Token verification failed',
        'error': 'token_verification_failed'
    }), 401

# Identity handling
@jwt.user_identity_loader
def user_identity_lookup(identity):
    # Always convert user ID to string for consistent handling
    return str(identity)

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    # Convert string ID back to integer for database lookup
    identity = jwt_data["sub"]
    try:
        user_id = int(identity)
        return User.query.filter_by(id=user_id).one_or_none()
    except:
        return None

# Define models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100))
    job_title = db.Column(db.String(100))
    bio = db.Column(db.Text)
    profile_image = db.Column(db.String(255))
    projects = db.relationship('Project', backref='user', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    demo_url = db.Column(db.String(255))
    repo_url = db.Column(db.String(255))
    description = db.Column(db.Text)
    image = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(hashed_pw, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_pw.encode('utf-8'))

def send_password_reset_email(user):
    token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=24)
    
    # Save token in database
    reset = PasswordReset(user_id=user.id, token=token, expires_at=expires_at)
    db.session.add(reset)
    db.session.commit()
    
    # Generate a reset link
    reset_link = f"http://localhost:9745/reset-password?token={token}"
    
    # Send email
    subject = "Password Reset Request"
    body = f"Click the link below to reset your password:\n\n{reset_link}\n\nThis link will expire in 24 hours."
    
    sender = app.config['MAIL_DEFAULT_SENDER']
    msg = Message(subject=subject, recipients=[user.email], body=body, sender=sender)
    try:
        mail.send(msg)
        logger.info(f"Password reset email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")

# Application-wide error handler
@app.errorhandler(422)
def handle_unprocessable_entity(err):
    # Log the error
    logger.error(f"Unprocessable Entity Error: {str(err)}")
    # Return a custom error response
    return jsonify({
        "error": "Invalid input data",
        "message": str(err.description)
    }), 422

# Routes
@app.route('/api/user/signup', methods=['POST'])
def signup():
    data = request.json
    logger.info(f"Received signup request: {data}")
    
    try:
        # Check if email already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            logger.warning(f"Signup failed: Email {data['email']} already registered")
            return jsonify({'error': 'Email already registered'}), 409
        
        # Create new user
        hashed_password = hash_password(data['password'])
        new_user = User(
            email=data['email'],
            password=hashed_password,
            name=data.get('name', ''),
            job_title=data.get('job_title', ''),
            bio=data.get('bio', '')
        )
        
        logger.info(f"Creating new user with email: {data['email']}")
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"User created successfully with ID: {new_user.id}")
        
        # Generate access token
        access_token = create_access_token(identity=new_user.id)
        
        return jsonify({
            'message': 'User created successfully',
            'token': access_token,
            'user': {
                'id': new_user.id,
                'email': new_user.email,
                'name': new_user.name
            }
        }), 201
    except Exception as e:
        logger.error(f"Error during signup: {str(e)}")
        db.session.rollback()
        return jsonify({'error': f'Signup failed: {str(e)}'}), 500

@app.route('/api/user/login', methods=['POST'])
def login():
    try:
        data = request.json
        
        user = User.query.filter_by(email=data['email']).first()
        if not user or not check_password(user.password, data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        # Generate access token
        access_token = create_access_token(identity=user.id)
        logger.info(f"Generated token for user {user.id}: {access_token}")
        
        return jsonify({
            'token': access_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name
            }
        }), 200
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    
    user = User.query.filter_by(email=data['email']).first()
    if not user:
        return jsonify({'message': 'If the email is registered, a reset link will be sent'}), 200
    
    send_password_reset_email(user)
    
    return jsonify({'message': 'If the email is registered, a reset link will be sent'}), 200

@app.route('/api/user/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    token = data['token']
    new_password = data['password']
    
    # Find the token in the database
    reset = PasswordReset.query.filter_by(token=token).first()
    if not reset or reset.expires_at < datetime.utcnow():
        return jsonify({'error': 'Invalid or expired token'}), 400
    
    # Update the user's password
    user = User.query.get(reset.user_id)
    user.password = hash_password(new_password)
    
    # Delete all reset tokens for this user
    PasswordReset.query.filter_by(user_id=user.id).delete()
    
    db.session.commit()
    
    return jsonify({'message': 'Password reset successfully'}), 200

@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_profile():
    try:
        # Use the current_user from JWT extension (set by user_lookup_loader)
        current_user = get_jwt_identity()
        logger.info(f"Get profile for user ID: {current_user}")
        
        # Get user from database
        user_id = int(current_user)
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'job_title': user.job_title,
            'bio': user.bio,
            'profile_image': user.profile_image
        }), 200
    except Exception as e:
        logger.error(f"Error getting profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    try:
        current_user_id = get_jwt_identity()
        logger.info(f"Update profile for user ID: {current_user_id}")
        
        user = User.query.get(int(current_user_id))
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if the request has form data (for file uploads)
        if request.content_type and 'multipart/form-data' in request.content_type:
            # Handle form data with file upload
            if 'name' in request.form:
                user.name = request.form.get('name')
            if 'job_title' in request.form:
                user.job_title = request.form.get('job_title')
            if 'bio' in request.form:
                user.bio = request.form.get('bio')
            
            # Handle profile image upload
            if 'profile_image' in request.files:
                file = request.files['profile_image']
                if file and file.filename:
                    # Secure the filename
                    filename = secure_filename(file.filename)
                    # Create a unique filename with timestamp
                    unique_filename = f"{int(time.time())}_{filename}"
                    # Save the file
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(file_path)
                    # Update user profile with image path
                    user.profile_image = unique_filename
                    logger.info(f"Saved profile image: {unique_filename}")
        else:
            # Handle regular JSON data
            data = request.json
            logger.info(f"Profile update data: {data}")
            
            # Update user fields safely
            if 'name' in data:
                user.name = data['name']
            if 'job_title' in data:
                user.job_title = data['job_title']
            if 'bio' in data:
                user.bio = data['bio']
            if 'profile_image' in data and data['profile_image']:
                user.profile_image = data['profile_image']
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'job_title': user.job_title,
            'bio': user.bio,
            'profile_image': user.profile_image
        }), 200
    except Exception as e:
        logger.error(f"Error updating profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/projects', methods=['GET'])
@jwt_required()
def get_projects():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    projects = []
    for project in user.projects:
        projects.append({
            'id': project.id,
            'name': project.name,
            'demo_url': project.demo_url,
            'repo_url': project.repo_url,
            'description': project.description,
            'image': project.image
        })
    
    return jsonify(projects), 200

@app.route('/api/user/projects', methods=['POST'])
@jwt_required()
def add_project():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(int(current_user_id))
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if the request has form data (for file uploads)
        if request.content_type and 'multipart/form-data' in request.content_type:
            # Handle form data with file upload
            name = request.form.get('name')
            demo_url = request.form.get('demo_url', '')
            repo_url = request.form.get('repo_url', '')
            description = request.form.get('description', '')
            
            # Process image if included
            image_filename = ''
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename:
                    # Secure the filename
                    filename = secure_filename(file.filename)
                    # Create a unique filename with timestamp
                    unique_filename = f"project_{int(time.time())}_{filename}"
                    # Save the file
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(file_path)
                    # Set image filename
                    image_filename = unique_filename
                    logger.info(f"Saved project image: {unique_filename}")
            
            new_project = Project(
                name=name,
                demo_url=demo_url,
                repo_url=repo_url,
                description=description,
                image=image_filename,
                user_id=int(current_user_id)
            )
        else:
            # Handle JSON data
            data = request.json
            
            new_project = Project(
                name=data['name'],
                demo_url=data.get('demo_url', ''),
                repo_url=data.get('repo_url', ''),
                description=data.get('description', ''),
                image=data.get('image', ''),
                user_id=int(current_user_id)
            )
        
        db.session.add(new_project)
        db.session.commit()
        
        return jsonify({
            'message': 'Project added successfully', 
            'id': new_project.id,
            'name': new_project.name,
            'demo_url': new_project.demo_url,
            'repo_url': new_project.repo_url,
            'description': new_project.description,
            'image': new_project.image
        }), 201
    except Exception as e:
        logger.error(f"Error adding project: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/projects/<int:project_id>', methods=['PUT'])
@jwt_required()
def update_project(project_id):
    try:
        current_user_id = get_jwt_identity()
        
        project = Project.query.filter_by(id=project_id, user_id=int(current_user_id)).first()
        if not project:
            return jsonify({'error': 'Project not found or unauthorized'}), 404
        
        # Check if the request has form data (for file uploads)
        if request.content_type and 'multipart/form-data' in request.content_type:
            # Handle form data with file upload
            if 'name' in request.form:
                project.name = request.form.get('name')
            if 'demo_url' in request.form:
                project.demo_url = request.form.get('demo_url', '')
            if 'repo_url' in request.form:
                project.repo_url = request.form.get('repo_url', '')
            if 'description' in request.form:
                project.description = request.form.get('description', '')
            
            # Process image if included
            if 'image' in request.files:
                file = request.files['image']
                if file and file.filename:
                    # Secure the filename
                    filename = secure_filename(file.filename)
                    # Create a unique filename with timestamp
                    unique_filename = f"project_{int(time.time())}_{filename}"
                    # Save the file
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(file_path)
                    # Update project with image path
                    project.image = unique_filename
                    logger.info(f"Saved project image: {unique_filename}")
        else:
            # Handle JSON data
            data = request.json
            
            project.name = data.get('name', project.name)
            project.demo_url = data.get('demo_url', project.demo_url)
            project.repo_url = data.get('repo_url', project.repo_url)
            project.description = data.get('description', project.description)
            project.image = data.get('image', project.image)
        
        db.session.commit()
        
        return jsonify({
            'message': 'Project updated successfully',
            'project': {
                'id': project.id,
                'name': project.name,
                'demo_url': project.demo_url,
                'repo_url': project.repo_url,
                'description': project.description,
                'image': project.image
            }
        }), 200
    except Exception as e:
        logger.error(f"Error updating project: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/projects/<int:project_id>', methods=['DELETE'])
@jwt_required()
def delete_project(project_id):
    current_user_id = get_jwt_identity()
    
    project = Project.query.filter_by(id=project_id, user_id=current_user_id).first()
    if not project:
        return jsonify({'error': 'Project not found or unauthorized'}), 404
    
    db.session.delete(project)
    db.session.commit()
    
    return jsonify({'message': 'Project deleted successfully'}), 200

@app.route('/api/portfolio/<int:user_id>', methods=['GET'])
def get_portfolio(user_id):
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    projects = []
    for project in user.projects:
        projects.append({
            'id': project.id,
            'name': project.name,
            'demo_url': project.demo_url,
            'repo_url': project.repo_url,
            'description': project.description,
            'image': project.image
        })
    
    return jsonify({
        'user': {
            'name': user.name,
            'job_title': user.job_title,
            'bio': user.bio,
            'profile_image': user.profile_image
        },
        'projects': projects
    }), 200

@app.route('/api/contact', methods=['POST'])
def contact():
    data = request.json
    
    user = User.query.get(data['user_id'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Send email
    subject = f"Contact from {data.get('name', 'Anonymous')}"
    body = f"From: {data.get('email', 'No email provided')}\n\n{data.get('message', 'No message')}"
    
    sender = app.config['MAIL_DEFAULT_SENDER']
    msg = Message(subject=subject, recipients=[user.email], body=body, sender=sender)
    try:
        mail.send(msg)
        logger.info(f"Contact message sent to {user.email}")
        return jsonify({'message': 'Message sent successfully'}), 200
    except Exception as e:
        logger.error(f"Failed to send contact email: {str(e)}")
        return jsonify({'error': f'Failed to send email: {str(e)}'}), 500

# Route to serve uploaded files
@app.route('/uploads/<path:filename>', methods=['GET'])
def uploaded_file(filename):
    """Serve uploaded files"""
    logger.info(f"Serving file: {filename}")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Alternative route with /api prefix for frontend compatibility
@app.route('/api/uploads/<path:filename>', methods=['GET'])
def api_uploaded_file(filename):
    """Serve uploaded files (with /api prefix)"""
    logger.info(f"Serving file via /api/uploads/: {filename}")
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Debug route to test token validation
@app.route('/api/debug/token', methods=['GET'])
def debug_token():
    auth_header = request.headers.get('Authorization', '')
    logger.info(f"Auth header received: {auth_header}")
    return jsonify({'message': 'Token debug info', 'header': auth_header}), 200

# Function to try connecting to the database with retries
def initialize_database(max_retries=30, retry_interval=10):
    """Kết nối tới MySQL và tạo tables với cơ chế thử lại nhiều lần"""
    logger.info("Bắt đầu khởi tạo cơ sở dữ liệu...")
    
    # Khởi tạo ứng dụng với DB
    db.init_app(app)
    
    retries = 0
    while retries < max_retries:
        try:
            logger.info(f"Lần thử {retries + 1}/{max_retries} kết nối tới MySQL...")
            
            # Thử kết nối và tạo tables
            with app.app_context():
                db.create_all()
            
            logger.info("✅ Kết nối thành công! Đã tạo xong các bảng.")
            return True
            
        except Exception as e:
            retries += 1
            logger.error(f"❌ Lỗi kết nối: {str(e)}")
            
            if retries >= max_retries:
                logger.error(f"⛔ Đã thử {max_retries} lần không thành công. Thoát.")
                return False
                
            logger.info(f"⏳ Đang chờ {retry_interval} giây trước khi thử lại...")
            time.sleep(retry_interval)
    
    return False

if __name__ == '__main__':
    # Khởi tạo cơ sở dữ liệu với cơ chế thử lại (30 lần, mỗi lần 10 giây)
    success = initialize_database(max_retries=30, retry_interval=10)
    
    if not success:
        logger.error("Không thể kết nối tới cơ sở dữ liệu sau nhiều lần thử. Ứng dụng sẽ thoát.")
        sys.exit(1)
    
    # Khởi động ứng dụng Flask
    logger.info("🚀 Khởi động Flask server...")
    app.run(host='0.0.0.0', port=7331, debug=True) 