from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
import os
import time
from datetime import timedelta
import uuid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import pymysql
from functools import wraps

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='frontend/build', static_url_path='')
# Allow CORS for all routes
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
bcrypt = Bcrypt(app)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:password@db/portfolio'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Change JWT_SECRET_KEY to invalidate all existing tokens
app.config['JWT_SECRET_KEY'] = 'new-super-secret-key-change-in-production-20250608'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

jwt = JWTManager(app)

# Custom JWT error handlers
@jwt.invalid_token_loader
def invalid_token_callback(error):
    logger.error(f"Invalid token: {error}")
    return jsonify({
        'message': 'Invalid token',
        'error': str(error)
    }), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    logger.error(f"Expired token: {jwt_payload}")
    return jsonify({
        'message': 'Token has expired',
        'error': 'token_expired'
    }), 401

@jwt.unauthorized_loader
def unauthorized_callback(error):
    logger.error(f"Unauthorized: {error}")
    return jsonify({
        'message': 'Missing Authorization Header',
        'error': str(error)
    }), 401

# JWT identity loader to ensure identity is always a string
@jwt.user_identity_loader
def user_identity_loader(user):
    # Always convert to string
    user_id_str = str(user)
    logger.debug(f"Converting user identity to string: {user} -> {user_id_str}")
    return user_id_str

# Custom wrapper for jwt_required
def jwt_required_with_logging():
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                verify_jwt_in_request()
                identity = get_jwt_identity()
                logger.debug(f"JWT verification successful. Identity: {identity} (type: {type(identity)})")
                return fn(*args, **kwargs)
            except Exception as e:
                logger.error(f"JWT verification failed: {str(e)}")
                return jsonify({
                    'message': 'Authentication failed',
                    'error': str(e)
                }), 401
        return wrapper
    return decorator

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    job_title = db.Column(db.String(100))
    bio = db.Column(db.Text)
    profile_image = db.Column(db.Text)  # Changed from String(255) to Text for larger image data
    reset_token = db.Column(db.String(100))
    projects = db.relationship('Project', backref='user', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    demo_url = db.Column(db.String(255))
    repo_url = db.Column(db.String(255))
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Helper function to send emails
def send_email(to_email, subject, body):
    # This is a placeholder function
    # In a real application, you would use an email service like SendGrid
    print(f"Sending email to {to_email}")
    print(f"Subject: {subject}")
    print(f"Body: {body}")
    return True

# API Routes
@app.route('/api/user/signup', methods=['POST'])
def signup():
    try:
        data = request.json
        logger.debug(f"Signup attempt received: {data}")
        
        if not data or 'email' not in data or 'password' not in data:
            logger.error("Missing required fields in signup data")
            return jsonify({'error': 'Email and password are required'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            logger.debug(f"Email already exists: {data['email']}")
            return jsonify({'error': 'Email already exists'}), 400
        
        # Ensure data is properly encoded if it contains Unicode characters
        name = data.get('name', '')
        email = data['email']
        password = data['password']
        job_title = data.get('job_title', '')
        bio = data.get('bio', '')
        profile_image = data.get('profile_image', '')
        
        logger.debug(f"Processing signup for email: {email}, name: {name}")
        
        try:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            new_user = User(
                email=email,
                password=hashed_password,
                name=name,
                job_title=job_title,
                bio=bio,
                profile_image=profile_image
            )
            
            db.session.add(new_user)
            db.session.commit()
            logger.debug(f"User created successfully: {new_user.id}")
            
            return jsonify({'message': 'User created successfully', 'id': new_user.id}), 201
        except Exception as inner_err:
            db.session.rollback()
            logger.error(f"Database error during signup: {str(inner_err)}")
            return jsonify({'error': f'Database error: {str(inner_err)}'}), 500
    except Exception as e:
        logger.error(f"Error in signup: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/login', methods=['POST'])
def login():
    try:
        data = request.json
        logger.debug(f"Login attempt for email: {data['email']}")
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not bcrypt.check_password_hash(user.password, data['password']):
            logger.debug("Invalid credentials")
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Use the integer user.id - our identity loader will convert to string
        access_token = create_access_token(identity=user.id)
        logger.debug(f"Token created successfully for user {user.id}")
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'job_title': user.job_title,
                'bio': user.bio,
                'profile_image': user.profile_image
            }
        }), 200
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.json
        user = User.query.filter_by(email=data['email']).first()
        
        if not user:
            logger.debug(f"Forgot password: Email not found {data['email']}")
            return jsonify({'message': 'If your email exists in our system, you will receive a reset link'}), 200
        
        reset_token = str(uuid.uuid4())
        user.reset_token = reset_token
        db.session.commit()
        
        reset_link = f"http://localhost:9745/reset-password/{reset_token}"
        send_email(
            user.email,
            "Password Reset Request",
            f"Click the following link to reset your password: {reset_link}"
        )
        logger.debug(f"Reset token generated for user {user.id}")
        
        return jsonify({'message': 'If your email exists in our system, you will receive a reset link'}), 200
    except Exception as e:
        logger.error(f"Error in forgot_password: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.json
        user = User.query.filter_by(reset_token=data['token']).first()
        
        if not user:
            logger.debug(f"Invalid reset token: {data['token']}")
            return jsonify({'error': 'Invalid or expired token'}), 400
        
        hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        user.password = hashed_password
        user.reset_token = None
        db.session.commit()
        logger.debug(f"Password reset successful for user {user.id}")
        
        return jsonify({'message': 'Password reset successful'}), 200
    except Exception as e:
        logger.error(f"Error in reset_password: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['GET'])
@jwt_required_with_logging()
def get_profile():
    try:
        # The identity will be a string - convert to int for DB lookup
        user_id = int(get_jwt_identity())
        logger.debug(f"Get profile for user_id: {user_id}")
        
        user = User.query.get(user_id)
        
        if not user:
            logger.debug(f"User not found with ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'job_title': user.job_title,
            'bio': user.bio,
            'profile_image': user.profile_image
        }), 200
    except Exception as e:
        logger.error(f"Error in get_profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/profile', methods=['PUT'])
@jwt_required_with_logging()
def update_profile():
    try:
        # The identity will be a string - convert to int for DB lookup
        user_id = int(get_jwt_identity())
        logger.debug(f"Update profile for user_id: {user_id}")
        
        user = User.query.get(user_id)
        
        if not user:
            logger.debug(f"User not found with ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        
        data = request.json
        logger.debug(f"Profile update data: {data}")
        
        user.name = data.get('name', user.name)
        user.job_title = data.get('job_title', user.job_title)
        user.bio = data.get('bio', user.bio)
        user.profile_image = data.get('profile_image', user.profile_image)
        
        db.session.commit()
        logger.debug("Profile updated successfully")
        
        return jsonify({'message': 'Profile updated successfully'}), 200
    except Exception as e:
        logger.error(f"Error in update_profile: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/projects', methods=['GET'])
@jwt_required_with_logging()
def get_projects():
    try:
        # The identity will be a string - convert to int for DB lookup
        user_id = int(get_jwt_identity())
        logger.debug(f"Get projects for user_id: {user_id}")
        
        user = User.query.get(user_id)
        
        if not user:
            logger.debug(f"User not found with ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        
        projects = Project.query.filter_by(user_id=user_id).all()
        projects_data = [{
            'id': project.id,
            'name': project.name,
            'demo_url': project.demo_url,
            'repo_url': project.repo_url,
            'description': project.description
        } for project in projects]
        
        logger.debug(f"Retrieved {len(projects_data)} projects")
        return jsonify(projects_data), 200
    except Exception as e:
        logger.error(f"Error in get_projects: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/projects', methods=['POST'])
@jwt_required_with_logging()
def add_project():
    try:
        # The identity will be a string - convert to int for DB lookup
        user_id = int(get_jwt_identity())
        logger.debug(f"Add project for user_id: {user_id}")
        
        user = User.query.get(user_id)
        
        if not user:
            logger.debug(f"User not found with ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        
        data = request.json
        logger.debug(f"New project data: {data}")
        
        new_project = Project(
            name=data['name'],
            demo_url=data.get('demo_url', ''),
            repo_url=data.get('repo_url', ''),
            description=data.get('description', ''),
            user_id=user_id
        )
        
        db.session.add(new_project)
        db.session.commit()
        logger.debug(f"Project added successfully with ID: {new_project.id}")
        
        return jsonify({'message': 'Project added successfully', 'id': new_project.id}), 201
    except Exception as e:
        logger.error(f"Error in add_project: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/projects/<int:project_id>', methods=['PUT'])
@jwt_required_with_logging()
def update_project(project_id):
    try:
        # The identity will be a string - convert to int for DB lookup
        user_id = int(get_jwt_identity())
        logger.debug(f"Update project {project_id} for user_id: {user_id}")
        
        project = Project.query.get(project_id)
        
        if not project:
            logger.debug(f"Project not found with ID: {project_id}")
            return jsonify({'error': 'Project not found'}), 404
        
        if project.user_id != user_id:
            logger.debug(f"Unauthorized: Project user_id {project.user_id} doesn't match authenticated user {user_id}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        data = request.json
        logger.debug(f"Project update data: {data}")
        
        project.name = data.get('name', project.name)
        project.demo_url = data.get('demo_url', project.demo_url)
        project.repo_url = data.get('repo_url', project.repo_url)
        project.description = data.get('description', project.description)
        
        db.session.commit()
        logger.debug("Project updated successfully")
        
        return jsonify({'message': 'Project updated successfully'}), 200
    except Exception as e:
        logger.error(f"Error in update_project: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/user/projects/<int:project_id>', methods=['DELETE'])
@jwt_required_with_logging()
def delete_project(project_id):
    try:
        # The identity will be a string - convert to int for DB lookup
        user_id = int(get_jwt_identity())
        logger.debug(f"Delete project {project_id} for user_id: {user_id}")
        
        project = Project.query.get(project_id)
        
        if not project:
            logger.debug(f"Project not found with ID: {project_id}")
            return jsonify({'error': 'Project not found'}), 404
        
        if project.user_id != user_id:
            logger.debug(f"Unauthorized: Project user_id {project.user_id} doesn't match authenticated user {user_id}")
            return jsonify({'error': 'Unauthorized'}), 403
        
        db.session.delete(project)
        db.session.commit()
        logger.debug("Project deleted successfully")
        
        return jsonify({'message': 'Project deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Error in delete_project: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/portfolio/<int:user_id>', methods=['GET'])
def get_portfolio(user_id):
    try:
        logger.debug(f"Get portfolio for user_id: {user_id}")
        
        user = User.query.get(user_id)
        
        if not user:
            logger.debug(f"User not found with ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        
        projects = Project.query.filter_by(user_id=user_id).all()
        projects_data = [{
            'id': project.id,
            'name': project.name,
            'demo_url': project.demo_url,
            'repo_url': project.repo_url,
            'description': project.description
        } for project in projects]
        
        logger.debug(f"Retrieved portfolio with {len(projects_data)} projects")
        return jsonify({
            'user': {
                'id': user.id,
                'name': user.name,
                'job_title': user.job_title,
                'bio': user.bio,
                'profile_image': user.profile_image
            },
            'projects': projects_data
        }), 200
    except Exception as e:
        logger.error(f"Error in get_portfolio: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/contact', methods=['POST'])
def contact():
    try:
        data = request.json
        logger.debug(f"Contact form submission from {data['from_email']} to {data['to_email']}")
        
        to_email = data['to_email']
        from_email = data['from_email']
        message = data['message']
        
        # Send email to the portfolio owner
        send_email(
            to_email,
            f"Contact from {from_email}",
            message
        )
        logger.debug("Message sent successfully")
        
        return jsonify({'message': 'Message sent successfully'}), 200
    except Exception as e:
        logger.error(f"Error in contact: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Route to check JWT token validity
@app.route('/api/auth/verify', methods=['GET'])
@jwt_required_with_logging()
def verify_token():
    try:
        # Identity will already be a string (through our identity_loader)
        user_id = get_jwt_identity()
        logger.debug(f"Token verification successful for user: {user_id}")
        return jsonify({
            'valid': True, 
            'user_id': user_id,
            'message': 'Token is valid'
        }), 200
    except Exception as e:
        logger.error(f"Token verification failed: {str(e)}")
        return jsonify({'valid': False, 'error': str(e)}), 401

# Serve React frontend
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

# Function to wait for database to be ready
def wait_for_db(retries=30, delay=2):
    logger.info("Waiting for database connection...")
    for i in range(retries):
        try:
            conn = pymysql.connect(
                host='db',
                user='root',
                password='password',
                database='portfolio'
            )
            conn.close()
            logger.info("Database connection successful!")
            return True
        except pymysql.OperationalError as e:
            logger.warning(f"Database connection attempt {i+1}/{retries} failed: {e}")
            if i < retries - 1:
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)
    
    logger.error(f"Could not connect to database after {retries} attempts")
    return False

if __name__ == '__main__':
    # Wait for the database to be ready before starting the app
    wait_for_db()
    
    with app.app_context():
        try:
            # Create tables if they don't exist
            db.create_all()
            logger.info("Database tables created successfully!")
        except Exception as e:
            logger.error(f"Error creating database tables: {e}")
    
    app.run(host='0.0.0.0', port=9745, debug=True)
