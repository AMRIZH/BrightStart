"""
DSscan - Flask Application Factory
Medical Computer Vision Application for Down Syndrome Detection
Created by Informatika UMS - 2026
"""
import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask

from .config import config
from .extensions import db, login_manager, csrf, cors


def create_app(config_name=None):
    """Application factory function"""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config[config_name])
    
    # Get database path from config and ensure directory exists
    from .config import BASE_DIR
    instance_dir = os.path.join(BASE_DIR, 'instance')
    
    # Ensure instance and upload folders exist
    try:
        os.makedirs(instance_dir, exist_ok=True)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(os.path.dirname(app.config['LOG_FILE']), exist_ok=True)
    except OSError as e:
        print(f"Error creating directories: {e}")
    
    # Initialize extensions
    init_extensions(app)
    
    # Configure logging
    configure_logging(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Setup Flask-Admin
    setup_admin(app)
    
    # Create database tables and default admin
    with app.app_context():
        db.create_all()
        create_default_admin(app)
    
    # Preload ML model at startup
    preload_model(app)
    
    app.logger.info('DSscan application started successfully')
    
    return app


def init_extensions(app):
    """Initialize Flask extensions"""
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Configure CORS
    cors_origins = app.config['CORS_ORIGINS']
    if cors_origins == '*':
        cors.init_app(app, resources={r"/*": {"origins": "*"}})
    else:
        origins = [origin.strip() for origin in cors_origins.split(',')]
        cors.init_app(app, resources={r"/*": {"origins": origins}})
    
    # User loader for Flask-Login
    from .models.user import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))


def configure_logging(app):
    """Configure application logging"""
    log_level = getattr(logging, app.config['LOG_LEVEL'].upper(), logging.DEBUG)
    log_file = app.config['LOG_FILE']
    
    # Create file handler
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    ))
    
    # Create console handler with colored output hints
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    ))
    
    # Add handlers to app logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(log_level)
    
    # Also configure werkzeug logger to show requests
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.addHandler(file_handler)
    werkzeug_logger.addHandler(console_handler)
    werkzeug_logger.setLevel(logging.INFO)
    
    # Add request logging
    @app.before_request
    def log_request_info():
        from flask import request
        if not request.path.startswith('/static'):
            app.logger.debug(f">>> {request.method} {request.path}")
    
    @app.after_request
    def log_response_info(response):
        from flask import request
        if not request.path.startswith('/static'):
            status_mark = "[OK]" if response.status_code < 400 else "[ERR]"
            app.logger.debug(f"<<< {request.method} {request.path} {status_mark} {response.status_code}")
        return response


def register_blueprints(app):
    """Register Flask blueprints"""
    from .views.main import main_bp
    from .views.auth import auth_bp
    from .views.dashboard import dashboard_bp
    from .views.records import records_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(records_bp)


def setup_admin(app):
    """Setup Flask-Admin"""
    from flask_admin import Admin
    from flask_admin.theme import Bootstrap4Theme
    from .admin.views import (
        DSscanAdminIndexView,
        UserModelView,
        PredictionModelView
    )
    from .models.user import User
    from .models.prediction import Prediction
    
    admin = Admin(
        app,
        name='DSscan Admin',
        theme=Bootstrap4Theme(swatch='default'),
        index_view=DSscanAdminIndexView(name='Beranda', url='/admin')
    )
    
    admin.add_view(UserModelView(User, db.session, name='Pengguna', endpoint='admin_users'))
    admin.add_view(PredictionModelView(Prediction, db.session, name='Prediksi', endpoint='admin_predictions'))
    
    # Exempt Flask-Admin blueprint from CSRF (Flask-Admin handles CSRF internally)
    csrf.exempt(admin.index_view.blueprint)


def create_default_admin(app):
    """Create default admin user if no admin exists"""
    from .models.user import User
    
    admin_exists = User.query.filter_by(is_admin=True).first()
    if not admin_exists:
        admin_user = User(
            username=app.config['ADMIN_USERNAME'],
            is_admin=True
        )
        admin_user.set_password(app.config['ADMIN_PASSWORD'])
        db.session.add(admin_user)
        db.session.commit()
        app.logger.info(f"Default admin user '{app.config['ADMIN_USERNAME']}' created")


def preload_model(app):
    """Preload ML model at application startup"""
    from .services.inference import InferenceService
    
    print("\n" + "="*60)
    print("🤖 LOADING ML MODEL")
    print("="*60)
    
    model_path = app.config.get('MODEL_PATH')
    download_url = app.config.get('MODEL_DOWNLOAD_URL')
    
    print(f"  📁 Model path: {model_path}")
    
    # Check if model file exists
    import os
    if os.path.exists(model_path):
        model_size = os.path.getsize(model_path) / (1024 * 1024)
        print(f"  ✅ Model file found ({model_size:.1f} MB)")
    else:
        print(f"  ⚠️  Model file not found")
        if download_url:
            print(f"  📥 Download URL configured: {download_url[:50]}...")
        else:
            print(f"  ❌ No download URL configured!")
            print("="*60 + "\n")
            return
    
    # Load the model
    print(f"  ⏳ Loading model into memory...")
    
    try:
        model = InferenceService.initialize_model(model_path, download_url)
        
        if model is not None:
            print(f"  ✅ Model loaded successfully!")
            print(f"  📊 Input shape: {model.input_shape}")
            print(f"  📊 Output shape: {model.output_shape}")
        else:
            print(f"  ❌ Failed to load model")
    except Exception as e:
        print(f"  ❌ Error loading model: {str(e)}")
    
    print("="*60 + "\n")
