"""
DSscan Configuration Module
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

# Base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Config:
    """Base configuration"""
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database - use absolute path
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 
        f'sqlite:///{os.path.join(BASE_DIR, "instance", "dsscan.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session (default 30 days - value in days)
    PERMANENT_SESSION_LIFETIME = timedelta(days=int(os.environ.get('PERMANENT_SESSION_LIFETIME', 30)))
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Upload - use absolute path (MAX_CONTENT_LENGTH in MB)
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 10)) * 1024 * 1024  # Convert MB to bytes
    _upload_folder = os.environ.get('UPLOAD_FOLDER', 'uploads')
    # Convert relative path to absolute
    UPLOAD_FOLDER = _upload_folder if os.path.isabs(_upload_folder) else os.path.join(BASE_DIR, _upload_folder)
    ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'tif', 'heic', 'heif'}
    
    # Model
    MODEL_PATH = os.path.join(BASE_DIR, 'models', 'InceptionResNetV2.keras')
    MODEL_DOWNLOAD_URL = os.environ.get('MODEL_DOWNLOAD_URL', '')
    MODEL_INPUT_SIZE = (224, 224)
    
    # Admin
    ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'informatika')
    
    # CORS
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')
    
    # CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in os.environ.get('CSRF_TRUSTED_ORIGINS', '').split(',') if origin.strip()]
    
    # Logging - always use logs/dsscan.log
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'DEBUG')
    LOG_FILE = os.path.join(BASE_DIR, 'logs', 'dsscan.log')


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    FLASK_ENV = 'development'


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    FLASK_ENV = 'production'
    SESSION_COOKIE_SECURE = True
    LOG_LEVEL = 'INFO'


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
