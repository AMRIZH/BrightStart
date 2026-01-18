"""
DSscan - Application Entry Point
"""
import os
import sys

def print_banner():
    """Print startup banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║   ██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗        ║
    ║   ██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║        ║
    ║   ██║  ██║███████╗███████╗██║     ███████║██╔██╗ ██║        ║
    ║   ██║  ██║╚════██║╚════██║██║     ██╔══██║██║╚██╗██║        ║
    ║   ██████╔╝███████║███████║╚██████╗██║  ██║██║ ╚████║        ║
    ║   ╚═════╝ ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝        ║
    ║                       DSscan                                 ║
    ║          Down Syndrome Detection System                      ║
    ╠══════════════════════════════════════════════════════════════╣
    ║   FKI Universitas Muhammadiyah Surakarta                     ║
    ║   Program Studi Informatika - 2026                           ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_config_info(app):
    """Print configuration information"""
    print("\n" + "="*60)
    print("📋 KONFIGURASI APLIKASI")
    print("="*60)
    print(f"  🔧 Environment    : {os.environ.get('FLASK_ENV', 'development')}")
    print(f"  🐛 Debug Mode     : {app.debug}")
    print(f"  🔐 CSRF Enabled   : {app.config.get('WTF_CSRF_ENABLED', True)}")
    print(f"  🌐 CORS Origins   : {app.config.get('CORS_ORIGINS', '*')}")
    print(f"  📁 Upload Folder  : {app.config.get('UPLOAD_FOLDER')}")
    print(f"  📊 Max Upload     : {app.config.get('MAX_CONTENT_LENGTH', 0) / (1024*1024):.0f} MB")
    print(f"  🗄️  Database       : SQLite")
    print(f"  📝 Log Level      : {app.config.get('LOG_LEVEL', 'DEBUG')}")
    print("="*60)
    
    # Check model
    model_path = app.config.get('MODEL_PATH', '')
    if os.path.exists(model_path):
        model_size = os.path.getsize(model_path) / (1024 * 1024)
        print(f"  🤖 Model Status   : ✅ Loaded ({model_size:.1f} MB)")
    else:
        print(f"  🤖 Model Status   : ⚠️  Not found (will download on first use)")
    print("="*60 + "\n")

# Only run startup code in main process (not in Flask reloader child process)
if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
    print_banner()

from app import create_app

# Create application instance
if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
    print("🚀 Initializing DSscan application...")

app = create_app(os.environ.get('FLASK_ENV', 'development'))

if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
    print("✅ Application initialized successfully!")
    print_config_info(app)

if __name__ == '__main__':
    # Get configuration from environment
    debug = os.environ.get('FLASK_DEBUG', '1') == '1'
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        print(f"🌍 Starting server on http://{host}:{port}")
        print(f"   Local:   http://127.0.0.1:{port}")
        print(f"   Network: http://0.0.0.0:{port}")
        print("\n📌 Press CTRL+C to quit\n")
    
    app.run(host=host, port=port, debug=debug)

