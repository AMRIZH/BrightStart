"""
Flask-Admin Custom Views
"""
from flask import redirect, url_for, flash, request
from flask_login import current_user
from flask_admin import AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from wtforms import PasswordField, ValidationError
from wtforms.validators import DataRequired, Length, EqualTo, Optional
from werkzeug.security import generate_password_hash

from ..models.prediction import Prediction
from ..models.user import User
from ..extensions import db


class AdminAccessMixin:
    """Mixin to restrict access to admin users only"""
    
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self, name, **kwargs):
        if current_user.is_authenticated:
            flash('Anda tidak memiliki akses ke halaman ini.', 'danger')
            return redirect(url_for('dashboard.index'))
        return redirect(url_for('auth.login', next=request.url))


class DSscanAdminIndexView(AdminAccessMixin, AdminIndexView):
    """Custom Admin Index View with Statistics"""
    
    @expose('/')
    def index(self):
        # Get statistics
        total_users = User.query.count()
        total_predictions = Prediction.query.count()
        
        # Class distribution
        normal_count = Prediction.query.filter_by(result_class='Normal').count()
        ds_count = Prediction.query.filter_by(result_class='Down Syndrome').count()
        
        # Recent predictions
        recent_predictions = Prediction.query\
            .order_by(Prediction.created_at.desc())\
            .limit(10)\
            .all()
        
        # Average confidence
        avg_confidence_result = db.session.query(
            db.func.avg(Prediction.confidence)
        ).scalar()
        avg_confidence = float(avg_confidence_result) if avg_confidence_result else 0
        
        # Top users by prediction count
        top_users = db.session.query(
            User.username,
            db.func.count(Prediction.id).label('count')
        ).join(Prediction).group_by(User.id).order_by(
            db.func.count(Prediction.id).desc()
        ).limit(5).all()
        
        # Get current settings from config
        from flask import current_app
        settings = {
            'CORS_ORIGINS': current_app.config.get('CORS_ORIGINS', '*'),
            'MAX_CONTENT_LENGTH': f"{current_app.config.get('MAX_CONTENT_LENGTH', 0) / (1024 * 1024):.0f} MB",
            'LOG_LEVEL': current_app.config.get('LOG_LEVEL', 'DEBUG'),
            'UPLOAD_FOLDER': current_app.config.get('UPLOAD_FOLDER', 'uploads'),
            'MODEL_PATH': current_app.config.get('MODEL_PATH', 'N/A'),
        }
        
        return self.render(
            'admin/index.html',
            total_users=total_users,
            total_predictions=total_predictions,
            normal_count=normal_count,
            ds_count=ds_count,
            recent_predictions=recent_predictions,
            avg_confidence=avg_confidence,
            top_users=top_users,
            settings=settings
        )


class UserModelView(AdminAccessMixin, ModelView):
    """User management view"""
    
    # List view
    column_list = ['id', 'username', 'is_admin', 'created_at', 'last_login']
    column_searchable_list = ['username']
    column_filters = ['is_admin', 'created_at']
    column_sortable_list = ['id', 'username', 'is_admin', 'created_at', 'last_login']
    column_default_sort = ('created_at', True)
    
    # Labels in Indonesian
    column_labels = {
        'id': 'ID',
        'username': 'Username',
        'is_admin': 'Admin',
        'created_at': 'Dibuat',
        'last_login': 'Login Terakhir',
        'password': 'Password',
        'password_confirm': 'Konfirmasi Password'
    }
    
    # Form configuration - exclude auto-managed fields
    form_excluded_columns = ['password_hash', 'predictions', 'created_at', 'last_login']
    
    # Add password fields for create/edit
    form_extra_fields = {
        'password': PasswordField('Password'),
        'password_confirm': PasswordField('Konfirmasi Password')
    }
    
    def create_form(self, obj=None):
        """Override to make password required on create"""
        form = super().create_form(obj)
        # Set validators for create form - password is required
        form.password.validators = [
            DataRequired(message='Password wajib diisi'),
            Length(min=6, message='Password minimal 6 karakter')
        ]
        form.password_confirm.validators = [
            DataRequired(message='Konfirmasi password wajib diisi'),
            EqualTo('password', message='Password tidak cocok')
        ]
        return form
    
    def edit_form(self, obj=None):
        """Override to make password optional on edit"""
        form = super().edit_form(obj)
        # Set validators for edit form - password is optional
        form.password.validators = [
            Optional(),
            Length(min=6, message='Password minimal 6 karakter')
        ]
        form.password_confirm.validators = [
            EqualTo('password', message='Password tidak cocok')
        ]
        # Update label to indicate optional
        form.password.label.text = 'Password Baru (kosongkan jika tidak ingin mengubah)'
        return form
    
    def validate_form(self, form):
        """Override to add logging for form validation"""
        from flask import current_app
        result = super().validate_form(form)
        current_app.logger.info(f"validate_form result: {result}")
        if not result:
            current_app.logger.error(f"Form validation errors: {form.errors}")
        return result
    
    def on_model_change(self, form, model, is_created):
        """Hash password when creating or updating user"""
        from flask import current_app
        current_app.logger.info(f"on_model_change called: is_created={is_created}, username={model.username}")
        
        if form.password.data:
            model.password_hash = generate_password_hash(form.password.data)
            current_app.logger.info(f"Password hash set for user: {model.username}")
        elif is_created:
            # This should not happen due to form validation, but just in case
            raise ValidationError('Password wajib diisi untuk pengguna baru')
    
    def create_model(self, form):
        """Override to add logging"""
        from flask import current_app
        current_app.logger.info(f"create_model called with form data: {form.data}")
        try:
            model = super().create_model(form)
            if model:
                current_app.logger.info(f"User created successfully: {model.username}")
            else:
                current_app.logger.error("create_model returned None/False")
            return model
        except Exception as e:
            current_app.logger.error(f"Error creating user: {str(e)}")
            raise


class PredictionModelView(AdminAccessMixin, ModelView):
    """Prediction records view (read-only)"""
    
    # Disable create and edit
    can_create = False
    can_edit = False
    can_delete = True
    
    def on_model_delete(self, model):
        """Delete the associated image file when prediction is deleted"""
        import os
        from flask import current_app
        
        if model.filename:
            upload_folder = current_app.config['UPLOAD_FOLDER']
            file_path = os.path.join(upload_folder, model.filename)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    current_app.logger.info(f"Deleted image file: {model.filename}")
                except OSError as e:
                    current_app.logger.error(f"Failed to delete image file {model.filename}: {e}")
    
    # List view
    column_list = ['id', 'user.username', 'result_class', 'confidence', 'filename', 'created_at']
    column_searchable_list = ['filename', 'result_class']
    column_filters = ['result_class', 'created_at', 'user.username']
    column_sortable_list = ['id', 'result_class', 'confidence', 'created_at']
    column_default_sort = ('created_at', True)
    
    # Labels in Indonesian
    column_labels = {
        'id': 'ID',
        'user.username': 'Pengguna',
        'result_class': 'Hasil',
        'confidence': 'Keyakinan',
        'filename': 'Nama File',
        'original_filename': 'Nama Asli',
        'created_at': 'Waktu'
    }
    
    # Format confidence as percentage
    column_formatters = {
        'confidence': lambda v, c, m, p: f'{m.confidence * 100:.2f}%'
    }
