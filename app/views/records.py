"""
Records Views (Admin Only)
"""
import os
import io
import zipfile
from datetime import datetime
from flask import Blueprint, render_template, request, send_file, current_app, jsonify, abort, flash, redirect, url_for
from flask_login import login_required, current_user

from ..models.prediction import Prediction
from ..models.user import User
from ..extensions import db
from ..utils.decorators import admin_required

records_bp = Blueprint('records', __name__, url_prefix='/records')


@records_bp.route('/')
@login_required
@admin_required
def index():
    """Records list page"""
    # Get filter parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Filters
    user_filter = request.args.get('user', '')
    class_filter = request.args.get('class', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    # Sort parameters
    sort_by = request.args.get('sort', 'created_at')
    sort_order = request.args.get('order', 'desc')
    
    # Build query
    query = Prediction.query.join(User)
    
    # Apply filters
    if user_filter:
        query = query.filter(User.username.ilike(f'%{user_filter}%'))
    
    if class_filter:
        query = query.filter(Prediction.result_class == class_filter)
    
    if date_from:
        try:
            date_from_dt = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Prediction.created_at >= date_from_dt)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_dt = datetime.strptime(date_to, '%Y-%m-%d')
            # Include the entire day
            date_to_dt = date_to_dt.replace(hour=23, minute=59, second=59)
            query = query.filter(Prediction.created_at <= date_to_dt)
        except ValueError:
            pass
    
    # Apply sorting
    valid_sort_columns = ['created_at', 'result_class', 'confidence']
    if sort_by == 'user':
        sort_column = User.username
    elif sort_by in valid_sort_columns:
        sort_column = getattr(Prediction, sort_by)
    else:
        sort_column = Prediction.created_at
    
    if sort_order == 'asc':
        query = query.order_by(sort_column.asc())
    else:
        query = query.order_by(sort_column.desc())
    
    # Paginate
    predictions = query.paginate(page=page, per_page=per_page, error_out=False)
    
    # Get all users for filter dropdown
    users = User.query.all()
    
    return render_template(
        'records/index.html',
        predictions=predictions,
        users=users,
        filters={
            'user': user_filter,
            'class': class_filter,
            'date_from': date_from,
            'date_to': date_to,
            'sort': sort_by,
            'order': sort_order,
            'per_page': per_page
        }
    )


@records_bp.route('/image/<int:prediction_id>')
@login_required
@admin_required
def get_image(prediction_id):
    """Get uploaded image"""
    prediction = Prediction.query.get_or_404(prediction_id)
    
    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, prediction.filename)
    
    # Check if file exists, if not return placeholder
    if not os.path.exists(file_path):
        # Return a placeholder image or 404 with proper handling
        placeholder_path = os.path.join(current_app.static_folder, 'images', 'placeholder.png')
        if os.path.exists(placeholder_path):
            return send_file(placeholder_path)
        # If no placeholder, return 404 JSON response
        current_app.logger.warning(f'Image not found: {file_path}')
        abort(404, description='Gambar tidak ditemukan')
    
    return send_file(file_path)


@records_bp.route('/download/<int:prediction_id>')
@login_required
@admin_required
def download_single(prediction_id):
    """Download single image"""
    prediction = Prediction.query.get_or_404(prediction_id)
    
    upload_folder = current_app.config['UPLOAD_FOLDER']
    file_path = os.path.join(upload_folder, prediction.filename)
    
    if not os.path.exists(file_path):
        abort(404)
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=prediction.filename
    )


@records_bp.route('/download-selected', methods=['POST'])
@login_required
@admin_required
def download_selected():
    """Download selected images as ZIP"""
    data = request.get_json()
    prediction_ids = data.get('ids', [])
    
    if not prediction_ids:
        return jsonify({'error': 'Tidak ada gambar yang dipilih'}), 400
    
    predictions = Prediction.query.filter(Prediction.id.in_(prediction_ids)).all()
    
    if not predictions:
        return jsonify({'error': 'Gambar tidak ditemukan'}), 404
    
    # Create ZIP file in memory
    memory_file = io.BytesIO()
    upload_folder = current_app.config['UPLOAD_FOLDER']
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for prediction in predictions:
            file_path = os.path.join(upload_folder, prediction.filename)
            if os.path.exists(file_path):
                zf.write(file_path, prediction.filename)
    
    memory_file.seek(0)
    
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'dsscan_images_{timestamp}.zip'
    )


@records_bp.route('/download-all')
@login_required
@admin_required
def download_all():
    """Download all images as ZIP"""
    # Apply same filters as the list view
    user_filter = request.args.get('user', '')
    class_filter = request.args.get('class', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = Prediction.query.join(User)
    
    if user_filter:
        query = query.filter(User.username.ilike(f'%{user_filter}%'))
    
    if class_filter:
        query = query.filter(Prediction.result_class == class_filter)
    
    if date_from:
        try:
            date_from_dt = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Prediction.created_at >= date_from_dt)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_dt = datetime.strptime(date_to, '%Y-%m-%d')
            date_to_dt = date_to_dt.replace(hour=23, minute=59, second=59)
            query = query.filter(Prediction.created_at <= date_to_dt)
        except ValueError:
            pass
    
    predictions = query.all()
    
    if not predictions:
        return jsonify({'error': 'Tidak ada gambar untuk diunduh'}), 404
    
    # Create ZIP file in memory
    memory_file = io.BytesIO()
    upload_folder = current_app.config['UPLOAD_FOLDER']
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for prediction in predictions:
            file_path = os.path.join(upload_folder, prediction.filename)
            if os.path.exists(file_path):
                zf.write(file_path, prediction.filename)
    
    memory_file.seek(0)
    
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    
    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'dsscan_all_images_{timestamp}.zip'
    )


@records_bp.route('/delete/<int:prediction_id>', methods=['POST'])
@login_required
@admin_required
def delete_record(prediction_id):
    """Delete a prediction record and its associated image"""
    prediction = Prediction.query.get_or_404(prediction_id)
    
    # Delete the image file
    if prediction.filename:
        upload_folder = current_app.config['UPLOAD_FOLDER']
        file_path = os.path.join(upload_folder, prediction.filename)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                current_app.logger.info(f"Deleted image file: {prediction.filename}")
            except OSError as e:
                current_app.logger.error(f"Failed to delete image file {prediction.filename}: {e}")
    
    # Delete the database record
    db.session.delete(prediction)
    db.session.commit()
    
    current_app.logger.info(f"Deleted prediction record ID: {prediction_id}")
    flash('Data berhasil dihapus.', 'success')
    
    return redirect(url_for('records.index'))


@records_bp.route('/delete-selected', methods=['POST'])
@login_required
@admin_required
def delete_selected():
    """Delete selected prediction records and their associated images"""
    data = request.get_json()
    prediction_ids = data.get('ids', [])
    
    if not prediction_ids:
        return jsonify({'error': 'Tidak ada data yang dipilih'}), 400
    
    predictions = Prediction.query.filter(Prediction.id.in_(prediction_ids)).all()
    
    if not predictions:
        return jsonify({'error': 'Data tidak ditemukan'}), 404
    
    upload_folder = current_app.config['UPLOAD_FOLDER']
    deleted_count = 0
    
    for prediction in predictions:
        # Delete the image file
        if prediction.filename:
            file_path = os.path.join(upload_folder, prediction.filename)
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    current_app.logger.info(f"Deleted image file: {prediction.filename}")
                except OSError as e:
                    current_app.logger.error(f"Failed to delete image file {prediction.filename}: {e}")
        
        db.session.delete(prediction)
        deleted_count += 1
    
    db.session.commit()
    
    current_app.logger.info(f"Deleted {deleted_count} prediction records")
    
    return jsonify({'success': True, 'deleted': deleted_count})
