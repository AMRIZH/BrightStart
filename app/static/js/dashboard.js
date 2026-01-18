/**
 * DSscan - Dashboard JavaScript
 * Handles file upload, camera capture, and prediction
 */

document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const uploadForm = document.getElementById('upload-form');
    const uploadArea = document.getElementById('upload-area');
    const fileInput = document.getElementById('file-input');
    const uploadPlaceholder = document.getElementById('upload-placeholder');
    const previewContainer = document.getElementById('preview-container');
    const previewImage = document.getElementById('preview-image');
    const fileName = document.getElementById('file-name');
    const analyzeBtn = document.getElementById('analyze-btn');
    const clearBtn = document.getElementById('clear-btn');
    const loadingOverlay = document.getElementById('loading-overlay');
    const resultSection = document.getElementById('result-section');
    const resultContent = document.getElementById('result-content');
    
    // Camera elements
    const cameraTab = document.getElementById('camera-tab');
    const cameraVideo = document.getElementById('camera-video');
    const cameraCanvas = document.getElementById('camera-canvas');
    const cameraPreview = document.getElementById('camera-preview');
    const cameraPlaceholder = document.getElementById('camera-placeholder');
    const startCameraBtn = document.getElementById('start-camera-btn');
    const captureBtn = document.getElementById('capture-btn');
    const retakeBtn = document.getElementById('retake-btn');
    const analyzeCameraBtn = document.getElementById('analyze-camera-btn');
    
    // Mobile camera modal elements
    const cameraModal = document.getElementById('cameraModal');
    const modalCameraVideo = document.getElementById('modal-camera-video');
    const modalCaptureBtn = document.getElementById('modal-capture-btn');
    const closeCameraModal = document.getElementById('close-camera-modal');
    
    let currentFile = null;
    let cameraStream = null;
    let capturedBlob = null;
    
    // Check if mobile
    const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
    
    // ======================
    // File Upload Functions
    // ======================
    
    // Click to upload
    uploadArea.addEventListener('click', () => fileInput.click());
    
    // Drag and drop
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('drag-over');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('drag-over');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });
    
    // File input change
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });
    
    // Handle file selection
    function handleFile(file) {
        // Validate file type
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp', 'image/tiff', 'image/heic', 'image/heif'];
        const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'tif', 'heic', 'heif'];
        
        const ext = file.name.split('.').pop().toLowerCase();
        
        if (!allowedTypes.includes(file.type) && !allowedExtensions.includes(ext)) {
            showError('Format file tidak didukung. Gunakan JPG, PNG, GIF, BMP, WEBP, TIFF, atau HEIC.');
            return;
        }
        
        // Validate file size (10MB)
        if (file.size > 10 * 1024 * 1024) {
            showError('Ukuran file terlalu besar. Maksimal 10MB.');
            return;
        }
        
        currentFile = file;
        
        // Show preview
        const reader = new FileReader();
        reader.onload = (e) => {
            previewImage.src = e.target.result;
            fileName.textContent = file.name;
            uploadPlaceholder.classList.add('d-none');
            previewContainer.classList.remove('d-none');
            uploadArea.classList.add('has-image');
            analyzeBtn.disabled = false;
            clearBtn.classList.remove('d-none');
        };
        reader.readAsDataURL(file);
        
        // Hide previous results
        resultSection.classList.add('d-none');
    }
    
    // Clear button
    clearBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        resetUpload();
    });
    
    function resetUpload() {
        currentFile = null;
        fileInput.value = '';
        previewImage.src = '';
        fileName.textContent = '';
        uploadPlaceholder.classList.remove('d-none');
        previewContainer.classList.add('d-none');
        uploadArea.classList.remove('has-image');
        analyzeBtn.disabled = true;
        clearBtn.classList.add('d-none');
        resultSection.classList.add('d-none');
    }
    
    // ======================
    // Camera Functions
    // ======================
    
    startCameraBtn.addEventListener('click', async () => {
        if (isMobile) {
            // Show modal for mobile
            const modal = new bootstrap.Modal(cameraModal);
            modal.show();
            await startCamera(modalCameraVideo);
        } else {
            // Inline camera for desktop
            await startCamera(cameraVideo);
        }
    });
    
    async function startCamera(videoElement) {
        try {
            const constraints = {
                video: {
                    width: { ideal: 640 },
                    height: { ideal: 480 },
                    facingMode: 'user'
                }
            };
            
            cameraStream = await navigator.mediaDevices.getUserMedia(constraints);
            videoElement.srcObject = cameraStream;
            videoElement.classList.remove('d-none');
            
            if (videoElement === cameraVideo) {
                cameraPlaceholder.classList.add('d-none');
                startCameraBtn.classList.add('d-none');
                captureBtn.classList.remove('d-none');
            }
        } catch (error) {
            console.error('Camera error:', error);
            showError('Tidak dapat mengakses kamera. Pastikan Anda memberikan izin kamera.');
        }
    }
    
    function stopCamera() {
        if (cameraStream) {
            cameraStream.getTracks().forEach(track => track.stop());
            cameraStream = null;
        }
    }
    
    // Capture photo (desktop)
    captureBtn.addEventListener('click', () => {
        capturePhoto(cameraVideo);
    });
    
    // Capture photo (mobile modal)
    modalCaptureBtn.addEventListener('click', () => {
        capturePhoto(modalCameraVideo);
        
        // Close modal
        const modal = bootstrap.Modal.getInstance(cameraModal);
        modal.hide();
        
        // Show preview in main area
        cameraVideo.classList.add('d-none');
        cameraPreview.src = cameraCanvas.toDataURL('image/jpeg');
        cameraPreview.classList.remove('d-none');
        cameraPlaceholder.classList.add('d-none');
        startCameraBtn.classList.add('d-none');
        captureBtn.classList.add('d-none');
        retakeBtn.classList.remove('d-none');
        analyzeCameraBtn.classList.remove('d-none');
    });
    
    function capturePhoto(videoElement) {
        cameraCanvas.width = videoElement.videoWidth;
        cameraCanvas.height = videoElement.videoHeight;
        
        const ctx = cameraCanvas.getContext('2d');
        ctx.drawImage(videoElement, 0, 0);
        
        // Convert to blob
        cameraCanvas.toBlob((blob) => {
            capturedBlob = blob;
        }, 'image/jpeg', 0.9);
        
        stopCamera();
        
        if (videoElement === cameraVideo) {
            cameraVideo.classList.add('d-none');
            cameraPreview.src = cameraCanvas.toDataURL('image/jpeg');
            cameraPreview.classList.remove('d-none');
            captureBtn.classList.add('d-none');
            retakeBtn.classList.remove('d-none');
            analyzeCameraBtn.classList.remove('d-none');
        }
        
        // Hide previous results
        resultSection.classList.add('d-none');
    }
    
    // Retake photo
    retakeBtn.addEventListener('click', async () => {
        capturedBlob = null;
        cameraPreview.classList.add('d-none');
        retakeBtn.classList.add('d-none');
        analyzeCameraBtn.classList.add('d-none');
        
        if (isMobile) {
            cameraPlaceholder.classList.remove('d-none');
            startCameraBtn.classList.remove('d-none');
        } else {
            await startCamera(cameraVideo);
        }
    });
    
    // Close modal - stop camera
    closeCameraModal.addEventListener('click', () => {
        stopCamera();
    });
    
    cameraModal.addEventListener('hidden.bs.modal', () => {
        stopCamera();
        modalCameraVideo.srcObject = null;
    });
    
    // Stop camera when switching tabs
    cameraTab.addEventListener('hidden.bs.tab', () => {
        stopCamera();
        cameraVideo.classList.add('d-none');
        cameraPreview.classList.add('d-none');
        cameraPlaceholder.classList.remove('d-none');
        startCameraBtn.classList.remove('d-none');
        captureBtn.classList.add('d-none');
        retakeBtn.classList.add('d-none');
        analyzeCameraBtn.classList.add('d-none');
        capturedBlob = null;
    });
    
    // ======================
    // Prediction Functions
    // ======================
    
    // Submit file upload form
    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        if (!currentFile) {
            showError('Pilih gambar terlebih dahulu.');
            return;
        }
        
        await submitPrediction(currentFile);
    });
    
    // Submit camera capture
    analyzeCameraBtn.addEventListener('click', async () => {
        if (!capturedBlob) {
            showError('Ambil foto terlebih dahulu.');
            return;
        }
        
        // Create file from blob
        const file = new File([capturedBlob], 'camera_capture.jpg', { type: 'image/jpeg' });
        await submitPrediction(file);
    });
    
    async function submitPrediction(file) {
        showLoading();
        
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch('/dashboard/predict', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': document.querySelector('input[name="csrf_token"]').value
                }
            });
            
            const data = await response.json();
            
            hideLoading();
            
            if (data.success) {
                showResult(data.result);
            } else {
                showError(data.error || 'Terjadi kesalahan saat memproses gambar.');
            }
        } catch (error) {
            hideLoading();
            console.error('Prediction error:', error);
            showError('Terjadi kesalahan jaringan. Silakan coba lagi.');
        }
    }
    
    // ======================
    // UI Helper Functions
    // ======================
    
    function showLoading() {
        loadingOverlay.classList.remove('d-none');
    }
    
    function hideLoading() {
        loadingOverlay.classList.add('d-none');
    }
    
    function showError(message) {
        resultSection.classList.remove('d-none');
        resultContent.innerHTML = `
            <div class="alert alert-danger d-flex align-items-center" role="alert">
                <i class="bi bi-exclamation-triangle-fill me-2 fs-4"></i>
                <div>${message}</div>
            </div>
        `;
    }
    
    function showResult(result) {
        const isNormal = result.class === 'Normal';
        const cardClass = isNormal ? 'result-normal' : 'result-ds';
        const bgClass = isNormal ? 'bg-success-subtle' : 'bg-warning-subtle';
        const textClass = isNormal ? 'text-success' : 'text-warning';
        const icon = isNormal ? 'bi-check-circle-fill' : 'bi-exclamation-circle-fill';
        
        resultSection.classList.remove('d-none');
        resultContent.innerHTML = `
            <div class="card result-card ${cardClass} ${bgClass} border-0 rounded-4">
                <div class="card-body p-4">
                    <div class="row align-items-center">
                        <div class="col-auto">
                            <i class="bi ${icon} ${textClass} display-4"></i>
                        </div>
                        <div class="col">
                            <h4 class="mb-1 fw-bold">${result.class}</h4>
                            <p class="mb-0 text-muted">Tingkat Keyakinan: <strong>${result.confidence_percentage}</strong></p>
                        </div>
                    </div>
                    
                    <hr class="my-3">
                    
                    <h6 class="fw-bold mb-3">Detail Probabilitas:</h6>
                    <div class="mb-2">
                        <div class="d-flex justify-content-between mb-1">
                            <span>Normal</span>
                            <span class="fw-bold">${result.probabilities.Normal}</span>
                        </div>
                        <div class="progress" style="height: 20px;">
                            <div class="progress-bar bg-success" style="width: ${result.probabilities.Normal}"></div>
                        </div>
                    </div>
                    <div>
                        <div class="d-flex justify-content-between mb-1">
                            <span>Down Syndrome</span>
                            <span class="fw-bold">${result.probabilities['Down Syndrome']}</span>
                        </div>
                        <div class="progress" style="height: 20px;">
                            <div class="progress-bar bg-warning" style="width: ${result.probabilities['Down Syndrome']}"></div>
                        </div>
                    </div>
                    
                    <div class="alert alert-info mt-4 mb-0">
                        <i class="bi bi-info-circle me-2"></i>
                        <small>Hasil ini hanya untuk tujuan penelitian dan edukasi. Bukan diagnosis medis.</small>
                    </div>
                </div>
            </div>
        `;
        
        // Scroll to result
        resultSection.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
});
