// --- GENERIC LIVE MEDIA CAPTURE LOGIC ---
const captureModalEl = document.getElementById('captureModal');
if (captureModalEl) {
    const captureModal = new bootstrap.Modal(captureModalEl);
    const liveVideo = document.getElementById('live-video');
    const photoCanvas = document.getElementById('photo-canvas');
    const videoContainer = document.getElementById('video-container');
    const audioContainer = document.getElementById('audio-container');
    const startBtn = document.getElementById('start-btn');
    const stopBtn = document.getElementById('stop-btn');
    const captureBtn = document.getElementById('capture-btn');
    const permError = document.getElementById('permission-error');
    const modalTitle = document.getElementById('captureModalLabel');
    
    let mediaStream = null;
    let mediaRecorder = null;
    let recordedChunks = [];
    let activeCaptureType = '';
    let activeFileInput = null;
    let activePreviewHandler = null;

    const resetUI = () => {
        permError.style.display = 'none';
        videoContainer.style.display = 'none';
        audioContainer.style.display = 'none';
        startBtn.style.display = 'none';
        stopBtn.style.display = 'none';
        captureBtn.style.display = 'none';
        captureBtn.disabled = true;
        recordedChunks = [];
    };
    
    const addCapturedFileToInput = (file) => {
        console.log('Adding file to input:', file.name);
        console.log('Active input element:', activeFileInput);
        
        if (!activeFileInput) {
            console.error('ERROR: No active file input could be found.');
            alert('An error occurred. Could not find the target file input.');
            return;
        }
        
        // Use the preview handler to add the file directly to fileStore
        if (activePreviewHandler && activePreviewHandler.addFile) {
            activePreviewHandler.addFile(file);
            console.log('File added via preview handler');
        } else {
            // Fallback: add directly to input (without preview handler)
            console.warn('No preview handler found, adding file directly to input');
            const dt = new DataTransfer();
            if (activeFileInput.files) {
                for (let i = 0; i < activeFileInput.files.length; i++) {
                    dt.items.add(activeFileInput.files[i]);
                }
            }
            dt.items.add(file);
            activeFileInput.files = dt.files;
            
            // Trigger change event only in fallback mode
            activeFileInput.dispatchEvent(new Event('change', { bubbles: true }));
        }
        
        // Close modal
        captureModal.hide();
    };

    const handleStream = (stream) => {
        mediaStream = stream;
        if (activeCaptureType === 'image') {
            liveVideo.srcObject = stream;
            videoContainer.style.display = 'block';
            modalTitle.textContent = 'Capture Photo';
            captureBtn.style.display = 'inline-block';
            startBtn.style.display = 'none';
        } 
        else if (activeCaptureType === 'video') {
            liveVideo.srcObject = stream;
            videoContainer.style.display = 'block';
            modalTitle.textContent = 'Record Video';
            startBtn.style.display = 'inline-block';
            captureBtn.style.display = 'none';
        } 
        else { // audio
            audioContainer.style.display = 'block';
            modalTitle.textContent = 'Record Audio';
            startBtn.style.display = 'inline-block';
            captureBtn.style.display = 'none';
        }
    };
    
    liveVideo.addEventListener('canplay', () => {
        if (activeCaptureType === 'image') {
            captureBtn.disabled = false;
        }
    });
    
    const handleStreamError = (err) => {
        console.error("Error accessing media devices.", err);
        permError.style.display = 'block';
    };

    startBtn.onclick = () => {
        startBtn.style.display = 'none';
        stopBtn.style.display = 'inline-block';
        recordedChunks = [];
        const mimeType = activeCaptureType === 'video' ? 'video/webm' : 'audio/webm';
        mediaRecorder = new MediaRecorder(mediaStream, { mimeType });
        
        mediaRecorder.ondataavailable = e => { 
            if (e.data.size > 0) {
                console.log('Chunk received:', e.data.size);
                recordedChunks.push(e.data); 
            }
        };
        
        mediaRecorder.onstop = () => {
            console.log('Recording stopped, chunks:', recordedChunks.length);
            stopBtn.style.display = 'none';
            startBtn.style.display = 'inline-block';
            
            if (recordedChunks.length > 0) {
                const blob = new Blob(recordedChunks, { type: mimeType });
                const fileName = `${activeCaptureType}_${Date.now()}.${mimeType.split('/')[1]}`;
                const file = new File([blob], fileName, { type: mimeType });
                console.log('File created:', file.name, file.size);
                addCapturedFileToInput(file);
            } else {
                console.error('No chunks recorded');
                alert('Recording failed - no data captured.');
            }
        };
        
        mediaRecorder.start(100); // Collect data every 100ms
        console.log('Recording started');
    };

    stopBtn.onclick = () => { 
        console.log('Stop button clicked');
        if (mediaRecorder && mediaRecorder.state === 'recording') {
            mediaRecorder.stop();
        }
    };
    
    captureBtn.onclick = () => {
        if (liveVideo.readyState < 2) return;
        photoCanvas.width = liveVideo.videoWidth;
        photoCanvas.height = liveVideo.videoHeight;
        photoCanvas.getContext('2d').drawImage(liveVideo, 0, 0, photoCanvas.width, photoCanvas.height);
        photoCanvas.toBlob(blob => {
            const file = new File([blob], `capture_${Date.now()}.png`, { type: 'image/png' });
            addCapturedFileToInput(file);
        }, 'image/png');
    };
    
    captureModalEl.addEventListener('show.bs.modal', (event) => {
        resetUI();
        const button = event.relatedTarget;
        activeCaptureType = button.dataset.captureType;
        
        console.log('Capture type:', activeCaptureType);
        
        // Map capture type to correct input ID
        let inputId;
        if (activeCaptureType === 'image') {
            inputId = 'images'; // plural
        } else if (activeCaptureType === 'video') {
            inputId = 'videos'; // plural
        } else if (activeCaptureType === 'audio') {
            inputId = 'audio_files'; // with underscore
        }
        
        console.log('Looking for input with ID:', inputId);
        activeFileInput = document.getElementById(inputId);
        console.log('Found input:', activeFileInput ? 'YES' : 'NO');
        
        // Get the preview handler for this input
        if (window.previewHandlers && window.previewHandlers[inputId]) {
            activePreviewHandler = window.previewHandlers[inputId];
            console.log('Preview handler found for:', inputId);
        } else {
            activePreviewHandler = null;
            console.warn('No preview handler found for:', inputId);
        }
        
        if (!activeFileInput) {
            console.error('Could not find input element with ID:', inputId);
            alert('Error: File input not found. Please check the page structure.');
            return;
        }
        
        const constraints = activeCaptureType === 'image' || activeCaptureType === 'video' 
            ? { video: true, audio: activeCaptureType === 'video' } 
            : { audio: true };
            
        navigator.mediaDevices.getUserMedia(constraints).then(handleStream).catch(handleStreamError);
    });

    captureModalEl.addEventListener('hide.bs.modal', () => { 
        if (mediaStream) { 
            mediaStream.getTracks().forEach(track => track.stop()); 
            mediaStream = null;
        }
        if (mediaRecorder && mediaRecorder.state === 'recording') {
            mediaRecorder.stop();
        }
    });
}