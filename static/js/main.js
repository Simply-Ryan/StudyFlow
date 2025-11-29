// Dynamic form handling for session type
document.addEventListener('DOMContentLoaded', function() {
    // Set minimum date for session creation (today)
    const sessionDateInput = document.getElementById('session_date_input');
    if (sessionDateInput) {
        const today = new Date().toISOString().split('T')[0];
        sessionDateInput.min = today;
    }
    
    // Combine date and time inputs before form submission
    const createForm = document.getElementById('createForm');
    if (createForm) {
        createForm.addEventListener('submit', function(e) {
            const dateInput = document.getElementById('session_date_input');
            const timeInput = document.getElementById('session_time_input');
            const hiddenDatetime = document.getElementById('session_date');
            
            if (dateInput && timeInput && hiddenDatetime) {
                // Combine date and time into datetime-local format
                hiddenDatetime.value = dateInput.value + ' ' + timeInput.value;
            }
        });
    }
    
    const sessionTypeSelect = document.getElementById('session_type');
    const meetingLinkGroup = document.getElementById('meetingLinkGroup');
    const locationGroup = document.getElementById('locationGroup');
    
    if (sessionTypeSelect) {
        sessionTypeSelect.addEventListener('change', function() {
            if (this.value === 'remote') {
                meetingLinkGroup.style.display = 'block';
                locationGroup.style.display = 'none';
            } else if (this.value === 'in-person') {
                meetingLinkGroup.style.display = 'none';
                locationGroup.style.display = 'block';
            } else {
                meetingLinkGroup.style.display = 'none';
                locationGroup.style.display = 'none';
            }
        });
    }
    
    // Test reminder button
    const testReminderBtn = document.getElementById('testReminder');
    const reminderNotification = document.getElementById('reminderNotification');
    
    if (testReminderBtn && reminderNotification) {
        testReminderBtn.addEventListener('click', function() {
            // Simulate a reminder notification
            reminderNotification.innerHTML = `
                <strong>🔔 Reminder Sent!</strong><br>
                "Don't forget your study session is coming up soon!"<br>
                <small>Sent at ${new Date().toLocaleTimeString()}</small>
            `;
            reminderNotification.style.display = 'block';
            
            // Hide after 5 seconds
            setTimeout(() => {
                reminderNotification.style.display = 'none';
            }, 5000);
        });
    }
    
    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
    
    // Handle quick file upload from chat area
    const quickFileUpload = document.getElementById('quick-file-upload');
    if (quickFileUpload) {
        quickFileUpload.addEventListener('change', function(e) {
            if (this.files && this.files[0]) {
                const file = this.files[0];
                const sessionId = window.location.pathname.split('/').pop();
                
                // Create FormData for file upload
                const formData = new FormData();
                formData.append('file', file);
                
                // Show upload indication
                const uploadBtn = document.querySelector('.file-upload-btn');
                const originalContent = uploadBtn.innerHTML;
                uploadBtn.innerHTML = '⏳';
                uploadBtn.style.pointerEvents = 'none';
                
                // Upload the file
                fetch(`/session/${sessionId}/upload`, {
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        // Reload page to show new file
                        window.location.reload();
                    } else {
                        alert(data.error || 'Failed to upload file');
                        uploadBtn.innerHTML = originalContent;
                        uploadBtn.style.pointerEvents = 'auto';
                    }
                })
                .catch(error => {
                    alert('Error uploading file: ' + error);
                    uploadBtn.innerHTML = originalContent;
                    uploadBtn.style.pointerEvents = 'auto';
                });
                
                // Reset file input
                this.value = '';
            }
        });
    }
});