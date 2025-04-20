// Main JavaScript for Legal Document Verifier

document.addEventListener('DOMContentLoaded', function() {
    // File upload validation
    const fileInput = document.getElementById('document');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                // Check file size
                const maxSize = 10 * 1024 * 1024; // 10MB
                if (file.size > maxSize) {
                    alert('File is too large. Maximum file size is 10MB.');
                    e.target.value = '';
                    return;
                }
                
                // Check file type
                const validTypes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'image/jpeg', 'image/png'];
                const fileExtension = file.name.split('.').pop().toLowerCase();
                const validExtensions = ['pdf', 'docx', 'jpg', 'jpeg', 'png'];
                
                if (!validTypes.includes(file.type) && !validExtensions.includes(fileExtension)) {
                    alert('Invalid file type. Please upload PDF, DOCX, JPG, JPEG, or PNG.');
                    e.target.value = '';
                    return;
                }
                
                // Show file name in UI
                const fileName = document.querySelector('.custom-file-label');
                if (fileName) {
                    fileName.textContent = file.name;
                }
            }
        });
    }
    
    // Enable tooltips
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    if (tooltips.length > 0) {
        tooltips.forEach(tooltip => {
            new bootstrap.Tooltip(tooltip);
        });
    }
    
    // Enable popovers
    const popovers = document.querySelectorAll('[data-bs-toggle="popover"]');
    if (popovers.length > 0) {
        popovers.forEach(popover => {
            new bootstrap.Popover(popover);
        });
    }
    
    // Prevent form resubmission on page refresh
    if (window.history.replaceState) {
        window.history.replaceState(null, null, window.location.href);
    }
    
    // Auto-expand first accordion item if present
    const firstAccordionButton = document.querySelector('.accordion-button');
    if (firstAccordionButton) {
        // Uncomment to auto-expand first item
        // firstAccordionButton.click();
    }
    
    // Add smooth scrolling to all links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });
});

// Highlight text in report sections
function highlightText(elementId, searchText) {
    const element = document.getElementById(elementId);
    if (!element || !searchText) return;
    
    const regex = new RegExp(`(${searchText})`, 'gi');
    element.innerHTML = element.textContent.replace(
        regex, 
        '<span class="highlight">$1</span>'
    );
}

// Copy report text to clipboard
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    if (!element) return;
    
    const text = element.innerText;
    navigator.clipboard.writeText(text).then(() => {
        // Show success message
        const button = document.querySelector(`[data-copy="${elementId}"]`);
        if (button) {
            const originalText = button.innerHTML;
            button.innerHTML = '<i class="fas fa-check"></i> Copied!';
            setTimeout(() => {
                button.innerHTML = originalText;
            }, 2000);
        }
    }).catch(err => {
        console.error('Could not copy text: ', err);
    });
}
