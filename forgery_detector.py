import os
import logging
import re
import cv2
import numpy as np
from PIL import Image
import pytesseract
import PyPDF2
import pdf2image
import tempfile

logger = logging.getLogger(__name__)

def detect_font_inconsistencies(text):
    """
    Detect potential font inconsistencies in the text that might indicate forgery
    Uses text pattern analysis rather than actual font detection
    """
    alerts = []
    
    # Check for unusual character combinations that might indicate copy-paste
    lines = text.split('\n')
    prev_line_style = None
    style_changes = 0
    
    for i, line in enumerate(lines):
        if not line.strip():
            continue
            
        # Analyze line style characteristics
        uppercase_ratio = sum(1 for c in line if c.isupper()) / max(len(line), 1)
        digit_ratio = sum(1 for c in line if c.isdigit()) / max(len(line), 1)
        punctuation_ratio = sum(1 for c in line if c in '.,;:!?-()[]{}') / max(len(line), 1)
        
        current_style = (
            round(uppercase_ratio, 2),
            round(digit_ratio, 2),
            round(punctuation_ratio, 2)
        )
        
        if prev_line_style is not None:
            # Check for significant style change
            style_diff = sum(abs(a - b) for a, b in zip(current_style, prev_line_style))
            if style_diff > 0.5:  # Threshold for significant change
                style_changes += 1
        
        prev_line_style = current_style
    
    # Alert if there are many style changes in the document
    if style_changes > len(lines) / 10:  # If more than 10% of lines have style changes
        alerts.append("Multiple font or formatting inconsistencies detected throughout the document.")
    
    # Check for unusual spacing patterns
    unusual_spacing = re.findall(r'\S\s{3,}\S', text)
    if len(unusual_spacing) > 5:
        alerts.append("Unusual spacing detected in text, possible indication of content manipulation.")
    
    return alerts

def check_signature_irregularities(image_path):
    """
    Analyze a document image to detect potential signature irregularities
    """
    alerts = []
    
    try:
        # Load the image
        image = cv2.imread(image_path)
        if image is None:
            logger.error(f"Failed to load image: {image_path}")
            return ["Could not analyze image for signature verification"]
        
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Apply adaptive thresholding to find signature-like areas
        thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                      cv2.THRESH_BINARY_INV, 11, 2)
        
        # Find contours
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        # Filter contours to find potential signatures
        potential_signatures = []
        for contour in contours:
            x, y, w, h = cv2.boundingRect(contour)
            aspect_ratio = w / h if h > 0 else 0
            
            # Signatures typically have certain characteristics
            if 200 < w < 1000 and 20 < h < 200 and 1.5 < aspect_ratio < 10:
                signature_roi = thresh[y:y+h, x:x+w]
                
                # Check density of black pixels (signature should have certain density)
                black_pixel_density = np.sum(signature_roi == 255) / (w * h)
                
                if 0.05 < black_pixel_density < 0.5:
                    potential_signatures.append((x, y, w, h, signature_roi, black_pixel_density))
        
        # Analyze potential signatures
        if potential_signatures:
            # Check for pixel-level inconsistencies in signatures
            for i, (x, y, w, h, roi, density) in enumerate(potential_signatures):
                # Check for pixelation - look at pixel value transitions
                edge_count = 0
                for r in range(1, roi.shape[0]-1):
                    for c in range(1, roi.shape[1]-1):
                        if roi[r,c] != roi[r,c+1] or roi[r,c] != roi[r,c-1] or roi[r,c] != roi[r+1,c] or roi[r,c] != roi[r-1,c]:
                            edge_count += 1
                
                edge_density = edge_count / (w * h)
                
                # A high number of edges compared to area might indicate digital tampering
                if edge_density > 0.3:
                    alerts.append(f"Potential signature irregularity detected: pixelation suggests possible digital manipulation.")
                    break
                
                # Check for uniform borders that might indicate copy-paste
                border_uniformity = True
                for i in range(min(20, h-1)):
                    if np.sum(roi[i,:] == 255) > 0:
                        border_uniformity = False
                        break
                
                if border_uniformity:
                    alerts.append(f"Potential signature irregularity: unusually uniform borders suggest possible copying.")
                    break
            
            # If multiple signatures, check for exact duplicates
            if len(potential_signatures) > 1:
                for i in range(len(potential_signatures)):
                    for j in range(i+1, len(potential_signatures)):
                        sig1 = cv2.resize(potential_signatures[i][4], (100, 50))
                        sig2 = cv2.resize(potential_signatures[j][4], (100, 50))
                        
                        # Calculate similarity
                        similarity = np.sum(sig1 == sig2) / (100 * 50)
                        
                        if similarity > 0.9:  # If more than 90% identical
                            alerts.append("Multiple signatures appear nearly identical, suggesting possible copying.")
                            break
        else:
            # If the document should have signatures but none detected
            text = pytesseract.image_to_string(image)
            if re.search(r'\b(?:sign(?:ed|ature)|agree(?:d|ment))\b', text, re.IGNORECASE):
                if not potential_signatures:
                    alerts.append("Document appears to require signatures, but no clear signatures detected.")
    
    except Exception as e:
        logger.error(f"Error in signature analysis: {str(e)}", exc_info=True)
        alerts.append("Error in signature analysis.")
    
    return alerts

def detect_image_manipulation(image_path):
    """
    Detect potential image manipulation that might indicate document forgery
    """
    alerts = []
    
    try:
        # Load the image
        image = cv2.imread(image_path)
        if image is None:
            logger.error(f"Failed to load image: {image_path}")
            return ["Could not analyze image for manipulation detection"]
        
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Apply error level analysis (ELA)
        # Save as JPEG with quality 95
        temp_jpg_path = os.path.join(tempfile.gettempdir(), "temp_ela.jpg")
        cv2.imwrite(temp_jpg_path, image, [cv2.IMWRITE_JPEG_QUALITY, 95])
        
        # Load back the JPEG
        jpg_image = cv2.imread(temp_jpg_path)
        
        # Compute the difference
        if jpg_image is not None:
            ela_image = cv2.absdiff(image, jpg_image)
            
            # Calculate the average error level
            avg_error = np.mean(ela_image)
            
            # If the error level is unusually high, it might indicate manipulation
            if avg_error > 10:
                alerts.append("Image analysis indicates possible digital manipulation of the document.")
            
            # Clean up
            os.remove(temp_jpg_path)
        
        # Check for copy-paste by looking for repeated patterns
        # Use normalized cross-correlation for pattern detection
        result = cv2.matchTemplate(gray, gray, cv2.TM_CCOEFF_NORMED)
        threshold = 0.95
        locations = np.where(result >= threshold)
        
        # Filter out trivial matches (a region matching itself)
        matches = []
        for pt in zip(*locations[::-1]):
            unique_match = True
            for existing_pt in matches:
                if abs(pt[0] - existing_pt[0]) < 5 and abs(pt[1] - existing_pt[1]) < 5:
                    unique_match = False
                    break
            if unique_match:
                matches.append(pt)
        
        # If there are multiple non-trivial matches, it might indicate copy-paste
        if len(matches) > 5:
            alerts.append("Document appears to contain repeated elements, suggesting possible copy-paste manipulation.")
        
    except Exception as e:
        logger.error(f"Error in image manipulation detection: {str(e)}", exc_info=True)
        alerts.append("Error in image analysis.")
    
    return alerts

def check_metadata_inconsistencies(file_path):
    """
    Check for inconsistencies in document metadata
    """
    alerts = []
    
    try:
        file_extension = os.path.splitext(file_path)[1].lower()
        
        if file_extension == '.pdf':
            with open(file_path, 'rb') as f:
                pdf_reader = PyPDF2.PdfReader(f)
                
                if pdf_reader.metadata:
                    # Check for modification date vs creation date
                    created_date = pdf_reader.metadata.get('/CreationDate')
                    mod_date = pdf_reader.metadata.get('/ModDate')
                    
                    if created_date and mod_date:
                        # Extract dates from PDF date format
                        created_match = re.search(r'D:(\d{14})', created_date)
                        mod_match = re.search(r'D:(\d{14})', mod_date)
                        
                        if created_match and mod_match:
                            created_timestamp = created_match.group(1)
                            mod_timestamp = mod_match.group(1)
                            
                            # If modification date is earlier than creation date
                            if mod_timestamp < created_timestamp:
                                alerts.append("Document metadata shows modification date earlier than creation date, suggesting possible tampering.")
                            
                            # If dates are far apart, might be a modified document
                            created_year = int(created_timestamp[:4])
                            mod_year = int(mod_timestamp[:4])
                            
                            if abs(mod_year - created_year) > 5:
                                alerts.append(f"Document was created in {created_year} but modified in {mod_year}, suggesting possible updates to original content.")
                
                # Check for inconsistent fonts across the document
                fonts = set()
                for page in pdf_reader.pages:
                    if '/Resources' in page:
                        resources = page['/Resources']
                        if '/Font' in resources:
                            for font in resources['/Font']:
                                fonts.add(font)
                
                if len(fonts) > 5:
                    alerts.append(f"Document uses {len(fonts)} different font types, suggesting possible cut-and-paste from multiple sources.")
    
    except Exception as e:
        logger.error(f"Error checking metadata: {str(e)}", exc_info=True)
    
    return alerts

def detect_forgery(document_text, file_path):
    """
    Main function to detect potential forgery in a document
    """
    alerts = []
    risk_score = 0.0
    
    # Check for font inconsistencies in the text
    text_alerts = detect_font_inconsistencies(document_text)
    alerts.extend(text_alerts)
    
    # If the file exists, perform image-based checks
    if os.path.exists(file_path):
        file_extension = os.path.splitext(file_path)[1].lower()
        
        if file_extension == '.pdf':
            # For PDFs, extract images and check each one
            try:
                # Convert first page to image for analysis
                images = pdf2image.convert_from_path(file_path, first_page=1, last_page=1)
                if images:
                    # Save the image temporarily
                    temp_image_path = os.path.join(tempfile.gettempdir(), "temp_pdf_image.png")
                    images[0].save(temp_image_path)
                    
                    # Check signatures and image manipulation
                    signature_alerts = check_signature_irregularities(temp_image_path)
                    alerts.extend(signature_alerts)
                    
                    manipulation_alerts = detect_image_manipulation(temp_image_path)
                    alerts.extend(manipulation_alerts)
                    
                    # Clean up
                    os.remove(temp_image_path)
                
                # Check metadata
                metadata_alerts = check_metadata_inconsistencies(file_path)
                alerts.extend(metadata_alerts)
                
            except Exception as e:
                logger.error(f"Error processing PDF for forgery detection: {str(e)}", exc_info=True)
                alerts.append("Error analyzing PDF document for forgery indicators.")
                
        elif file_extension in ['.jpg', '.jpeg', '.png']:
            # For images, check directly
            signature_alerts = check_signature_irregularities(file_path)
            alerts.extend(signature_alerts)
            
            manipulation_alerts = detect_image_manipulation(file_path)
            alerts.extend(manipulation_alerts)
    
    # Calculate risk score based on number and severity of alerts
    risk_score = min(1.0, len(alerts) * 0.2)
    
    # Add general alert if no specific issues found but text appears suspicious
    if not alerts and len(document_text.split()) > 100:
        suspicious_patterns = [
            r'\bfee\s+of\s+\$\s*[\d,]+(?:\.\d+)?\s+(?:USD|dollars)\b',
            r'\bbank\s+(?:transfer|wire)\b',
            r'\b(?:western\s+union|moneygram)\b',
            r'\bcryptocurrency\b',
            r'\bbitcoin\b',
            r'\bconfidential\s+information\b',
            r'\bsign\s+immediately\b',
            r'\btime\s+sensitive\b',
            r'\burgent\s+(?:action|attention|response)\b'
        ]
        
        matches = []
        for pattern in suspicious_patterns:
            if re.search(pattern, document_text, re.IGNORECASE):
                matches.append(pattern)
        
        if len(matches) >= 2:
            alerts.append("Document contains potentially suspicious wording patterns. Exercise caution.")
            risk_score = max(risk_score, 0.4)
    
    return {
        "alerts": alerts,
        "risk_score": risk_score
    }
