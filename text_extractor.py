import os
import logging
import pytesseract
from PIL import Image
import docx
import PyPDF2
import pdf2image
import tempfile

logger = logging.getLogger(__name__)

def extract_text_from_pdf(pdf_path):
    """Extract text from PDF files"""
    text = ""
    try:
        # Try to extract text directly from PDF
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                page_text = page.extract_text()
                
                # If page has no text, it might be scanned - use OCR
                if not page_text or page_text.isspace():
                    logger.info(f"Page {page_num+1} appears to be scanned, using OCR")
                    # Convert PDF page to image
                    images = pdf2image.convert_from_path(
                        pdf_path, 
                        first_page=page_num+1, 
                        last_page=page_num+1
                    )
                    
                    if images:
                        # Apply OCR to the image
                        page_text = pytesseract.image_to_string(images[0])
                
                text += page_text + "\n"
                
        if not text or text.isspace():
            logger.info("No text extracted from PDF, attempting full OCR")
            # If no text was extracted, convert the entire PDF to images and OCR them
            images = pdf2image.convert_from_path(pdf_path)
            for image in images:
                text += pytesseract.image_to_string(image) + "\n"
                
    except Exception as e:
        logger.error(f"Error extracting text from PDF: {str(e)}", exc_info=True)
        raise
        
    return text

def extract_text_from_docx(docx_path):
    """Extract text from DOCX files"""
    try:
        doc = docx.Document(docx_path)
        text = '\n'.join([paragraph.text for paragraph in doc.paragraphs])
        return text
    except Exception as e:
        logger.error(f"Error extracting text from DOCX: {str(e)}", exc_info=True)
        raise

def extract_text_from_image(image_path):
    """Extract text from image files using OCR"""
    try:
        image = Image.open(image_path)
        text = pytesseract.image_to_string(image)
        return text
    except Exception as e:
        logger.error(f"Error extracting text from image: {str(e)}", exc_info=True)
        raise

def extract_text_from_document(file_path):
    """Extract text from various document formats"""
    try:
        file_extension = os.path.splitext(file_path)[1].lower()
        
        if file_extension == '.pdf':
            return extract_text_from_pdf(file_path)
        elif file_extension == '.docx':
            return extract_text_from_docx(file_path)
        elif file_extension in ['.jpg', '.jpeg', '.png']:
            return extract_text_from_image(file_path)
        else:
            logger.error(f"Unsupported file type: {file_extension}")
            raise ValueError(f"Unsupported file type: {file_extension}")
    except Exception as e:
        logger.error(f"Error in extract_text_from_document: {str(e)}", exc_info=True)
        raise
