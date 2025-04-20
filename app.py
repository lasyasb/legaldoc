import os
import logging
import uuid
import tempfile
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
import time

# Import document processing modules
from text_extractor import extract_text_from_document
from document_analyzer import analyze_document
from forgery_detector import detect_forgery
from scam_detector import detect_scams
from models import db, Report

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "default_dev_key")
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()  # Use temporary directory for uploads
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'docx', 'jpg', 'jpeg', 'png'}

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Create database tables if they don't exist
with app.app_context():
    db.create_all()

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle document file upload and processing"""
    if 'document' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)
    
    file = request.files['document']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)
    
    if not allowed_file(file.filename):
        flash('File type not allowed. Please upload PDF, DOCX, JPG, JPEG, or PNG.', 'danger')
        return redirect(request.url)
    
    # Generate unique filename to avoid collisions
    filename = secure_filename(file.filename)
    unique_filename = f"{str(uuid.uuid4())}_{filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    try:
        file.save(filepath)
        logger.info(f"File saved to {filepath}")
        
        # Process the document
        start_time = time.time()
        
        # Extract text from the document
        logger.info("Extracting text...")
        document_text = extract_text_from_document(filepath)
        
        if not document_text or document_text.strip() == "":
            flash("Could not extract text from document. Please check the file and try again.", "danger")
            return redirect(url_for('index'))
        
        # Analyze the document text
        logger.info("Analyzing document...")
        analysis_results = analyze_document(document_text, filepath)
        
        # Detect forgery
        logger.info("Checking for forgery...")
        forgery_results = detect_forgery(document_text, filepath)
        
        # Detect scams
        logger.info("Checking for scams...")
        scam_results = detect_scams(document_text)
        
        # Calculate overall risk score based on forgery and scam results
        risk_scores = {
            "forgery_risk": forgery_results['risk_score'],
            "scam_risk": scam_results['risk_score'],
        }
        
        combined_risk_score = max(risk_scores.values())
        risk_level = "Low" if combined_risk_score < 0.4 else "Medium" if combined_risk_score < 0.7 else "High"
        
        # Store results in session for display
        report_data = {
            "filename": filename,
            "summary": analysis_results['summary'],
            "key_terms": analysis_results['key_terms'],
            "forgery_alerts": forgery_results['alerts'],
            "scam_alerts": scam_results['alerts'],
            "risk_scores": risk_scores,
            "risk_level": risk_level,
            "processing_time": f"{time.time() - start_time:.2f}"
        }
        
        # Save report to database
        try:
            new_report = Report.from_dict(report_data)
            db.session.add(new_report)
            db.session.commit()
            logger.info(f"Report saved to database with ID: {new_report.id}")
            
            # Store report ID in session
            session['report_id'] = new_report.id
        except Exception as e:
            logger.error(f"Error saving report to database: {str(e)}", exc_info=True)
            flash("Report generated but couldn't be saved to database.", "warning")
        
        session['report_data'] = report_data
        
        logger.info("Document analysis complete")
        return redirect(url_for('report'))
        
    except Exception as e:
        logger.error(f"Error processing document: {str(e)}", exc_info=True)
        flash(f"Error processing document: {str(e)}", "danger")
        return redirect(url_for('index'))
    finally:
        # Clean up uploaded file
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception as e:
            logger.error(f"Error cleaning up file: {str(e)}")

@app.route('/report')
@app.route('/report/<int:report_id>')
def report(report_id=None):
    """Display the document analysis report"""
    # If a specific report ID is provided, retrieve it
    if report_id:
        try:
            report_obj = Report.query.get(report_id)
            if not report_obj:
                flash("Report not found.", "warning")
                return redirect(url_for('index'))
            report_data = report_obj.to_dict()
        except Exception as e:
            logger.error(f"Error retrieving report {report_id}: {str(e)}", exc_info=True)
            flash("Error retrieving report from database.", "danger")
            return redirect(url_for('index'))
    # Otherwise use the report from session (newly generated)
    elif 'report_data' in session:
        report_data = session['report_data']
    else:
        flash("No report data available. Please upload a document first.", "warning")
        return redirect(url_for('index'))
    
    return render_template('report.html', report=report_data)

@app.errorhandler(413)
def too_large(e):
    """Handle file size exceeded error"""
    flash("File too large. Maximum file size is 10MB.", "danger")
    return redirect(url_for('index'))

@app.route('/history')
def history():
    """Display history of document analyses"""
    try:
        # Retrieve the most recent 20 reports
        reports = Report.query.order_by(Report.created_at.desc()).limit(20).all()
        return render_template('history.html', reports=reports)
    except Exception as e:
        logger.error(f"Error retrieving report history: {str(e)}", exc_info=True)
        flash("Error retrieving report history from database.", "danger")
        return redirect(url_for('index'))

@app.route('/delete_report/<int:report_id>', methods=['POST'])
def delete_report(report_id):
    """Delete a report from the database"""
    try:
        report = Report.query.get(report_id)
        if report:
            db.session.delete(report)
            db.session.commit()
            flash("Report deleted successfully.", "success")
        else:
            flash("Report not found.", "warning")
    except Exception as e:
        logger.error(f"Error deleting report {report_id}: {str(e)}", exc_info=True)
        flash("Error deleting report from database.", "danger")
    
    return redirect(url_for('history'))

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 error"""
    return render_template('index.html', error="Page not found"), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
