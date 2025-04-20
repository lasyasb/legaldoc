from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class Report(db.Model):
    """Store document analysis reports"""
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text, nullable=True)
    key_terms = db.Column(db.Text, nullable=True)  # Stored as JSON
    forgery_alerts = db.Column(db.Text, nullable=True)  # Stored as JSON
    scam_alerts = db.Column(db.Text, nullable=True)  # Stored as JSON
    forgery_risk_score = db.Column(db.Float, default=0.0)
    scam_risk_score = db.Column(db.Float, default=0.0)
    risk_level = db.Column(db.String(20), nullable=False)
    processing_time = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        """Convert report to dictionary for template rendering"""
        return {
            'id': self.id,
            'filename': self.filename,
            'summary': json.loads(self.summary) if self.summary else [],
            'key_terms': json.loads(self.key_terms) if self.key_terms else [],
            'forgery_alerts': json.loads(self.forgery_alerts) if self.forgery_alerts else [],
            'scam_alerts': json.loads(self.scam_alerts) if self.scam_alerts else [],
            'risk_scores': {
                'forgery_risk': self.forgery_risk_score,
                'scam_risk': self.scam_risk_score
            },
            'risk_level': self.risk_level,
            'processing_time': str(self.processing_time),
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

    @classmethod
    def from_dict(cls, data):
        """Create a report instance from dictionary data"""
        report = cls(
            filename=data['filename'],
            summary=json.dumps(data['summary']),
            key_terms=json.dumps(data['key_terms']),
            forgery_alerts=json.dumps(data['forgery_alerts']),
            scam_alerts=json.dumps(data['scam_alerts']),
            forgery_risk_score=data['risk_scores']['forgery_risk'],
            scam_risk_score=data['risk_scores']['scam_risk'],
            risk_level=data['risk_level'],
            processing_time=float(data['processing_time'])
        )
        return report