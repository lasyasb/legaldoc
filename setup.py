from setuptools import setup, find_packages

setup(
    name="legal-document-verifier",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "flask",
        "flask-sqlalchemy",
        "gunicorn",
        "psycopg2-binary",
        "email-validator",
        "Werkzeug",
        "pytesseract",
        "Pillow",
        "numpy",
        "opencv-python",
        "PyPDF2",
        "python-docx",
        "pdf2image",
        "spacy",
    ],
    python_requires=">=3.8",
)