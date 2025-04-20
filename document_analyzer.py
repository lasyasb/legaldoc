import logging
import re
from datetime import datetime
import spacy
import os

# Initialize logging
logger = logging.getLogger(__name__)

# Load spaCy NLP model
try:
    nlp = spacy.load("en_core_web_sm")
except:
    logger.warning("Could not load en_core_web_sm model. Using en_core_web_sm with basic components.")
    nlp = spacy.blank("en")
    for component in ["tok2vec", "tagger", "parser", "ner", "attribute_ruler", "lemmatizer"]:
        nlp.add_pipe(component)

# Key legal terms to look for
LEGAL_TERMS = [
    "agreement", "contract", "terms", "conditions", "party", "parties", "effective date",
    "termination", "clause", "liability", "indemnification", "confidentiality",
    "intellectual property", "governing law", "jurisdiction", "arbitration",
    "force majeure", "breach", "remedy", "compensation", "warranty",
    "amendment", "assignment", "severability", "waiver", "notice",
    "compliance", "obligation", "payment", "deadline", "penalty",
    "fee", "subscription", "cancellation", "refund", "consent"
]

def clean_text(text):
    """Clean the text by removing excessive whitespace and special characters"""
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    return text

def extract_dates(doc):
    """Extract dates from the document"""
    dates = []
    
    # Use spaCy's named entity recognition to find dates
    for ent in doc.ents:
        if ent.label_ == "DATE":
            dates.append(ent.text)
    
    # Use regex to find date patterns not caught by spaCy
    date_patterns = [
        r'\d{1,2}/\d{1,2}/\d{2,4}',  # MM/DD/YYYY or DD/MM/YYYY
        r'\d{1,2}-\d{1,2}-\d{2,4}',  # MM-DD-YYYY or DD-MM-YYYY
        r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b'  # Month DD, YYYY
    ]
    
    for pattern in date_patterns:
        matches = re.findall(pattern, doc.text)
        dates.extend(matches)
    
    return list(set(dates))  # Remove duplicates

def extract_parties(doc):
    """Extract the parties involved in the document"""
    parties = []
    
    # Use spaCy's named entity recognition to find organizations and persons
    for ent in doc.ents:
        if ent.label_ in ["ORG", "PERSON"]:
            parties.append((ent.text, ent.label_))
    
    # Look for common party indicators
    party_indicators = [
        r'(?:party|PARTY) of the first part[:\s]+([^,\.;]+)',
        r'(?:party|PARTY) of the second part[:\s]+([^,\.;]+)',
        r'(?:between|BETWEEN)[:\s]+([^,\.;]+)(?:\s+and\s+|\s*,\s*)([^,\.;]+)',
        r'(?:lessor|LESSOR)[:\s]+([^,\.;]+)',
        r'(?:lessee|LESSEE)[:\s]+([^,\.;]+)',
        r'(?:landlord|LANDLORD)[:\s]+([^,\.;]+)',
        r'(?:tenant|TENANT)[:\s]+([^,\.;]+)',
        r'(?:employer|EMPLOYER)[:\s]+([^,\.;]+)',
        r'(?:employee|EMPLOYEE)[:\s]+([^,\.;]+)',
        r'(?:seller|SELLER)[:\s]+([^,\.;]+)',
        r'(?:buyer|BUYER)[:\s]+([^,\.;]+)',
        r'(?:vendor|VENDOR)[:\s]+([^,\.;]+)',
        r'(?:client|CLIENT)[:\s]+([^,\.;]+)',
        r'(?:hereinafter referred to as[^"]*"([^"]+)")',
        r'(?:hereinafter referred to as\s+([^,\.;]+))'
    ]
    
    for pattern in party_indicators:
        matches = re.findall(pattern, doc.text)
        if matches:
            for match in matches:
                if isinstance(match, tuple):
                    for m in match:
                        parties.append((m.strip(), "PARTY"))
                else:
                    parties.append((match.strip(), "PARTY"))
    
    # Remove duplicates while preserving order
    unique_parties = []
    seen = set()
    for party, label in parties:
        if party not in seen and len(party) > 1:  # Ensure it's more than one character
            seen.add(party)
            unique_parties.append((party, label))
    
    return unique_parties

def extract_key_clauses(doc):
    """Extract key clauses from the document"""
    key_clauses = []
    
    # Split the document into paragraphs
    paragraphs = re.split(r'\n\s*\n', doc.text)
    
    # Look for paragraphs containing important legal terms
    for paragraph in paragraphs:
        paragraph = paragraph.strip()
        if len(paragraph) < 10:  # Skip very short paragraphs
            continue
            
        # Check if paragraph contains important legal terms
        importance_score = 0
        for term in LEGAL_TERMS:
            term_pattern = r'\b' + re.escape(term) + r'\b'
            if re.search(term_pattern, paragraph, re.IGNORECASE):
                importance_score += 1
        
        # If the paragraph contains multiple legal terms, consider it important
        if importance_score >= 2:
            # Find a title for this clause if possible
            title_match = re.match(r'^(?:\d+\.?\s*)?([A-Z][^.!?]*)[.!?]', paragraph)
            title = title_match.group(1).strip() if title_match else "Key Clause"
            
            # Truncate long paragraphs
            if len(paragraph) > 300:
                content = paragraph[:297] + "..."
            else:
                content = paragraph
                
            key_clauses.append((title, content, importance_score))
    
    # Sort by importance score
    key_clauses.sort(key=lambda x: x[2], reverse=True)
    
    # Return top N clauses
    return key_clauses[:8]

def extract_payment_terms(doc):
    """Extract payment terms and deadlines"""
    payment_terms = []
    
    # Look for payment-related sentences
    payment_patterns = [
        r'(?:[Pp]ayment|[Ff]ee|[Aa]mount|[Cc]ost)[^.!?]*\$\s*[\d,]+(?:\.\d+)?[^.!?]*[.!?]',
        r'(?:[Pp]ayment|[Ff]ee|[Aa]mount|[Cc]ost)[^.!?]*[\d,]+(?:\.\d+)?\s*dollars[^.!?]*[.!?]',
        r'(?:[Pp]ayment|[Ff]ee|[Aa]mount|[Cc]ost)[^.!?]*[\d,]+(?:\.\d+)?\s*USD[^.!?]*[.!?]',
        r'(?:[Dd]eadline|[Dd]ue date|[Pp]ayable)[^.!?]*[.!?]'
    ]
    
    for pattern in payment_patterns:
        matches = re.findall(pattern, doc.text)
        payment_terms.extend(matches)
    
    # Remove duplicates
    return list(set(payment_terms))

def extract_termination_clauses(doc):
    """Extract termination clauses"""
    termination_clauses = []
    
    # Look for termination-related paragraphs
    termination_patterns = [
        r'(?:[Tt]erminat(?:ion|e)|[Cc]ancel(?:lation|ling)|[Ee]nd(?:ing)?)[^.!?]*the(?:\s+\w+){1,7}\s+agreement[^.!?]*[.!?]',
        r'(?:[Tt]erminat(?:ion|e)|[Cc]ancel(?:lation|ling)|[Ee]nd(?:ing)?)[^.!?]*this(?:\s+\w+){1,7}\s+agreement[^.!?]*[.!?]',
        r'(?:[Tt]erminat(?:ion|e)|[Cc]ancel(?:lation|ling)|[Ee]nd(?:ing)?)[^.!?]*contract[^.!?]*[.!?]'
    ]
    
    for pattern in termination_patterns:
        matches = re.findall(pattern, doc.text)
        termination_clauses.extend(matches)
    
    # Remove duplicates
    return list(set(termination_clauses))

def summarize_document(doc, parties, dates, key_clauses, payment_terms, termination_clauses):
    """Generate a summary of the document"""
    summary = []
    
    # Document type determination
    doc_type = "Legal Document"
    doc_text_lower = doc.text.lower()
    
    if "lease" in doc_text_lower or "rental" in doc_text_lower or "tenant" in doc_text_lower:
        doc_type = "Lease Agreement"
    elif "employment" in doc_text_lower:
        doc_type = "Employment Contract"
    elif "purchase" in doc_text_lower and "sale" in doc_text_lower:
        doc_type = "Purchase Agreement"
    elif "non-disclosure" in doc_text_lower or "confidentiality" in doc_text_lower:
        doc_type = "Non-Disclosure Agreement"
    elif "service" in doc_text_lower:
        doc_type = "Service Agreement"
    
    summary.append(f"Document Type: {doc_type}")
    
    # Add parties
    if parties:
        summary.append(f"Parties Involved: {', '.join([party for party, _ in parties[:5]])}")
    
    # Add key dates
    if dates:
        summary.append(f"Key Dates: {', '.join(dates[:3])}")
    
    # Add payment information if present
    if payment_terms:
        summary.append(f"Payment Terms: {payment_terms[0][:100]}...")
    
    # Add termination information if present
    if termination_clauses:
        summary.append(f"Termination: {termination_clauses[0][:100]}...")
    
    # Document length
    word_count = len(doc.text.split())
    summary.append(f"Document Length: Approximately {word_count} words")
    
    return summary

def analyze_document(text, file_path=None):
    """Analyze the document text and return structured information"""
    logger.info("Starting document analysis")
    
    # Clean the text
    text = clean_text(text)
    
    # Process with spaCy
    doc = nlp(text[:100000])  # Limit to first 100k chars to avoid memory issues
    
    # Extract information
    dates = extract_dates(doc)
    parties = extract_parties(doc)
    key_clauses = extract_key_clauses(doc)
    payment_terms = extract_payment_terms(doc)
    termination_clauses = extract_termination_clauses(doc)
    
    # Generate summary
    summary = summarize_document(doc, parties, dates, key_clauses, payment_terms, termination_clauses)
    
    # Extract key terms for highlighting
    key_terms = []
    for title, content, _ in key_clauses:
        key_terms.append({
            "title": title,
            "content": content[:200] + "..." if len(content) > 200 else content
        })
    
    # Combine everything
    results = {
        "summary": summary,
        "parties": parties,
        "dates": dates,
        "key_clauses": key_clauses,
        "payment_terms": payment_terms,
        "termination_clauses": termination_clauses,
        "key_terms": key_terms
    }
    
    logger.info("Document analysis completed")
    return results
