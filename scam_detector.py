import logging
import re
import os
from collections import Counter

# Setup logging
logger = logging.getLogger(__name__)

# Dictionary of suspicious clauses to look for
SUSPICIOUS_CLAUSES = {
    "unilateral_termination": {
        "patterns": [
            r"\b(?:may|can|shall|will)\s+terminate\s+(?:this|the)\s+(?:agreement|contract)\s+(?:at\s+(?:any|its)\s+time|without\s+(?:cause|reason|notice))",
            r"\b(?:sole|exclusive)\s+(?:discretion|option)\s+to\s+terminate",
            r"\b(?:right|authority)\s+to\s+(?:cancel|terminate)\s+(?:immediately|without\s+notice)"
        ],
        "description": "Unilateral termination clause that allows one party to end the agreement without notice or cause",
        "risk_level": "high"
    },
    "hidden_fees": {
        "patterns": [
            r"\badditional\s+(?:fees|charges|costs)\s+(?:may|will|shall)\s+(?:apply|be\s+charged|be\s+assessed)",
            r"\breserves\s+(?:the\s+)?right\s+to\s+(?:charge|assess|impose)\s+(?:additional|extra)\s+fees",
            r"\bfees\s+subject\s+to\s+change\s+without\s+(?:prior\s+)?notice",
            r"\bpricing\s+may\s+be\s+modified\s+at\s+(?:any\s+time|the\s+(?:sole|exclusive)\s+discretion)"
        ],
        "description": "Clause allowing arbitrary fees to be added without consent",
        "risk_level": "high"
    },
    "unfair_liability": {
        "patterns": [
            r"\bshall\s+not\s+be\s+liable\s+(?:under\s+any\s+circumstances|for\s+any\s+(?:reason|cause))",
            r"\b(?:waives|releases)\s+(?:all|any)\s+(?:claims|rights|remedies)",
            r"\bholds\s+harmless\s+(?:from|against)\s+(?:all|any)",
            r"\bindemnify\s+and\s+(?:hold\s+harmless|defend)\s+against\s+all"
        ],
        "description": "Excessively one-sided liability clause that shifts all risk to one party",
        "risk_level": "high"
    },
    "automatic_renewal": {
        "patterns": [
            r"\b(?:automatically|shall)\s+renew\s+for\s+(?:successive|additional)\s+(?:terms|periods)",
            r"\brenewal\s+(?:shall|will)\s+continue\s+until\s+(?:terminated|cancelled)",
            r"\bunless\s+(?:written\s+)?notice\s+is\s+(?:provided|given|sent)\s+at\s+least\s+(\d+)\s+(?:days|months)"
        ],
        "description": "Automatic renewal clause with difficult termination requirements",
        "risk_level": "medium"
    },
    "ownership_transfer": {
        "patterns": [
            r"\b(?:assigns|transfers|grants)\s+all\s+(?:rights|ownership|title|interest)",
            r"\b(?:intellectual\s+property|copyright|patents|trademarks)\s+shall\s+(?:belong|be\s+owned|vest)\s+exclusively",
            r"\bwaives\s+(?:any|all)\s+(?:moral|intellectual\s+property)\s+rights"
        ],
        "description": "Clause that transfers ownership of your intellectual property or assets",
        "risk_level": "high"
    },
    "non_disclosure_trap": {
        "patterns": [
            r"\bnon[\-\s]disclosure\s+(?:shall|will)\s+remain\s+in\s+effect\s+(?:indefinitely|for\s+(?:ever|an\s+unlimited\s+period))",
            r"\bconfidentiality\s+obligations\s+(?:shall|will)\s+survive\s+termination\s+for\s+(?:a\s+period\s+of\s+)?\d{2,}\s+years",
            r"\ball\s+information\s+(?:shared|disclosed|provided)\s+shall\s+be\s+considered\s+confidential"
        ],
        "description": "Overly broad confidentiality clause with excessive duration",
        "risk_level": "medium"
    },
    "arbitration_clauses": {
        "patterns": [
            r"\b(?:disputes|claims|controversies)\s+shall\s+be\s+resolved\s+(?:exclusively|only|solely)\s+by\s+(?:binding\s+)?arbitration",
            r"\bwaives\s+(?:any|all)\s+(?:rights|ability)\s+to\s+(?:participate\s+in|bring|join)\s+(?:a\s+class\s+action|collective\s+proceeding)",
            r"\barbitration\s+shall\s+take\s+place\s+in\s+([^.,;]+)"
        ],
        "description": "Mandatory arbitration clause that prevents legal recourse or specifies distant jurisdiction",
        "risk_level": "medium"
    },
    "unilateral_amendment": {
        "patterns": [
            r"\b(?:may|can|reserves\s+the\s+right\s+to)\s+(?:amend|modify|change)\s+(?:this|the)\s+(?:agreement|contract|terms)\s+at\s+(?:any\s+time|its\s+(?:sole|exclusive)\s+discretion)",
            r"\bchanges\s+(?:shall|will)\s+be\s+effective\s+(?:immediately|upon\s+posting|without\s+notice)",
            r"\bcontinued\s+use\s+(?:constitutes|indicates|demonstrates)\s+(?:acceptance|agreement)"
        ],
        "description": "Clause allowing unilateral changes to terms without proper notice or consent",
        "risk_level": "high"
    },
    "penalty_clauses": {
        "patterns": [
            r"\b(?:penalty|fee|charge)\s+of\s+(?:[\$\€\£]\s*[\d,]+(?:\.\d+)?|\d+\s*(?:percent|%))",
            r"\bliquidated\s+damages\s+in\s+the\s+amount\s+of\s+(?:[\$\€\£]\s*[\d,]+(?:\.\d+)?|\d+\s*(?:percent|%))",
            r"\bfailure\s+to\s+(?:comply|adhere|abide)\s+will\s+result\s+in\s+(?:a\s+(?:fee|penalty|charge))"
        ],
        "description": "Excessive penalties or liquidated damages clause",
        "risk_level": "high"
    },
    "personal_guarantee": {
        "patterns": [
            r"\b(?:personally|individually)\s+(?:guarantees|assures|is\s+responsible\s+for)",
            r"\bindividual\s+signing\s+(?:shall|will)\s+be\s+(?:personally|individually)\s+liable",
            r"\bjointly\s+and\s+severally\s+liable"
        ],
        "description": "Personal guarantee clause making you individually liable for business obligations",
        "risk_level": "high"
    },
    "urgent_request": {
        "patterns": [
            r"\bmust\s+(?:sign|execute|complete)\s+(?:immediately|urgently|promptly)",
            r"\btime\s+is\s+of\s+the\s+essence",
            r"\blimited[\-\s]time\s+offer",
            r"\bexpires\s+(?:in|within)\s+\d+\s+(?:hours|days)"
        ],
        "description": "Creates false urgency to pressure signing without proper review",
        "risk_level": "medium"
    }
}

# Known scam templates to check for similarity
KNOWN_SCAM_KEYWORDS = [
    "advance fee", "Nigerian prince", "lottery winner", "unclaimed inheritance",
    "overseas transfer", "million dollars", "urgent assistance", "confidential business",
    "western union", "moneygram", "wire transfer", "cryptocurrency",
    "bitcoin", "gift card", "overseas bank", "foreign investor"
]

def detect_suspicious_clauses(text):
    """Detect suspicious clauses in the document text"""
    found_clauses = []
    
    # Check for each suspicious clause type
    for clause_type, clause_info in SUSPICIOUS_CLAUSES.items():
        for pattern in clause_info["patterns"]:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # For each match, extract the surrounding context
                for match in matches:
                    # Find the start of the sentence containing the match
                    pattern_obj = re.compile(pattern, re.IGNORECASE)
                    for match_obj in pattern_obj.finditer(text):
                        start_pos = max(0, text[:match_obj.start()].rfind('.') + 1)
                        if start_pos == 0:
                            start_pos = max(0, text[:match_obj.start()].rfind('\n') + 1)
                        
                        # Find the end of the sentence
                        end_pos = text.find('.', match_obj.end())
                        if end_pos == -1:
                            end_pos = min(len(text), match_obj.end() + 200)
                        
                        # Extract the context
                        context = text[start_pos:end_pos].strip()
                        
                        found_clauses.append({
                            "type": clause_type,
                            "description": clause_info["description"],
                            "risk_level": clause_info["risk_level"],
                            "context": context
                        })
                        
                        # Only use the first match per pattern to avoid redundancy
                        break
    
    # Remove duplicates while preserving order
    unique_clauses = []
    seen_contexts = set()
    for clause in found_clauses:
        # Create a simplified version of the context for comparison
        simple_context = ' '.join(clause["context"].lower().split())
        if simple_context not in seen_contexts:
            seen_contexts.add(simple_context)
            unique_clauses.append(clause)
    
    return unique_clauses

def check_for_scam_templates(text):
    """Check if the document resembles known scam templates"""
    alerts = []
    
    # Check for concentration of scam keywords
    text_lower = text.lower()
    keyword_count = sum(1 for keyword in KNOWN_SCAM_KEYWORDS if keyword in text_lower)
    
    if keyword_count >= 3:
        alerts.append({
            "type": "scam_template",
            "description": f"Document contains multiple phrases commonly found in scam communications ({keyword_count} suspicious terms detected)",
            "risk_level": "high",
            "context": "Multiple suspicious terms detected throughout the document"
        })
    
    # Check for common scam structures
    scam_structures = [
        (r"\b(?:dear|attention|greetings)(?:\s+to)?\s+(?:sir|madam|friend|beneficiary)", "Starts with generic greeting common in scam communications"),
        (r"\bI\s+(?:am|represent)\s+(?:a|the)\s+(?:bank|attorney|solicitor|barrister)", "Claims to be a financial or legal representative, common in scams"),
        (r"\b(?:million|billion)\s+(?:dollars|USD|euros|pounds)", "References unusually large sums of money"),
        (r"\b(?:confidential|private|sensitive)\s+(?:business|transaction|matter|proposal)", "Emphasizes secrecy for a business proposal"),
        (r"\b(?:next\s+of\s+kin|beneficiary|heir)\s+to\s+(?:the|a)\s+(?:late|deceased)", "Inheritance scam pattern"),
        (r"\bcontact\s+(?:me|us)\s+(?:(?:as\s+)?soon\s+as\s+possible|immediately|urgently)", "Urges immediate contact"),
        (r"\b(?:percentage|share|commission)\s+of\s+(?:the|this)\s+(?:fund|money|amount)", "Offers a percentage of funds"),
        (r"\b(?:God|Allah|heaven)\s+bless\s+(?:you|your|family)", "Religious blessing, common in certain scams")
    ]
    
    for pattern, description in scam_structures:
        if re.search(pattern, text, re.IGNORECASE):
            alerts.append({
                "type": "scam_structure",
                "description": f"Document contains language pattern common in scams: {description}",
                "risk_level": "high",
                "context": "Suspicious language pattern detected"
            })
    
    return alerts

def check_for_unusual_requests(text):
    """Check for unusual requests that might indicate fraud"""
    alerts = []
    
    unusual_requests = [
        (r"\b(?:transfer|send|wire|deposit)\s+(?:money|funds|payment|fee)\s+(?:to|into)\s+(?:my|our|the)\s+(?:account|bank)", 
         "Requests money transfer to an account"),
        
        (r"\b(?:prepay|advance|upfront)\s+(?:fee|payment|deposit|money)\s+(?:of|for|to)\s+", 
         "Requests advance payment or fee"),
        
        (r"\b(?:gift\s+cards?|itunes|amazon|google\s+play|steam)\s+(?:cards?|codes?|vouchers?)", 
         "Requests payment in gift cards, a common scam tactic"),
        
        (r"\bcryptocurrency\s+(?:payment|transfer|wallet|address|bitcoin|ethereum|crypto)", 
         "Requests cryptocurrency payment, often used in scams due to irreversibility"),
        
        (r"\b(?:sensitive|confidential|personal)\s+(?:information|details|data)\s+(?:such\s+as|including|like)\s+(?:passport|driver's\s+license|id|birth\s+certificate)", 
         "Requests excessive personal identification documents"),
        
        (r"\bverification\s+(?:code|number|pin)\s+(?:sent|received|texted|messaged)\s+to\s+(?:your|the)\s+(?:phone|mobile|cell)", 
         "Requests verification codes sent to your phone, common in identity theft"),
        
        (r"\bdo\s+not\s+(?:tell|inform|share|discuss)\s+(?:with|this|anyone|anybody|lawyers|attorneys|accountants)", 
         "Requests secrecy or non-disclosure to professional advisors")
    ]
    
    for pattern, description in unusual_requests:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            # Get the context around the match
            start_pos = max(0, match.start() - 100)
            end_pos = min(len(text), match.end() + 100)
            context = text[start_pos:end_pos].strip()
            
            alerts.append({
                "type": "unusual_request",
                "description": f"Document contains suspicious request: {description}",
                "risk_level": "high",
                "context": context
            })
    
    return alerts

def check_for_inconsistencies(text):
    """Check for internal inconsistencies that might indicate fraud"""
    alerts = []
    
    # Check for conflicting statements or terms
    conflicting_terms = [
        (r"\bno\s+(?:fee|cost|charge)\b", r"\b(?:pay|payment|fee|cost|charge)\s+of\s+[\$\€\£]?\s*\d+", 
         "Document claims no fees but then mentions payments/charges"),
        
        (r"\bfree\b", r"\bcosts?\s+[\$\€\£]?\s*\d+", 
         "Document claims to be free but then mentions costs"),
        
        (r"\bno\s+obligation\b", r"\bmust\s+(?:pay|provide|submit|agree)", 
         "Document claims no obligation but then imposes requirements"),
        
        (r"\bguaranteed\b", r"\bno\s+(?:guarantee|warranty|assurance)", 
         "Document provides conflicting statements about guarantees")
    ]
    
    for pattern1, pattern2, description in conflicting_terms:
        if re.search(pattern1, text, re.IGNORECASE) and re.search(pattern2, text, re.IGNORECASE):
            alerts.append({
                "type": "inconsistency",
                "description": description,
                "risk_level": "medium",
                "context": "Inconsistent terms detected in document"
            })
    
    # Check for inconsistent company or entity names
    company_names = re.findall(r'\b(?:[A-Z][a-z]*\s+)+(?:LLC|Inc|Ltd|Corporation|Corp|Company|Co|GmbH|SA|NV|PLC)\b', text)
    if len(company_names) >= 2:
        # Count occurrences of each name
        name_counter = Counter(company_names)
        
        # If there are multiple company names with significant occurrences, flag it
        significant_names = [name for name, count in name_counter.items() if count >= 2]
        if len(significant_names) >= 2:
            alerts.append({
                "type": "inconsistency",
                "description": f"Document references multiple different company names: {', '.join(significant_names[:3])}",
                "risk_level": "medium",
                "context": "Multiple company names may indicate document has been altered"
            })
    
    return alerts

def detect_scams(text):
    """Main function to detect scams in document text"""
    all_alerts = []
    
    # Detect suspicious clauses
    suspicious_clauses = detect_suspicious_clauses(text)
    all_alerts.extend(suspicious_clauses)
    
    # Check for known scam templates
    scam_template_alerts = check_for_scam_templates(text)
    all_alerts.extend(scam_template_alerts)
    
    # Check for unusual requests
    unusual_request_alerts = check_for_unusual_requests(text)
    all_alerts.extend(unusual_request_alerts)
    
    # Check for inconsistencies
    inconsistency_alerts = check_for_inconsistencies(text)
    all_alerts.extend(inconsistency_alerts)
    
    # Calculate risk score
    risk_score = calculate_risk_score(all_alerts)
    
    # Format alerts for display
    formatted_alerts = format_alerts(all_alerts)
    
    return {
        "alerts": formatted_alerts,
        "risk_score": risk_score
    }

def calculate_risk_score(alerts):
    """Calculate overall risk score based on alerts"""
    if not alerts:
        return 0.0
    
    risk_level_scores = {
        "high": 0.25,
        "medium": 0.15,
        "low": 0.05
    }
    
    # Calculate score based on risk levels
    score = sum(risk_level_scores.get(alert["risk_level"], 0.1) for alert in alerts)
    
    # Cap at 1.0
    score = min(score, 1.0)
    
    return score

def format_alerts(alerts):
    """Format alerts for display in the report"""
    formatted_alerts = []
    
    # Group by type and risk level
    for alert in alerts:
        formatted_alert = f"{alert['description']} "
        if "context" in alert and alert["context"]:
            # Truncate context if too long
            context = alert["context"]
            if len(context) > 200:
                context = context[:197] + "..."
            formatted_alert += f"\nContext: \"{context}\""
        
        formatted_alerts.append(formatted_alert)
    
    return formatted_alerts
