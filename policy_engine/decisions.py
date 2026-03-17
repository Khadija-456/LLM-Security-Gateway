# policy_engine/decision.py

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from presidio_anonymizer import AnonymizerEngine
from config.settings import INJECTION_THRESHOLD

# Initialize anonymizer
anonymizer = AnonymizerEngine()

def get_pii_sensitivity(pii_entities):
    """Determine sensitivity level of detected PII"""
    
    high_sensitivity = ["CREDIT_CARD", "SSN", "PASSPORT", "API_KEY"]
    medium_sensitivity = ["EMAIL_ADDRESS", "PHONE_NUMBER", "INTERNAL_ID"]
    
    for entity in pii_entities:
        if entity.entity_type in high_sensitivity:
            return "HIGH"
        elif entity.entity_type in medium_sensitivity:
            return "MEDIUM"
    
    return "LOW" if pii_entities else "NONE"

def policy_decision(text, injection_score, pii_entities):
    """
    Policy decision engine
    Returns: (decision, output_text)
    """
    
    # Get sensitivity level
    sensitivity = get_pii_sensitivity(pii_entities)
    
    # CASE 1: HIGH INJECTION SCORE - BLOCK
    if injection_score > INJECTION_THRESHOLD:
        return (
            "BLOCK",
            "Request blocked: Potential security threat detected"
        )
    
    # CASE 2: MEDIUM INJECTION SCORE - SCRUTINIZE
    elif injection_score > INJECTION_THRESHOLD * 0.7:  # 0.28 if threshold is 0.4
        if sensitivity == "HIGH":
            return (
                "BLOCK",
                "Request blocked: Suspicious input with sensitive data"
            )
        elif pii_entities:
            # Mask PII
            anonymized = anonymizer.anonymize(
                text=text,
                analyzer_results=pii_entities
            )
            return ("MASK", anonymized.text)
        else:
            return ("ALLOW", text)
    
    # CASE 3: LOW INJECTION SCORE - NORMAL PROCESSING
    else:
        if sensitivity == "HIGH":
            return (
                "BLOCK",
                "Request blocked: Contains sensitive information"
            )
        elif pii_entities:
            # Mask any PII
            anonymized = anonymizer.anonymize(
                text=text,
                analyzer_results=pii_entities
            )
            return ("MASK", anonymized.text)
        else:
            return ("ALLOW", text)