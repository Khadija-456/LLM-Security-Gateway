# presidio_module/pii_analyzer.py

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer import EntityRecognizer
import re
from config.settings import CONTEXT_TERMS

# ============================================
# CUSTOM RECOGNIZER 1: API Key (you already have this)
# ============================================
class APICustomRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern("API Key Pattern", r"\bAPI-[\w-]{8,}\b", 0.7),  # Made more flexible
        Pattern("Bearer Token", r"Bearer\s+[A-Za-z0-9\-._~+/]+", 0.8),
        Pattern("AWS Key", r"AKIA[0-9A-Z]{16}", 0.9),
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="API_KEY", 
            patterns=self.PATTERNS, 
            name="api_key_custom"
        )
    
    # Add context awareness
    def analyze(self, text, entities, nlp_artifacts):
        results = super().analyze(text, entities, nlp_artifacts)
        
        for result in results:
            # Check surrounding text for context terms
            start = max(0, result.start - 40)
            end = min(len(text), result.end + 40)
            surrounding = text[start:end].lower()
            
            # Boost confidence if context terms nearby
            context_terms = CONTEXT_TERMS.get("API_KEY", [])
            if any(term in surrounding for term in context_terms):
                result.score = min(1.0, result.score + 0.2)
        
        return results

# ============================================
# CUSTOM RECOGNIZER 2: Internal ID (you already have this)
# ============================================
class InternalIDRecognizer(PatternRecognizer):
    PATTERNS = [
        Pattern("Internal ID Pattern", r"\b(ID|EMP|CTR)-\d{6}\b", 0.6),  # Lower base confidence
        Pattern("Employee ID", r"\b\d{6}\b(?=\s*(employee|staff|id))", 0.5)
    ]
    
    def __init__(self):
        super().__init__(
            supported_entity="INTERNAL_ID", 
            patterns=self.PATTERNS, 
            name="internal_id_custom"
        )
    
    # Add context awareness
    def analyze(self, text, entities, nlp_artifacts):
        results = super().analyze(text, entities, nlp_artifacts)
        
        context_terms = CONTEXT_TERMS.get("EMPLOYEE_ID", [])
        
        for result in results:
            # Check surrounding text (50 chars before and after)
            start = max(0, result.start - 50)
            end = min(len(text), result.end + 50)
            surrounding = text[start:end].lower()
            
            # Boost confidence if context terms nearby
            if any(term in surrounding for term in context_terms):
                result.score = min(1.0, result.score + 0.2)
            
            # Apply confidence calibration
            result.score = calibrate_confidence(
                result.entity_type, 
                result.score, 
                result.start, 
                len(text)
            )
        
        return results

# ============================================
# CUSTOM RECOGNIZER 3: Composite Entity Detection (NEW)
# ============================================
class CompositeRecognizer(PatternRecognizer):
    """Detects related groups like credential pairs and addresses"""
    
    def __init__(self):
        patterns = [
            # Credential pairs (username+password together)
            Pattern(
                "credential_pair", 
                r"(username|user|email|login).{0,30}(password|pass|pwd).{0,30}",
                0.9
            ),
            # Address blocks
            Pattern(
                "address_block",
                r"(address|street|road|avenue).{0,50}(city|town|state|zip|postal)",
                0.85
            ),
            # API key with description
            Pattern(
                "api_with_context",
                r"(api[-\s]?key|token|secret).{0,30}[\w-]{16,}",
                0.88
            )
        ]
        super().__init__(
            supported_entity="COMPOSITE_PII", 
            patterns=patterns, 
            name="composite_recognizer"
        )

# ============================================
# Confidence Calibration Function (NEW)
# ============================================
def calibrate_confidence(entity_type, raw_score, position, text_length):
    """Adjust confidence based on various factors"""
    
    calibrated = raw_score
    
    # Factor 1: Position in text (entities at very start/end might be less reliable)
    position_factor = 1.0
    if position < 20:
        position_factor = 0.95  # Slight penalty for very start
    elif position > text_length - 20:
        position_factor = 0.95  # Slight penalty for very end
    
    calibrated *= position_factor
    
    # Factor 2: Entity type specific calibration
    if entity_type == "API_KEY":
        # API keys are usually more reliable when pattern is strong
        if raw_score > 0.8:
            calibrated = min(1.0, calibrated * 1.05)
    
    elif entity_type == "INTERNAL_ID":
        # Internal IDs need more evidence
        if raw_score < 0.7:
            calibrated *= 0.9  # Penalize low confidence IDs
    
    return min(1.0, calibrated)

# ============================================
# Initialize analyzer with ALL customizations
# ============================================

# Create analyzer
analyzer = AnalyzerEngine()

# Add all three custom recognizers
analyzer.registry.add_recognizer(APICustomRecognizer())
analyzer.registry.add_recognizer(InternalIDRecognizer())
analyzer.registry.add_recognizer(CompositeRecognizer())  # NEW

def analyze_pii(text):
    """Main PII analysis function with all customizations"""
    
    # Run analysis
    results = analyzer.analyze(
        text=text,
        entities=["PHONE_NUMBER", "EMAIL_ADDRESS", "API_KEY", "INTERNAL_ID", "COMPOSITE_PII"],
        language="en"
    )
    
    # Apply confidence calibration to all results
    for result in results:
        result.score = calibrate_confidence(
            result.entity_type,
            result.score,
            result.start,
            len(text)
        )
    
    return results