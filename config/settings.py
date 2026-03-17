# config/settings.py

# Thresholds - LOWERED for better detection
INJECTION_THRESHOLD = 0.7  # Changed from 0.7
PATTERN_WEIGHT = 0.7       # Increased pattern importance
ANOMALY_WEIGHT = 0.3       # Decreased anomaly importance

# Original suspicious keywords
SUSPICIOUS_KEYWORDS = [
    "ignore previous instructions",
    "ignore all instructions",
    "reveal system prompt",
    "reveal hidden instructions",
    "bypass safety",
    "bypass restrictions",
    "developer mode",
    "jailbreak",
    "dan mode",
    "do anything now",
    "system prompt",
    "hidden instructions"
]

# INSTRUCTION_OVERRIDE patterns - EXPANDED
INSTRUCTION_OVERRIDE = [
    "ignore previous instructions",
    "ignore all instructions", 
    "ignore instructions",
    "forget instructions",
    "forget rules",
    "disregard guidelines",
    "disregard instructions",
    "override instructions",
    "override rules",
    "system override",
    "ignore your instructions",
    "do not follow",
    "disregard previous",
    "ignore above",
    "ignore",           # Added broader patterns
    "disregard",
    "override",
    "forget",
    "do not follow"
]

# JAILBREAK_PATTERNS - EXPANDED
JAILBREAK_PATTERNS = [
    "pretend you are",
    "act as if",
    "you are now",
    "role play",
    "unrestricted mode",
    "developer mode",
    "jailbreak",
    "dan mode",
    "do anything now",
    "no restrictions",
    "without rules",
    "unfiltered mode",
    "bypass safety",
    "bypass restrictions",
    "pretend",          # Added broader patterns
    "act as",
    "role play",
    "unrestricted",
    "no filters",
    "bypass",
    "bypass all restrictions",
"bypass restrictions"
]

# EXTRACTION_ATTEMPTS - EXPANDED
EXTRACTION_ATTEMPTS = [
    "output your prompt",
    "reveal instructions",
    "reveal prompt",
    "what are your rules",
    "what are your instructions",
    "system prompt",
    "initial instructions",
    "hidden instructions",
    "tell me your prompt",
    "show your prompt",
    "display your instructions",
    "what rules do you follow",
    "how were you programmed",
    "system prompt",    # Added broader patterns
    "instructions",
    "rules",
    "guidelines",
    "configuration",
    "your prompt"
]

# PII settings
PII_ENTITIES = ["PHONE_NUMBER", "EMAIL_ADDRESS", "API_KEY", "INTERNAL_ID"]

# Context terms for confidence boosting
CONTEXT_TERMS = {
    "EMPLOYEE_ID": ["employee", "staff", "hr", "personnel", "worker", "id", "identification"],
    "API_KEY": ["api", "key", "token", "secret", "authentication", "credentials"],
    "CREDENTIAL_PAIR": ["username", "password", "login", "credentials"]
}

# Logging
LOG_FILE = "logs/gateway_logs.txt"