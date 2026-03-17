# main.py

import time
import logging
import os
from injection_detection.detector import detect_injection
from presidio_module.pii_analyzer import analyze_pii
from policy_engine.decisions import policy_decision

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Setup logging
logging.basicConfig(
    filename='logs/gateway_logs.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

def gateway(user_input):
    start_time = time.time()
    
    # Step 1: Detect injection
    injection_score = detect_injection(user_input)
    
    # Step 2: Detect PII
    pii_entities = analyze_pii(user_input)
    
    # Step 3: Policy decision
    decision, output = policy_decision(user_input, injection_score, pii_entities)
    
    # Step 4: Log
    latency = (time.time() - start_time) * 1000
    logging.info(f"Input: {user_input[:50]}... | Score: {injection_score:.2f} | "
                f"PII: {len(pii_entities)} | Decision: {decision} | Latency: {latency:.2f}ms")
    
    return decision, output, latency

if __name__ == "__main__":
    print("=" * 50)
    print("🔒 LLM SECURITY GATEWAY")
    print("=" * 50)
    
    while True:
        text = input("\nYou: ")
        if text.lower() in ['quit', 'exit', 'q']:
            break
            
        decision, output, latency = gateway(text)
        print(f"\nDecision: {decision}")
        print(f"Output: {output}")
        print(f"Latency: {latency:.2f}ms")
        print("-" * 50)