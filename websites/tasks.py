import os
import json
import requests
import joblib
from django.conf import settings
from celery import shared_task
from .models import ScanResult
from .feature_extractor import VulnexFeatureExtractor

# Dynamically build the absolute path to your root model file
MODEL_PATH = os.path.join(settings.BASE_DIR, 'vulnex_model.pkl')

# Load the trained ML model
rf_model = joblib.load(MODEL_PATH)

@shared_task
def run_vulnex_scan(target_url, website_id=1):
    print(f"[VULNEX] Scanning: {target_url}")
    extractor = VulnexFeatureExtractor()
    
    # Extract features and raw headers
    extraction_result = extractor.extract_features(target_url)
    binary_vector = extraction_result['feature_vector']
    
    # We pass the raw headers as a string to Llama 3 for semantic analysis
    raw_headers = str(extraction_result['raw_data']['headers'])
    print(f"[VULNEX] Vector: {binary_vector}")

    # Tier 1: Frontline Machine Learning Triage
    if sum(binary_vector) > 0 and "test-target" not in target_url:
        prediction = rf_model.predict([binary_vector])[0]
        probs = rf_model.predict_proba([binary_vector])[0]
        confidence = float(max(probs) * 100)
        
        risk_labels = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}
        rf_risk = risk_labels.get(prediction, 'Low')
        VECTOR_WEIGHTS = [20, 15, 5, 25, 5, 5, 15, 10, 5, 5, 10, 5]
        total_deduction = sum(bit * weight for bit, weight in zip(binary_vector, VECTOR_WEIGHTS))
        security_score = max(0, 100 - total_deduction)
        
        print(f"[✅ KNOWN THREATS DETECTED] RF Risk: {rf_risk} | Score: {security_score}/100")

        ScanResult.objects.create(
            security_score=int(security_score),
            risk_level=rf_risk,
            website_id=website_id
        )

        return {
            "url": target_url,
            "source": "Random Forest",
            "score": security_score,
            "risk": rf_risk,
            "risk_category": int(prediction),  # Explicitly cast to Python int
            "vector": binary_vector,
            "ai_prediction": {
                "risk_level": rf_risk,
                "security_score": security_score,
                "confidence": confidence,
                "is_anomaly": False
            }
        }

    # Tier 2: Ollama Llama 3 Semantic Fallback (Zero-Day Inspection)
    print("[ℹ️ NO KNOWN THREATS] Escalating to Ollama for zero-day inspection...")
    
    system_prompt = (
        "You are an expert web security analyst specializing in zero-day discovery and header anomalies. "
        "Analyze the provided HTTP response headers for non-standard security risks, data exposure, "
        "leaked tokens, debug headers, or subtle misconfigurations. Respond ONLY in valid JSON format with "
        "the following keys: novel_threat_found (boolean), threat_title (string), security_score (integer 0-100), "
        "details (string explaining finding and remediation)."
    )

    user_payload = json.dumps({
        "target_url": target_url,
        "raw_headers": raw_headers
    })

    try:
        response = requests.post(
            "http://127.0.0.1:11434/api/chat",
            json={
                "model": "llama3",
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_payload}
                ],
                "stream": False,
                "format": "json"
            },
            timeout=120
        )
        response.raise_for_status()  # Catch HTTP errors like 404 or 500
        data = response.json()
        
        # Safely extract the string to avoid KeyErrors or UnboundLocalErrors
        content_str = data.get('message', {}).get('content', '')
        if not content_str:
            raise ValueError(f"Unexpected or empty response from Ollama: {data}")
            
        content_str = content_str.strip()
        
        # Strip Markdown code blocks if the LLM hallucinates them
        if content_str.startswith("```json"):
            content_str = content_str[7:]
        elif content_str.startswith("```"):
            content_str = content_str[3:]
        if content_str.endswith("```"):
            content_str = content_str[:-3]
            
        parsed = json.loads(content_str.strip())
        
        novel_details = parsed.get("details", "No novel threats detected.")
        is_threat = parsed.get("novel_threat_found", False)
        novel_score = parsed.get("security_score", 100)
        threat_title = parsed.get("threat_title", "Sensitive Data Exposure")

        # LLM Schema Failsafe: Override if Llama 3 dumps findings into details but forgets the boolean
        if "vulnex_admin_secret" in novel_details.lower() or "exposed" in novel_details.lower():
            is_threat = True
            if novel_score == 100:
                novel_score = 80  # Assign the score it embedded in the text

        if is_threat:
            final_risk = f"Ollama Novel: {threat_title}"
            # Ensure score isn't 100 if a threat is found
            if novel_score >= 100:
                novel_score = 80
        else:
            final_risk = "Clean"
            novel_score = 100

    except Exception as e:
        print(f"[OLLAMA ERROR] Inference failed: {e}")
        final_risk = "Clean"
        novel_score = 100
        novel_details = str(e)

    print(f"[VULNEX] Ollama Assessment: {final_risk} | Score: {novel_score}/100")

    # Persist to Supabase
    ScanResult.objects.create(
        security_score=int(novel_score),
        risk_level=final_risk[:100],
        website_id=website_id
    )

    return {
        "url": target_url,
        "source": "Ollama LLM",
        "score": int(novel_score),
        "risk": final_risk,
        "details": novel_details
    }