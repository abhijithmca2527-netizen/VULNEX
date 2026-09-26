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
    if sum(binary_vector) > 0:
        prediction = rf_model.predict([binary_vector])[0]
        probs = rf_model.predict_proba([binary_vector])[0]
        confidence = float(max(probs) * 100)
        
        risk_labels = {0: 'Low', 1: 'Medium', 2: 'High', 3: 'Critical'}
        rf_risk = risk_labels.get(prediction, 'Low')
        security_score = round(100 - (prediction * 25 + (100 - confidence) * 0.1), 2)
        
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
            "risk_category": prediction,
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
            "http://localhost:11434/api/chat",
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
        
        data = response.json()
        parsed = json.loads(data['message']['content'])
        
        if parsed.get("novel_threat_found", False):
            final_risk = f"Ollama Novel: {parsed.get('threat_title', 'Anomaly Detected')}"
            novel_score = parsed.get("security_score", 70)
        else:
            final_risk = "Clean"
            novel_score = 100

        novel_details = parsed.get("details", "No novel threats detected.")

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