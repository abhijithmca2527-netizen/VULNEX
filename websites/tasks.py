from celery import shared_task
from .feature_extractor import VulnexFeatureExtractor
from .ml_engine import VulnexAIEngine

@shared_task
def run_vulnex_scan(target_url, scan_id=1):
    print(f"\n[VULNEX] Scanning: {target_url}")
    
    # 1. Feature Extraction (What you already finished!)
    extractor = VulnexFeatureExtractor(timeout=5)
    extracted_data = extractor.extract_features(target_url)
    binary_vector = extracted_data['feature_vector']
    
    # 2. AI Prediction (The New Step!)
    ai_engine = VulnexAIEngine()
    ai_results = ai_engine.predict_risk(binary_vector)
    
    # 3. Print the final results to Celery
    print(f"[VULNEX] Vector: {binary_vector}")
    print(f"[VULNEX AI] Risk Level: {ai_results['risk_level']} (Confidence: {ai_results['confidence']}%)")
    print(f"[VULNEX] Scan Complete!\n")
    
    return {
        "vector": binary_vector,
        "ai_prediction": ai_results
    }