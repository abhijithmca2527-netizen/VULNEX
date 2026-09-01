from celery import shared_task
from .feature_extractor import VulnexFeatureExtractor
from .ml_engine import VulnexAIEngine
from .models import ScanResult, SandboxThreat

@shared_task
def run_vulnex_scan(target_url, scan_id=1):
    print(f"\n[VULNEX] Scanning: {target_url}")
    
    extractor = VulnexFeatureExtractor(timeout=5)
    extracted_data = extractor.extract_features(target_url)
    binary_vector = extracted_data['feature_vector']
    
    ai_engine = VulnexAIEngine()
    ai_results = ai_engine.predict_risk(binary_vector)
    
    risk_level = ai_results['risk_level']
    security_score = ai_results['security_score']
    is_anomaly = ai_results['is_anomaly']
    
    print(f"[VULNEX] Vector: {binary_vector}")
    print(f"[VULNEX] Risk: {risk_level} | Security Score: {security_score}/100")
    
    if is_anomaly:
        print("[🚨 ANOMALY DETECTED] Sending to Quarantine Sandbox...")
        SandboxThreat.objects.create(
            target_url=target_url,
            feature_vector=str(binary_vector),
            rf_predicted_risk=risk_level
        )
    else:
        print("[✅ NORMAL PATTERN] Saving to standard scan history...")
        ScanResult.objects.create(
            target_url=target_url,
            feature_vector=str(binary_vector)
        )
    
    return {
        "vector": binary_vector,
        "ai_prediction": ai_results
    }