from celery import shared_task
from .feature_extractor import VulnexFeatureExtractor

@shared_task
def run_vulnex_scan(target_url, scan_id=1):
    """
    Asynchronous Celery task that executes the AI Feature Extractor 
    against a target URL.
    """
    print(f"\n[VULNEX CELERY] Received background scan request #{scan_id} for: {target_url}")
    
    # 1. Instantiate the extractor
    extractor = VulnexFeatureExtractor(timeout=5)
    
    # 2. Run the real probe
    results = extractor.extract_features(target_url)
    
    # 3. Log the extracted vector in the Celery worker terminal
    print(f"[VULNEX CELERY] Scan #{scan_id} Complete!")
    print(f"[VULNEX CELERY] Extracted Vector: {results['feature_vector']}")
    print(f"[VULNEX CELERY] Summary: {results['vulnerability_dict']}\n")
    
    # Return the dictionary so Celery stores the result state
    return results