import csv
import sys
import os

# Ensure the root project path is visible
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from websites.feature_extractor import VulnexFeatureExtractor

def update_dataset():
    extractor = VulnexFeatureExtractor(timeout=5)

    with open('trusted_domains.txt', 'r') as file:
        # Strip ranking numbers and clean whitespace
        domains = [line.split()[-1].strip() for line in file if line.strip()]

    # Limit to the first 150-200 domains so it finishes in 2-3 minutes
    target_domains = domains[:150]

    with open('training_data.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        for domain in target_domains:
            url = f"https://{domain}"
            print(f"Scanning {url}...")
            
            try:
                # 1. Run actual feature extraction
                scan_result = extractor.extract_features(url)
                real_vector = scan_result['feature_vector']
                
                # 2. Append genuine feature vector labeled as 'Low'
                writer.writerow(real_vector + ['Low'])
                print(f"✅ Added: {real_vector} -> Low")
                
            except Exception as e:
                print(f"❌ Skipping {domain} - Error: {e}")

if __name__ == "__main__":
    update_dataset()