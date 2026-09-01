import csv
import requests
# Ensure this points to your actual vector generation function
# from your_scanner_module import generate_12_bit_vector 

def update_dataset():
    with open('trusted_domains.txt', 'r') as file:
        # NEW CODE
# This splits the text by spaces and grabs ONLY the very last item (the domain)
        domains = [line.split()[-1].strip() for line in file if line.strip()]

    with open('training_data.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        for domain in domains:
            url = f"https://{domain}"
            try:
                print(f"Scanning {url}...")
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                response = requests.get(url, headers=headers, timeout=5)
                
                # REPLACE THIS with your actual vector function
                # vector = generate_12_bit_vector(response.headers)
                vector = [1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1] # Mock vector
                
                writer.writerow(vector + ['Low'])
            except requests.RequestException:
                print(f"Skipping {domain} - Connection failed.")

if __name__ == "__main__":
    update_dataset()