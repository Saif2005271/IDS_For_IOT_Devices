import requests
import gzip
from pybloom_live import ScalableBloomFilter
def update_from_IoCs():
    
    url = "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/master/abuseipdb-s100-all.ipv4.gz"
    bloom_filename = "malicious.bloom"

    # Initialize a Scalable Bloom Filter
    # initial_capacity: Start small, it will grow automatically
    # error_rate: 0.1% chance of a false positive(false alerts)
    sbf = ScalableBloomFilter(mode=ScalableBloomFilter.SMALL_SET_GROWTH, error_rate=0.001)

    print("Starting download and processing...")

    try:
        # Get the file as a stream saves ram by processing in bit chunks instead all at once
        response = requests.get(url, stream=True)
        response.raise_for_status() #ensure the download actually worked before processing data

        # Open the Gzip stream directly
        with gzip.open(response.raw, 'rt', encoding='utf-8') as f:
            count = 0
            for line in f:
                # Clean the line: remove whitespace/newlines
                line = line.strip()

                # Skip empty lines or comments (lines starting with #)
                if not line or line.startswith('#'):
                    continue
                
                # Add IP to the Bloom Filter
                sbf.add(line)
                count += 1

        print(f"Processed {count} IPs.")

        # Save the Bloom Filter to a file
        with open(bloom_filename, "wb") as f:
            sbf.tofile(f)

        print(f"Bloom filter saved successfully to: {bloom_filename}")

    except Exception as e:
        print(f"An error occurred: {e}")