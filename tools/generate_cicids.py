import pandas as pd
import numpy as np
import random

def generate_cicids_sample(num_rows=5000, output_path="data/cicids_sample.csv"):
    """
    Generates a synthetic dataset mimicking CIC-IDS 2017 structure.
    Columns: Flow Duration, Total Fwd Packets, Total Backward Packets, Total Length of Fwd Packets, Total Length of Bwd Packets, Label
    """
    print(f"Generating {num_rows} rows of synthetic CIC-IDS data...")
    
    data = []
    attacks = ['BENIGN', 'DDoS', 'PortScan', 'Bot', 'Infiltration']
    
    for _ in range(num_rows):
        label = np.random.choice(attacks, p=[0.7, 0.1, 0.1, 0.05, 0.05])
        
        if label == 'BENIGN':
            flow_duration = random.randint(100, 10000) # Short normal flows
            fwd_pkts = random.randint(1, 20)
            bwd_pkts = random.randint(1, 20)
            fwd_len = random.randint(64, 1500)
            bwd_len = random.randint(64, 5000)
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1, 1024)
        elif label == 'DDoS':
            flow_duration = random.randint(100000, 5000000) # Long duration spam
            fwd_pkts = random.randint(1000, 5000)
            bwd_pkts = random.randint(0, 10)
            fwd_len = random.randint(64, 100) # Small packets
            bwd_len = 0
            src_port = random.randint(1024, 65535)
            dst_port = 80
        elif label == 'PortScan':
            flow_duration = random.randint(10, 100) # Very short
            fwd_pkts = 2
            bwd_pkts = 0
            fwd_len = 0
            bwd_len = 0
            src_port = random.randint(1024, 65535)
            dst_port = random.randint(1, 65535) # Varying ports
        elif label == 'Bot':
            flow_duration = random.randint(1000, 60000)
            fwd_pkts = random.randint(5, 50)
            bwd_pkts = random.randint(5, 50)
            fwd_len = random.randint(100, 1000)
            bwd_len = random.randint(100, 1000)
            src_port = random.randint(1024, 65535)
            dst_port = 8080
        else: # Infiltration
            flow_duration = random.randint(5000, 100000)
            fwd_pkts = random.randint(10, 100)
            bwd_pkts = random.randint(10, 100)
            fwd_len = random.randint(1000, 50000)
            bwd_len = random.randint(1000, 50000)
            src_port = random.randint(1024, 65535)
            dst_port = 445

        # Map to expected structure for our trainer if possible, or just raw CIC-IDS cols
        row = {
            'Flow Duration': flow_duration,
            'Total Fwd Packets': fwd_pkts,
            'Total Backward Packets': bwd_pkts,
            'Total Length of Fwd Packets': fwd_len,
            'Total Length of Bwd Packets': bwd_len,
            'Source Port': src_port,
            'Destination Port': dst_port,
            'Label': label
        }
        data.append(row)
        
    df = pd.DataFrame(data)
    df.to_csv(output_path, index=False)
    print(f"Saved to {output_path}")

if __name__ == "__main__":
    generate_cicids_sample()
