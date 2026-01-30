import pandas as pd
import re

def convert_arff_to_csv(arff_path, csv_path):
    with open(arff_path, 'r') as f:
        lines = f.readlines()

    data_start = 0
    headers = []
    
    # Parse headers
    for i, line in enumerate(lines):
        if line.lower().startswith('@attribute'):
            # Extract attribute name (handling quotes)
            match = re.search(r"@attribute\s+'?([^'\s]+)'?", line, re.IGNORECASE)
            if match:
                headers.append(match.group(1))
        elif line.lower().startswith('@data'):
            data_start = i + 1
            break
            
    print(f"Found {len(headers)} columns.")
    print(f"Data starts at line {data_start}.")

    # Read data
    # KDD ARFFs often have no quotes around strings in data section, straightforward CSV
    # Skip lines until data_start
    
    # We can just read the file from data_start info dataframe and assign columns
    try:
        # Use simple file reading to avoid pandas parsing issues with @ lines if we just skip rows
        # But pandas read_csv with skiprows might be easier if format is clean csv below @data
        df = pd.read_csv(arff_path, skiprows=data_start, header=None, names=headers)
        
        # Pre-processing for KDD specifically for our pipeline
        # 1. Decode protocol to ints (TCP=6, UDP=17, SCMP=1)
        if 'protocol_type' in df.columns:
            proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
            df['protocol'] = df['protocol_type'].map(proto_map).fillna(0)
            
        # 2. Sum bytes
        if 'src_bytes' in df.columns and 'dst_bytes' in df.columns:
            df['bytes'] = df['src_bytes'] + df['dst_bytes']
            
        # 3. Rename duration
        if 'duration' in df.columns:
            df.rename(columns={'duration': 'flow_duration'}, inplace=True)
            
        # 4. Map count to packets (loose approximation)
        if 'count' in df.columns:
             df.rename(columns={'count': 'packets'}, inplace=True)

        # 5. Handle label
        if 'class' in df.columns:
             df.rename(columns={'class': 'label'}, inplace=True)
             # Binarize label if needed (normal vs anomaly)
             df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

        print(f"Converted shape: {df.shape}")
        df.to_csv(csv_path, index=False)
        print(f"Saved to {csv_path}")
        
    except Exception as e:
        print(f"Error converting: {e}")

if __name__ == "__main__":
    convert_arff_to_csv("KDDTest+.arff", "data/kdd_converted.csv")
