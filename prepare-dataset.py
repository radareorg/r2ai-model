import pandas as pd
import json

SYSTEM_PROMPT = """
***RADARE2 MODE: ON***
"""

# Read the TSV file
df = pd.read_csv('data/radare2/radare2_enriched.tsv', sep='\t')

jsonl_data = []
for index in range(len(df)):
    try:
        row = df.iloc[index]
        q = row['q']
        a = row['a']
        
        # Skip rows with NaN values
        if pd.isna(q) or pd.isna(a):
            continue
            
        # Convert to string and skip empty strings
        q_str = str(q).strip()
        a_str = str(a).strip()
        
        if not q_str or not a_str:
            continue
        
        conversation = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": q_str},
            {"role": "assistant", "content": a_str}
        ]
        jsonl_data.append(json.dumps({"messages": conversation}))
        
    except Exception as e:
        print(f"Skipping row {index} due to error: {e}")
        continue

with open('data/radare2/radare2_train.jsonl', 'w') as f:
    for item in jsonl_data:
        f.write(item + '\n')

print(f"Generated {len(jsonl_data)} valid examples")