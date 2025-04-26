import json
import uuid
import random  # Nuovo import per lo shuffling

# Definizione dello strumento r2cmd
tools = [
    {
        "type": "function",
        "function": {
            "name": "r2cmd",
            "description": "Execute a radare2 command and return the output.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The radare2 command to execute (e.g., 'CCf~cases', 'pdf', 'afl')."
                    }
                },
                "required": ["command"]
            }
        }
    }
]

def convert_entry(original_entry):
    messages = original_entry["messages"]
    
    # Aggiorna il system message con la descrizione di r2cmd
    system_msg = messages[0]
    system_msg["content"] += "\n\nAvailable tool:\n- r2cmd: Execute radare2 commands. Usage: `r2cmd <command>`"
    
    # Prendi il comando dalla risposta dell'assistente originale
    user_msg = messages[1]
    assistant_msg = messages[2]
    r2_command = assistant_msg["content"].strip()  # Es: "CCf~cases"
    
    call_id = f"call{uuid.uuid4().hex[:5]}"
    
    new_messages = [
        system_msg,
        user_msg,
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": "r2cmd",
                        "arguments": json.dumps({"command": r2_command})
                    }
                }
            ]
        },
        {
            "role": "tool",
            "name": "r2cmd",
            "content": r2_command,
            "tool_call_id": call_id
        },
        {
            "role": "assistant",
            "content": f"Command executed: `{r2_command}`\nResult:\n{r2_command}"
        }
    ]
    
    return {
        "messages": new_messages,
        "tools": tools
    }

# Carica il dataset originale
with open("./r2ai-model/data/radare2/radare2_train.jsonl", "r") as f:
    original_entries = [json.loads(line) for line in f]

# Converti e rimescola le entry
converted_dataset = [convert_entry(entry) for entry in original_entries]
random.shuffle(converted_dataset)  # Rimescola casualmente

# Salva il dataset shuffled
with open("./r2ai-model/data/radare2/function_calling_r2cmd_dataset.jsonl", "w") as f:
    for entry in converted_dataset:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
