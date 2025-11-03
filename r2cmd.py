import json
import uuid
import random

# Definition of the r2cmd tool
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
    
    # Update the system message with the r2cmd description
    system_msg = messages[0]
    system_msg["content"] += "\n\nAvailable tool:\n- r2cmd: Execute radare2 commands. Usage: `r2cmd <command>`"
    
    # Take the command from the original assistant response
    user_msg = messages[1]
    assistant_msg = messages[2]
    content = assistant_msg["content"]
    
    # Handle cases where content might be NaN or non-string
    if isinstance(content, str):
        r2_command = content.strip()
    else:
        # Skip entries with non-string content (like NaN)
        return None
    
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

# Load the original dataset
with open("./data/radare2/radare2_train.jsonl", "r") as f:
    original_entries = [json.loads(line) for line in f]

# Convert and shuffle the entries
converted_dataset = [convert_entry(entry) for entry in original_entries]
converted_dataset = [entry for entry in converted_dataset if entry is not None]  # Filter out None entries
random.shuffle(converted_dataset)  # Shuffle randomly

# Save the shuffled dataset
with open("./data/radare2/function_calling_r2cmd_dataset.jsonl", "w") as f:
    for entry in converted_dataset:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
