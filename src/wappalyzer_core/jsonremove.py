import json, ast

def parse_loose_json(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        text = text.replace("null", "None")
        return ast.literal_eval(text)

with open('categories.json') as f:
    raw_data = f.read()
    
    data = parse_loose_json(raw_data)
    print(json.dumps(data, indent=4))
