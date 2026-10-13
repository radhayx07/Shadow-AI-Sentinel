# redactor.py - replaces sensitive values with placeholders like [REDACTED_EMAIL].
import re

def redact(text, rules):
    for rule in rules:
        placeholder = "[REDACTED_" + rule["category_name"].upper().replace(" ", "_") + "]"
        text = re.sub(rule["regex_pattern"], placeholder, text, flags=re.IGNORECASE)
    return text
