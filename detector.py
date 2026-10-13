# detector.py - finds sensitive data using Python regular expressions.
import re

def detect(text, rules):
    """rules = active rows from SecurityRules joined with category info.
    Returns {category_id: {"name":..., "weight":..., "count":...}}"""
    found = {}
    for rule in rules:
        matches = re.findall(rule["regex_pattern"], text, flags=re.IGNORECASE)
        if matches:
            item = found.setdefault(rule["category_id"], {
                "name": rule["category_name"], "weight": rule["severity_weight"], "count": 0})
            item["count"] += len(matches)
    return found

def risk_level(found):
    """Simple rule: highest severity weight found decides the risk."""
    if not found:
        return "Low"
    top = max(item["weight"] for item in found.values())
    return {3: "High", 2: "Medium"}.get(top, "Low")
