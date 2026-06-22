
def score_severity(message):
        if "brute force" in message:
            return "Critical"
        elif "Unknown user" in message:
            return "High" 
        elif "Authentication issue" in message:
            return "Medium"
        else:
            return "Low"

