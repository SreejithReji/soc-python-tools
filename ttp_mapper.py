import json

def lookup_ttp(technique_id):
    with open(r"D:\Python\Phase 3 Project\enterprise-attack.json", "r", encoding="utf-8") as file:
        data = json.load(file)

    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    if ref.get("external_id") == technique_id:
                         
                        return {
                            "name": obj.get("name"),
                            "tactic": obj.get("kill_chain_phases", [{}])[0].get("phase_name", "unknown"),
                             "url": f"https://attack.mitre.org/techniques/{technique_id}/"
                            }

    return None
