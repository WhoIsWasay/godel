import re
import json

class OutputExtractor:
    @staticmethod
    def parse_z3_counterexample(z3_output: str) -> dict:
        """
        Parses Z3 model outputs to find variable assignments securely.
        Looks specifically for lines containing '=' or '->'.
        """
        extracted_variables = {}
        if not z3_output:
            return extracted_variables

        # Require a definitive assignment operator (= or ->) flanked by the variable and value
        pattern = r"([a-zA-Z0-9_]+)\s*(?:=Updated|=>|=Position|=|-?\>)\s*(-?[a-zA-Z0-9_x]+)"
        matches = re.findall(pattern, z3_output)

        # Filter out known log words to avoid noise
        banned_keys = {"BUG", "FOUND", "Z3", "Counterexample", "Model", "dimensions", "sat", "unsat"}

        for var_name, value in matches:
            if var_name in banned_keys:
                continue
            
            # Clean up numeric values if they are digits (sign included)
            if value.lstrip("-").isdigit():
                extracted_variables[var_name] = int(value)
            elif value.startswith("0x"):
                extracted_variables[var_name] = value
            else:
                # Only keep text values if they don't look like noisy split words
                if len(value) > 1 or value.isdigit():
                    extracted_variables[var_name] = value

        return extracted_variables

    @staticmethod
    def parse_slither_json(slither_json_str: str, target_function: str) -> dict:
        """
        Parses raw Slither JSON results to isolate structural metrics 
        matching our target function name.
        """
        extracted_facts = {
            "vulnerability_found": False,
            "detector_name": None,
            "impact": None,
            "line_numbers": [],
            "description": ""
        }
        
        if not slither_json_str:
            return extracted_facts

        try:
            data = json.loads(slither_json_str)
        except Exception:
            # Fallback if Slither output is raw text instead of structured JSON
            if target_function in slither_json_str:
                extracted_facts["vulnerability_found"] = True
                extracted_facts["description"] = "Raw trace signature matched target function."
            return extracted_facts

        results = data.get("results", {})
        detectors = results.get("detectors", [])

        for detector in detectors:
            description = detector.get("description", "")
            
            # Check if this specific detector flag references our sandboxed function
            if target_function in description or f".{target_function}(" in description:
                extracted_facts["vulnerability_found"] = True
                extracted_facts["detector_name"] = detector.get("check", "unknown")
                extracted_facts["impact"] = detector.get("impact", "unknown")
                extracted_facts["description"] = description
                
                # Extract line numbers from source mapping elements
                first_element = detector.get("first_markdown_element", "")
                lines = re.findall(r"#L(\d+)", first_element)
                if lines:
                    extracted_facts["line_numbers"] = list(set([int(l) for l in lines]))
                
                # Stop at the first significant matching rule violation
                break

        return extracted_facts