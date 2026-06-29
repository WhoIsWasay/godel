# domain/slither_runner.py

import subprocess
import json
import os

def run_slither(contract_path: str) -> dict:
    """Runs Slither static analysis on a Solidity contract file."""
    
    try:
        result = subprocess.run(
        ["python", "-m", "slither", contract_path, "--json", "-"],
        capture_output=True,
        text=True,
        timeout=60
) 
        # Slither returns exit code 0 (no findings) or 1 (findings found)
        # Both are valid runs — not errors
        if result.stdout:
            output = json.loads(result.stdout)
            findings = output.get("results", {}).get("detectors", [])
            
            return {
                "status": "success",
                "findings_count": len(findings),
                "findings": [
                    {
                        "check": f["check"],
                        "impact": f["impact"],
                        "confidence": f["confidence"],
                        "description": f["description"],
                        "elements": f.get("elements", [])
                    }
                    for f in findings
                ],
                "error": None
            }
        else:
            return {
                "status": "error",
                "findings_count": 0,
                "findings": [],
                "error": result.stderr
            }
            
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "findings_count": 0,
            "findings": [],
            "error": "Slither timed out after 60 seconds"
        }
    except json.JSONDecodeError:
        return {
            "status": "error",
            "findings_count": 0,
            "findings": [],
            "error": "Failed to parse Slither JSON output"
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "findings_count": 0,
            "findings": [],
            "error": "Slither not installed. Run: pip install slither-analyzer"
        }