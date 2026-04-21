import sys
import requests
from report import print_ioc_report

API_URL = "http://127.0.0.1:8000"

def test(indicator: str, force_rag: bool = True, show_evidence: bool = True):
    resp = requests.post(
        f"{API_URL}/ioc/analyze",
        json={"indicator": indicator},
        params={"force_rag": str(force_rag).lower()},
        timeout=600,
        headers={"Content-Type": "application/json"}
    )
    resp.raise_for_status()
    print_ioc_report(resp.json(), show_evidence=show_evidence)

if __name__ == "__main__":
    indicator = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    test(indicator)