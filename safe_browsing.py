"""
safe_browsing.py
Optional integration with Google Safe Browsing API v4 (free tier).
Get a free API key here: https://developers.google.com/safe-browsing/v4/get-started

If no key is provided, the app gracefully skips this check and relies
only on heuristics.py — so the project still works out of the box.
"""

import requests

SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


def check_safe_browsing(url: str, api_key: str) -> dict:
    """
    Returns:
        {"checked": True, "malicious": bool, "threats": [...]}  on success
        {"checked": False, "error": "..."}                      on failure
    """
    if not api_key:
        return {"checked": False, "error": "No API key provided"}

    payload = {
        "client": {"clientId": "url-safety-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        resp = requests.post(
            SAFE_BROWSING_URL,
            params={"key": api_key},
            json=payload,
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        threats = [m.get("threatType") for m in matches]
        return {"checked": True, "malicious": len(matches) > 0, "threats": threats}
    except requests.exceptions.RequestException as e:
        return {"checked": False, "error": str(e)}
