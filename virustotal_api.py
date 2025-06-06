# virustotal_api.py
import requests

def check_virustotal(url, api_key):
    headers = {"x-apikey": api_key}
    params = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=params)

    if response.status_code == 200:
        url_id = response.json()['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
        analysis = requests.get(analysis_url, headers=headers).json()
        stats = analysis['data']['attributes']['stats']
        return stats
    else:
        return {"error": "Failed to query VirusTotal"}
