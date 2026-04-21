import requests
import datetime

def data_fields(data, ip):
    last_scan = data["data"]["attributes"]["last_analysis_date"]
    last_scan_val = datetime.datetime.fromtimestamp(last_scan).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "ip"             : ip,
        "country"        : data["data"]["attributes"]["country"],
        "asn"            : data["data"]["attributes"]["asn"],
        "network"        : data["data"]["attributes"]["network"],
        "malicious"      : data["data"]["attributes"]["last_analysis_stats"]["malicious"],
        "harmless"       : data["data"]["attributes"]["last_analysis_stats"]["harmless"],
        "suspicious"     : data["data"]["attributes"]["last_analysis_stats"]["suspicious"],
        "reputation"     : data["data"]["attributes"]["reputation"],
        "owner"          : data["data"]["attributes"]["as_owner"],
        "votes_malicious": data["data"]["attributes"]["total_votes"]["malicious"],
        "votes_harmless" : data["data"]["attributes"]["total_votes"]["harmless"],
        "last_scan"      : last_scan_val,
        "engines"        : data["data"]["attributes"]["last_analysis_results"]
    }

def get_threat_ip_details_extra(ip):
    try:
        headers = {"x-apikey": ""}#put your api key here 
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=headers)
        data = response.json()
        return [data_fields(data, ip)]
    except:
        return []
"""
if __name__ == "__main__":
    ip = ""
    print(get_threat_ip_details_extra(ip))"""
