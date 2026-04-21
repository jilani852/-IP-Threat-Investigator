from flask import Flask
from virustotal import get_threat_ip_details_extra

app = Flask(__name__)

@app.route("/")
def welcome():
    return """
    <html>
    <head>
        <title>IP Threat Investigator</title>
        <style>
            body {{
                font-family: Arial;
                max-width: 800px;
                margin: 100px auto;
                text-align: center;
            }}
            h1 {{ color: #333; }}
            p  {{ color: #666; font-size: 16px; }}
            #warning {{
                font-weight: bold;
                color: red;
                font-size: 14px;
            }}
            input {{
                padding: 12px 20px;
                font-size: 16px;
                border: 1px solid #ccc;
                border-radius: 6px;
                width: 300px;
                margin-right: 10px;
            }}
            .btn {{
                padding: 12px 30px;
                background-color: #0066cc;
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 16px;
                cursor: pointer;
            }}
        </style>
    </head>
    <body>
        <h1>IP Threat Investigator</h1>
        <p>Enter any IP address to get a full threat intelligence report
           powered by VirusTotal.</p>
        <p id="warning">This tool is meant for educational purposes and security awareness only.</p>

        <form onsubmit="return handleSubmit(event)">
            <input type="text" id="ip" placeholder="e.g. 195.168.1.0">
            <button type="submit" class="btn">Scan IP</button>
        </form>

        <script>
        function handleSubmit(event) {{
            event.preventDefault();
            const ip = document.getElementById("ip").value;
            if (validate(ip)) {{
                window.location.href = "/scan/" + ip;
            }}
        }}

        function validate(ip) {{
            const segments = ip.split(".");
            if (segments.length !== 4) {{
                alert("Invalid IP - must have 4 parts separated by dots");
                return false;
            }}
            for (let i = 0; i < segments.length; i++) {{
                const num = Number(segments[i]);
                if (isNaN(num) || num < 0 || num > 255 || segments[i] === "") {{
                    alert("Invalid IP - each part must be between 0 and 255");
                    return false;
                }}
            }}
            return true;
        }}
        </script>
    </body>
    </html>
    """

@app.route("/scan/<ip>")
def scan(ip):
    data = get_threat_ip_details_extra(ip)
    
    if not data:
        return "<h1>Error: Could not retrieve data for this IP</h1>"
    
    result = data[0]

    if result["malicious"] == 0:
        color = "#2ecc71"
    elif result["malicious"] <= 5:
        color = "#f39c12"
    else:
        color = "#e74c3c"

    engines_html = ""
    for engine_name, engine_data in result["engines"].items():
        if engine_data["category"] == "malicious":
            engines_html += f"""
            <p style="color:red;">⚠ {engine_name} → {engine_data["result"]}</p>
            """
    if engines_html == "":
        engines_html = "<p style='color:green;'>✓ No engines flagged this IP</p>"

    card = f"""
    <div style="border: 1px solid #ccc; border-radius: 8px; margin: 20px 0;">

        <div style="background:{color}; padding:15px; border-radius:8px 8px 0 0;">
            <h2 style="margin:0; color:white;">{result["ip"]}</h2>
            <span style="color:white;">{result["country"]}</span> |
            <span style="color:white;">{result["owner"]}</span> |
            <span style="color:white;">ASN: {result["asn"]}</span> |
            <span style="color:white;">Network: {result["network"]}</span>
        </div>

        <div style="display:flex;">
            <div style="flex:1; padding:15px; border-right:1px solid #eee;">
                <h3>Stats</h3>
                <p>Malicious: {result["malicious"]}</p>
                <p>Harmless: {result["harmless"]}</p>
                <p>Suspicious: {result["suspicious"]}</p>
                <p>Reputation: {result["reputation"]}</p>
            </div>
            <div style="flex:1; padding:15px;">
                <h3>Community</h3>
                <p>Votes malicious: {result["votes_malicious"]}</p>
                <p>Votes harmless: {result["votes_harmless"]}</p>
                <p>Last scan: {result["last_scan"]}</p>
            </div>
        </div>

        <div style="padding:15px; border-top:1px solid #eee;">
            <h3>Engines that flagged this IP</h3>
            {engines_html}
        </div>

    </div>
    """

    return f"""
    <html>
    <head>
        <title>IP Threat Investigator</title>
        <style>
            body {{ font-family: Arial; max-width: 900px; margin: 40px auto; }}
            h1 {{ color: #333; text-align: center; }}
            h3 {{ color: #555; margin-top: 0; }}
        </style>
    </head>
    <body>
        <h1>Scan Results</h1>
        <a href="/" style="display:inline-block; margin-bottom:20px;">← Scan another IP</a>
        <div>{card}</div>
    </body>
    </html>
    """

if __name__ == "__main__":
    app.run(debug=True)