import httpx
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SecOps Portfolio Backend Engine", version="1.0.0")

# CRITICAL: This allows your frontend index.html to communicate safely with your backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to your production domain name later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock server-side logs simulating your real Security Log Analyzer database
MOCK_SERVER_LOGS = [
    "2026-05-17T07:12:04Z [INFO] Outbound secure proxy tunnel connection initialized.",
    "2026-05-17T07:15:22Z [WARN] SQL Injection pattern match caught on endpoint parameters.",
    "2026-05-17T07:18:41Z [CRITICAL] Web Application Firewall dropped payload matching cross-site scripting signatures.",
    "2026-05-17T07:22:15Z [INFO] Database configuration baseline hashes validated. Integrity intact."
]

@app.get("/")
def read_root():
    return {"status": "Operational", "engine": "Python Full-Stack SecOps Pipeline"}

@app.get("/api/v1/cve")
async def get_cve_data(query: str = Query(..., min_length=2)):
    """Acts as a secure backend proxy connecting to public threat databases."""
    # FIXED: Replaced the dead circl.lu endpoint with the official NVD API
    target_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={query}"
    
    async with httpx.AsyncClient() as client:
        try:
            # Added a standard User-Agent header so NVD doesn't block the request
            headers = {"User-Agent": "SecOpsPortfolioApp/1.0"}
            response = await client.get(target_url, headers=headers)
            
            if response.status_code != 200:
                return {"results": [], "error": f"NVD API responded with status {response.status_code}"}
                
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            sanitized_results = []
            # Parse out the top items to return to the frontend matching your expected format
            for item in vulnerabilities[:3]:
                cve_data = item.get("cve", {})
                descriptions = cve_data.get("descriptions", [])
                summary = descriptions[0].get("value", "No definition listed.") if descriptions else "No definition listed."
                
                # Extract CVSS score if available
                metrics = cve_data.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                cvss_score = cvss_v3[0].get("cvssData", {}).get("baseScore", "Unranked") if cvss_v3 else "Unranked"

                sanitized_results.append({
                    "id": cve_data.get("id", "Unknown"),
                    "summary": summary,
                    "cvss": cvss_score
                })
                
            return {"results": sanitized_results}
        except Exception as e:
            return {"results": [], "error": str(e)}

@app.get("/api/v1/logs")
def get_filtered_logs(grep: str = ""):
    """Simulates server-side logic from your Security Log Analyzer project."""
    if not grep:
        return MOCK_SERVER_LOGS
    
    # Process filtering completely on the Python server side
    filtered = [log for log in MOCK_SERVER_LOGS if grep.lower() in log.lower()]
    return filtered
