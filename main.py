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
    target_url = f"https://cve.circl.lu/api/search/{query}"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(target_url)
            # Parse out the top 3 items to return to the frontend
            data = response.json()
            results = data if isinstance(data, list) else data.get("results", [])
            
            sanitized_results = []
            for item in results[:3]:
                sanitized_results.append({
                    "id": item.get("id", "Unknown"),
                    "summary": item.get("summary", "No definition listed."),
                    "cvss": item.get("cvss", "Unranked")
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
