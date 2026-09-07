"""VULN pack: exposure"""
import uvicorn

def main():
    port = 6379
    # VULN: expose.wildcard-bind
    uvicorn.run("app:api", host="0.0.0.0", port=port)
