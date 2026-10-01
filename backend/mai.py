from fastapi import FastAPI

app = FastAPI(
    title="CyberSecurity Assistant",
    description="Security analysis assistant",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "app": "CyberSecurity Assistant",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }