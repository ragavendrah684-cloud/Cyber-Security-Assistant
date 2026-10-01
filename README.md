# Cybersecurity Assistant

A small educational dashboard for basic URL indicators and explicitly authorized TCP port checks. URL analysis is performed on the submitted text only; it does not visit the destination. Port checks use ordinary TCP connections with a short timeout. These tools are not a substitute for a professional security assessment, and a low-risk URL result is not a guarantee that a site is safe.

Only scan hosts you own or have explicit permission to test.

## Requirements

- Python 3.10 or newer
- PowerShell on Windows

## Install and run the backend (Windows PowerShell)

1. Install Python from [python.org](https://www.python.org/downloads/) if it is not already installed. During installation, enable the Python launcher (`py`).
2. Open the `CyberSecurity-Assistant` project folder in VS Code, then open a PowerShell terminal.
3. Create and activate a virtual environment:

   ```powershell
   cd backend
   py -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, allow it only in the current terminal process, then activate the environment again:

   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\venv\Scripts\Activate.ps1
   ```

   This process-scoped setting is temporary and does not change the machine-wide execution policy. Alternatively, run commands with `venv\Scripts\python.exe` without activating the environment.

4. Install the packages:

   ```powershell
   pip install -r requirements.txt
   ```

5. Start FastAPI from the `backend` directory:

   ```powershell
   uvicorn main:app --reload
   ```

   The API is available at <http://127.0.0.1:8000>. Keep this terminal open while using the app.

## Open the web application

In a second PowerShell terminal, serve the static frontend locally:

```powershell
cd frontend
py -m http.server 5500
```

Open <http://127.0.0.1:5500> in a browser. The API allows this localhost development origin through CORS. Do not open `index.html` directly as a `file://` URL.

The FastAPI interactive documentation is at <http://127.0.0.1:8000/docs>; ReDoc is at <http://127.0.0.1:8000/redoc>.

## Try the checks

- **URL checker:** enter a URL such as `https://example.com` and choose **Check URL**. The result reports the protocol, hostname, basic heuristic risk level, warnings, and recommendations. Try `http://192.0.2.1/login` to see some example indicators. The checker never requests the URL.
- **Port scanner:** use `127.0.0.1` as the host and ports such as `22,80,443`. Check the authorization confirmation before choosing **Scan Ports**. Results list each requested port as open, closed, or an error. Only use hosts for which you have permission.
- **Tests:** from the `backend` directory, run `py -m unittest discover -s tests`. The port-scan test opens a temporary local listener on `127.0.0.1`; no external systems are tested.

### Screenshot analyzer

Choose a PNG, JPG, or WebP screenshot (up to 5 MB) and select **Analyze Screenshot**. Tesseract.js extracts visible English text in the browser, checks common scam wording, and submits any recognized URLs to the local URL checker. The image itself is not uploaded. The first use downloads the OCR engine and English language data from jsDelivr and the Tesseract language-data host, so an internet connection is needed for the initial OCR run. OCR may miss or misread text; it cannot inspect hidden links, verify logos, or prove that an image or site is safe.

## API overview

- `GET /` and `GET /health` provide service status.
- `POST /security-check` accepts `{ "url": "https://example.com" }`.
- `POST /scan` accepts `{ "host": "127.0.0.1", "ports": "22,80,443", "confirm_authorized": true }`. Up to 50 unique TCP ports may be supplied as a comma-separated list.
- The existing `GET /scan` local machine security summary remains available for backward compatibility.
