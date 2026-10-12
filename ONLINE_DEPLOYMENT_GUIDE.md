# SecureLand — Online Deployment Guide

## Important before publishing
This is an educational prototype, not an official government system. Do not upload real land-record data, citizen personal data, confidential evidence, or sensitive files to a public demo.

This project currently uses a local SQLite database and local `evidence/` folder. On hosted platforms, local files may be temporary and can be lost when the app restarts/redeploys. Use sample/demo data only. Do not promise durable storage or production security.

## Deploy with Streamlit Community Cloud
1. Sign in to GitHub and create a **private** repository named `SecureLand` (public is not recommended for sensitive code/config).
2. Extract this ZIP on your computer.
3. Upload the contents of the `SecureLand_Stable_Project` folder to the repository root (so `app.py`, `database.py`, `forensics.py`, and `requirements.txt` are at the root).
4. Open Streamlit Community Cloud and connect your GitHub account.
5. Choose the repository, branch, and main file path `app.py`; click Deploy.
6. Once deployment completes, copy the HTTPS app URL provided by Streamlit. That is the Prototype/Demo Link for the application form.

## Demo login
The current app has demo-only defaults:
- Admin / admin123
- Talathi / talathi123
- Citizen / citizen123

These are not safe for a public deployment. Before deploying, configure strong credentials using the platform's secrets/environment settings, or remove login-based access until secure authentication is implemented. Never use the demo passwords for real users.

## Forensic tools on hosting
- SHA-256 runs in Python.
- ExifTool and TShark are detected only if installed on the hosting environment and available on PATH. This package does not install these system tools automatically.
- TShark applies to `.pcap` / `.pcapng` network capture files, not PDFs or images.
- FTK Imager and Autopsy are external desktop applications and are not run by this web app.

## Recommended form links
- Prototype/Demo Link: the HTTPS URL created by Streamlit Community Cloud after deployment.
- Website/Product Link: if you do not have a separate official website, leave it blank if the form permits. Do not put a made-up link.
