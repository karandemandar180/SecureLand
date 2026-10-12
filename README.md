# SecureLand Stable Prototype

## Run on Windows
1. Extract this ZIP into a **new folder** (do not overwrite your old project yet).
2. Open that folder in VS Code.
3. Run:
   `python -m pip install -r requirements.txt`
   `python -m streamlit run app.py`
4. Open `http://localhost:8501`.

Demo login: Admin/admin123, Talathi/talathi123, Citizen/citizen123.

## Included
- Land record form and search
- Evidence intake with SHA-256
- Integrity verification
- Chain of Custody
- ExifTool integration when installed
- tshark integration for PCAP/PCAPNG when installed
- External FTK Imager/Autopsy result registration
- JSON and CSV reports, audit log

## Important
This is a local educational prototype, not an official government system. Do not use real/confidential citizen data. Change demo passwords and obtain security/legal review before any real deployment. FTK Imager and Autopsy are external applications; this app does not automatically run them.
