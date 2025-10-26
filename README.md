# The-Knight-s-Shield-Network-Security-Dashboard-
A simple network security dashboard that gives live packages.

YOU NEED TO INSTALL WIRESHARK

To be able to injest and convert wireshark packages
python3 live_injest.py

To run the flaskAPI server
uvicorn server:app --reload

Host the dashboard locally
python3 -m http.server 5500

Must use snowflake
Set up account using the following template

SNOW_USER=your_username
SNOW_PASSWORD=your_password
SNOW_ACCOUNT=your_account_url
SNOW_WAREHOUSE=COMPUTE_WH
SNOW_DATABASE=NETSEC_DB
SNOW_SCHEMA=PUBLIC
