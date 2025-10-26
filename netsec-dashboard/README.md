YOU NEED TO INSTALL WIRESHARK

To be able to injest and convert wireshark packages
python3 live_injest.py

To run the flaskAPI server
uvicorn server:app --reload

Host the dashboard locally
python3 -m http.server 5500