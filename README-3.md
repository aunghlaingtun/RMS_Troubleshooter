# RMS Troubleshooter

A Streamlit app that analyses exported logs from a Rotork Master Station (RMS), Side A and/or Side B, and produces troubleshooting findings per FCU and per communication channel.

It is **read-only**: it only reads files you upload. It never connects to the RMS or DCS.

## What it checks

- **FCU health:** repeated Comms Loss, FCUs still offline at the end of the log, loop-map status and failure counts, manual-movement alarms.
- **Peer comparison:** an Isolation Forest scores how unusual each FCU is compared with the others.
- **Loop:** Classic Loop Faults (and whether they follow reset commands), groups of adjacent FCUs in Maintenance Required, loop-map changes between snapshots.
- **Host Modbus (ethernet, RTU1, RTU2):** exception responses and which register blocks cause them, response times, write-command echo, polling gaps.
- **Side A vs Side B:** how many of the frames Side B handles are also logged by Side A.
- **System log:** top warnings and errors from the syslog archive.

## Files you can upload

Keep the original export names. The app recognises them by prefix and by the `sideA` / `sideB` and `ethernet` / `rtu1` / `rtu2` parts.

| File | Used for |
|---|---|
| `AlarmLog_*.csv` | Comms Loss and other alarms per FCU |
| `DataLog_*.csv` | Control and reset events |
| `HostAnalyser_*_ethernet / rtu1 / rtu2.csv` | Raw Modbus request and response frames |
| `HostCommandLog_*.csv` | Write commands from hosts |
| `loop_map_*.csv` | Loop topology, FCU status, failures |
| `syslogs_*.tgz` | RMS system log |

Excel (`.xlsx`) versions of the CSV files also work. You can upload some or all of the files; each tab shows what it can from what you give it.

## Run on your own computer

Needs Python 3.10 or newer.

```
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run rms_app.py
```

The app opens at http://localhost:8501. Stop it with Ctrl+C.

## Deploy on Streamlit Community Cloud

1. Put `rms_app.py`, `rms_analyzer.py`, `requirements.txt` and this README in a GitHub repository (private is recommended).
2. Sign in at https://share.streamlit.io with GitHub and choose **Create app**.
3. Repository: this repo. Branch: `main`. Main file path: `rms_app.py`.
4. In **Advanced settings** set Python to 3.12, then **Deploy**.
5. In the app's Share settings, limit access to your team.

## Privacy

Logs contain tag names, IP addresses and operating history.

- Never commit log files to this repository.
- A cloud deployment processes uploads on Streamlit's servers. Check your company policy first; otherwise run it locally or on an internal server.

## Limits

- The HostAnalyser log does not capture every response (for example, 250-byte replies are not logged). The app reports this as information, not as a comms fault. Confirm with a packet capture.
- A Side A vs Side B gap can mean a Side A receive problem or a capture limit. Capture both sides at the same time to be sure.
- Health scores and the anomaly score are guides for where to look first, not proof of a fault.
- With only a few days of data there is not enough history for failure prediction.

## Files

- `rms_app.py` - Streamlit user interface
- `rms_analyzer.py` - parsers, health model and findings engine
- `requirements.txt` - Python libraries
