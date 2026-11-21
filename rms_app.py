"""RMS Troubleshooter - run with:  streamlit run app.py
Upload the RMS exports (AlarmLog, DataLog, HostAnalyser_*, HostCommandLog_*, loop_map, syslogs .tgz) from Side A and/or Side B."""
import io
import pandas as pd
import streamlit as st
import rms_analyzer as ra

st.set_page_config(page_title="RMS Troubleshooter", layout="wide")
st.title("Rotork Master Station - troubleshooting analyser")
st.caption("Read-only analysis of exported logs. Nothing is sent to the RMS or DCS.")

ups = st.file_uploader("Upload Side A and/or Side B files (CSV, XLSX, syslogs .tgz)", accept_multiple_files=True,
                       type=["csv", "xlsx", "xls", "tgz"])
if not ups:
    st.info("Upload the exported files to start. File names should keep the original prefixes (AlarmLog_, DataLog_, HostAnalyser_, "
            "HostCommandLog_, loop_map_, syslogs_) and the sideA / sideB and ethernet / rtu1 / rtu2 parts.")
    st.stop()

files = {u.name: u.getvalue() for u in ups}


@st.cache_data(show_spinner="Analysing...")
def run(files, main_loop):
    return ra.analyze(files, main_loop)


loops = [n for n in files if n.lower().startswith("loop_map")]
main_loop = st.sidebar.selectbox("Main loop map (for per-FCU status)", loops) if loops else None
R = run(files, main_loop)
for n in R["notes"]:
    st.sidebar.info(n)

fd = R["findings_df"]
c = st.columns(4)
for col, sev in zip(c, ["High", "Medium", "Low", "Info"]):
    col.metric(sev, int((fd.severity == sev).sum()) if not fd.empty else 0)

tabs = st.tabs(["Findings", "FCU health", "Alarm timeline", "Loop map", "Host Modbus", "System log", "Export"])

with tabs[0]:
    if fd.empty:
        st.success("No findings.")
    else:
        sev = st.multiselect("Severity", ["High", "Medium", "Low", "Info"], default=["High", "Medium"])
        area = st.multiselect("Area", sorted(fd.area.unique()), default=sorted(fd.area.unique()))
        v = fd[fd.severity.isin(sev) & fd.area.isin(area)]
        for r in v.itertuples():
            icon = {"High": "🔴", "Medium": "🟠", "Low": "🟡", "Info": "🔵"}[r.severity]
            with st.expander(f"{icon} {r.target} - {r.title}"):
                st.write(f"**Evidence:** {r.evidence}")
                st.write(f"**What to check:** {r.action}")

with tabs[1]:
    T = R["fcu"]
    st.caption("Health = 100 minus penalties for comms loss, offline-at-end, maintenance status, loop-map failures, manual movement. "
               "Anomaly = Isolation Forest score vs peer FCUs (1 = most unusual).")
    cols = [c for c in ["Addr", "Tag", "Type", "Port", "Position", "Status", "Failures", "n_Comms_Loss", "cl_downtime_s", "cl_open",
                        "n_Manual_Movement", "n_Battery_Low", "n_General_Alarm", "ctrl_events", "Health", "Anomaly"] if c in T]
    st.dataframe(T[cols], use_container_width=True, hide_index=True)
    st.bar_chart(T.sort_values("Addr").set_index("Addr")["Health"])

with tabs[2]:
    if "episodes" in R:
        ep = R["episodes"]
        key = st.selectbox("Alarm type", sorted(ep.AlarmKey.unique()), index=sorted(ep.AlarmKey.unique()).index("Comms Loss") if "Comms Loss" in set(ep.AlarmKey) else 0)
        e = ep[ep.AlarmKey == key]
        st.dataframe(e, use_container_width=True, hide_index=True)
        st.scatter_chart(e.assign(t=e.start).rename(columns={"seconds": "duration_s"}).fillna({"duration_s": 0}), x="t", y="Address", size="duration_s")
        if "resets" in R and len(R["resets"]):
            st.subheader("Reset / network commands (DataLog)")
            st.dataframe(R["resets"], use_container_width=True, hide_index=True)
    else:
        st.write("No AlarmLog uploaded.")

with tabs[3]:
    if "loop_compare" in R:
        st.subheader("FCUs whose status differs between loop-map snapshots")
        st.dataframe(R["loop_compare"], use_container_width=True)
    if "links" in R:
        st.subheader("Loop links")
        st.dataframe(R["links"], use_container_width=True, hide_index=True)

with tabs[4]:
    if "host_summary" in R:
        st.subheader("Per channel / host (as seen by Side B)")
        st.dataframe(R["host_summary"], use_container_width=True, hide_index=True)
        st.subheader("Request types and how many responses were logged")
        st.dataframe(R["request_classes"], use_container_width=True, hide_index=True)
        if len(R["coverage"]):
            st.subheader("Side A vs Side B on RTU (% of Side B frames Side A also logged)")
            st.dataframe(R["coverage"], use_container_width=True, hide_index=True)
        st.subheader("Polling gaps")
        st.dataframe(R["gaps"], use_container_width=True, hide_index=True)
    else:
        st.write("No HostAnalyser files uploaded.")

with tabs[5]:
    for k in [k for k in R if k.startswith("syslog_")]:
        st.subheader(f"Side {k[-1]} - top warnings/errors")
        st.dataframe(R[k].head(30), use_container_width=True, hide_index=True)
    if not any(k.startswith("syslog_") for k in R):
        st.write("No syslog .tgz uploaded.")

with tabs[6]:
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as w:
        fd.to_excel(w, sheet_name="Findings", index=False)
        R["fcu"].to_excel(w, sheet_name="FCU health", index=False)
        for k in ("host_summary", "request_classes", "coverage", "episodes", "loop_compare"):
            if k in R:
                x = R[k].reset_index() if k == "loop_compare" else R[k]
                x.to_excel(w, sheet_name=k[:31], index=False)
    st.download_button("Download troubleshooting report (Excel)", buf.getvalue(), "rms_troubleshooting_report.xlsx",
                       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    md = "# RMS troubleshooting report\n\n" + "\n".join(
        f"- **[{r.severity}] {r.target}: {r.title}** - {r.evidence}. _Check:_ {r.action}" for r in fd.itertuples())
    st.download_button("Download findings (Markdown)", md, "rms_findings.md")
