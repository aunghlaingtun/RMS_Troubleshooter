
"""RMS (Rotork Master Station) log analyser - parsers, per-FCU health model, troubleshooting findings.
Read-only: it only analyses exported CSV/XLSX/TGZ files."""
import io, re, csv, tarfile
import numpy as np
import pandas as pd

SYSTEM_ADDR = {10000, 10001}  # master station / classic loop controller, not FCUs


# ---------------------------------------------------------------- reading
def read_table(name, data):
    if name.lower().endswith((".xlsx", ".xls")):
        return pd.read_excel(io.BytesIO(data))
    return pd.read_csv(io.BytesIO(data))


def meta(name):
    n = name.lower()
    kind = next((k for k in ["alarmlog", "datalog", "hostanalyser", "hostcommandlog", "loop_map", "syslogs"] if n.startswith(k)), None)
    side = re.search(r"side([ab])", n)
    chan = re.search(r"(ethernet|rtu\d)", n)
    return kind, (side.group(1).upper() if side else "?"), (chan.group(1) if chan else "?")


def parse_loop_map(data):
    rows = list(csv.reader(io.StringIO(data.decode("utf-8", "ignore"))))
    hi = next(i for i, r in enumerate(rows) if r and r[0] == "Position")
    links = pd.DataFrame([r[:5] for r in rows[1:hi] if r and r[0]], columns=rows[0][:5])
    cols = rows[hi][:9]
    fcu = pd.DataFrame([r[:9] for r in rows[hi + 1:] if r and r[0]], columns=cols)
    fcu = fcu.rename(columns={"Address": "Addr", "FCU Soft Ver": "Ver", "Tags": "Tag"})
    for c in ["Position", "Addr", "Failures"]:
        fcu[c] = pd.to_numeric(fcu[c], errors="coerce")
    return links, fcu


# ---------------------------------------------------------------- alarms / data log
def alarm_features(al):
    al = al.copy()
    al["t"] = pd.to_datetime(al["Timestamp"], unit="ms")
    al = al.sort_values("t")
    raised = al[al.AlarmLevel != "Cleared"].pivot_table(index="Address", columns="AlarmKey", values="Number", aggfunc="count", fill_value=0)
    raised.columns = [f"n_{c.replace(' ', '_')}" for c in raised.columns]
    episodes = []
    for (addr, key), g in al.groupby(["Address", "AlarmKey"]):
        start = None
        for _, r in g.iterrows():
            if r.AlarmLevel != "Cleared" and start is None:
                start = r.t
            elif r.AlarmLevel == "Cleared" and start is not None:
                episodes.append((addr, key, start, r.t, (r.t - start).total_seconds())); start = None
        if start is not None:
            episodes.append((addr, key, start, pd.NaT, np.nan))
    ep = pd.DataFrame(episodes, columns=["Address", "AlarmKey", "start", "end", "seconds"])
    return al, raised, ep


# ---------------------------------------------------------------- Modbus frames
def decode(msg):
    b = [int(x, 16) for x in str(msg).split(":")]
    return b


def parse_host(df, channel):
    """Return transactions (request->response pairing seen by Side B) and raw frames."""
    d = df.copy().rename(columns={"Milliseconds After Midnight": "ms"})
    d = d.sort_values(["ms", "Number"], ascending=[True, False]).reset_index(drop=True)
    m = d.Address.str.extract(r"(Rx|Tx)(Side[AB])\[(.+)\]")
    d["dir"], d["side"], d["ep"] = m[0], m[1].str[-1], m[2]
    d["bytes"] = d.Message.map(decode)
    d["fc"] = d.bytes.str[1]
    d["channel"] = channel
    tx, q = [], {}
    # The analyser log does not always capture every response, and hosts send the next request before the
    # previous response is logged. So each response is matched to the oldest pending request of the same
    # function code whose expected response length fits; requests never matched become "not_logged".
    def expected(p):
        if p["fc"] in (1, 2): return 3 + (p["qty"] + 7) // 8
        if p["fc"] in (3, 4): return 3 + 2 * p["qty"]
        return 6 if p["fc"] == 5 else None
    for r in d[d.side == "B"].itertuples():
        qq = q.setdefault(r.ep, [])
        b = r.bytes
        if r.dir == "Rx":
            qq.append(dict(channel=channel, ep=r.ep, ms=r.ms, fc=b[1], start=(b[2] << 8 | b[3]) if len(b) >= 6 else None,
                           qty=(b[4] << 8 | b[5]) if len(b) >= 6 else None, req=r.Message))
            continue
        exc = b[1] >= 0x80
        cand = [i for i, p in enumerate(qq) if p["fc"] == (b[1] & 0x7F) and r.ms - p["ms"] <= 1000
                and (exc or expected(p) is None or expected(p) == len(b))]
        i = (cand[-1] if exc else cand[0]) if cand else None   # exceptions answer the most recent request
        if i is None:
            tx.append(dict(channel=channel, ep=r.ep, ms=r.ms, fc=b[1] & 0x7F, status="unmatched_response", resp_len=len(b))); continue
        p = qq.pop(i)
        p["rt_ms"] = r.ms - p["ms"]
        if exc:
            p["status"], p["exc"] = "exception", b[2] if len(b) > 2 else None
        else:
            p["status"] = "ok" if (p["fc"] != 5 or r.Message == p["req"]) else "bad_length_or_echo"
        tx.append(p)
    for qq in q.values():
        for p in qq:
            tx.append(dict(p, status="not_logged"))
    return pd.DataFrame(tx), d


def side_a_coverage(frames):
    """% of Side-B requests / responses that Side A also heard within 100 ms (RTU only)."""
    a = frames[frames.side == "A"].sort_values("ms")
    if a.empty:
        return None
    out = {}
    for d in ("Rx", "Tx"):
        b = frames[(frames.side == "B") & (frames.dir == d)].sort_values("ms")
        mm = pd.merge_asof(b[["ms", "Message", "ep"]], a[["ms", "Message", "ep"]].rename(columns={"ms": "ms_a"}),
                           left_on="ms", right_on="ms_a", by=["Message", "ep"], direction="nearest", tolerance=100)
        out["requests_heard" if d == "Rx" else "responses_heard"] = round(100 * float(mm.ms_a.notna().mean()), 1)
    return out


def polling_gaps(frames):
    out = []
    for ep, g in frames[(frames.side == "B") & (frames.dir == "Rx")].groupby("ep"):
        gap = g.ms.diff().dropna()
        if len(gap):
            out.append(dict(ep=ep, requests=len(g), median_gap_ms=gap.median(), max_gap_ms=gap.max()))
    return pd.DataFrame(out)


# ---------------------------------------------------------------- syslog
def parse_syslog(data):
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        m = next((x for x in t.getmembers() if x.name.split("/")[-1] == "syslog"), None)
        text = t.extractfile(m).read().decode("utf-8", "ignore") if m else ""
    pat = re.compile(r"^(\S+) \S+ (\S+): (WARNING|ERROR) \d+ \d+ (\S+) \d+ (\S+) : (.*)$")
    rows = []
    for line in text.splitlines():
        g = pat.match(line)
        if g:
            rows.append((g[1], g[3], g[2], g[4], re.sub(r"\d+", "#", g[6])[:140]))
    df = pd.DataFrame(rows, columns=["time", "level", "process", "source", "message"])
    if df.empty:
        return df
    return (df.groupby(["level", "source", "message"]).agg(count=("time", "size"), first=("time", "min"), last=("time", "max"))
            .reset_index().sort_values("count", ascending=False))


# ---------------------------------------------------------------- findings helper
def F(sev, area, target, title, evidence, action):
    return dict(severity=sev, area=area, target=str(target), title=title, evidence=evidence, action=action)


SEV_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


# ---------------------------------------------------------------- main
def analyze(files, main_loop=None):
    """files: {filename: bytes}. Returns dict of tables + findings."""
    R = dict(findings=[], notes=[])
    loops, alarms, datal, hosts, sys_logs, cmdlogs = {}, {}, {}, [], {}, []
    for name, data in files.items():
        kind, side, chan = meta(name)
        if kind == "loop_map":
            loops[name] = parse_loop_map(data)
        elif kind == "alarmlog":
            alarms[name] = read_table(name, data)
        elif kind == "datalog":
            datal[name] = read_table(name, data)
        elif kind == "hostanalyser":
            hosts.append((side, chan, read_table(name, data)))
        elif kind == "hostcommandlog":
            cmdlogs.append((side, chan, read_table(name, data)))
        elif kind == "syslogs":
            sys_logs[side] = parse_syslog(data)
        else:
            R["notes"].append(f"Ignored unrecognised file: {name}")
    R["loop_maps"] = list(loops)
    R["findings_f"] = []
    fnd = R["findings"]

    # --- alarm logs (A and B are synchronised; use first, note if identical)
    if len(alarms) > 1:
        v = list(alarms.values())
        if all(x.equals(v[0]) for x in v):
            R["notes"].append("Side A and Side B alarm logs are identical (synchronised) - analysed once.")
    al = None
    if alarms:
        al, raised, ep = alarm_features(list(alarms.values())[0])
        R["alarms"], R["episodes"] = al, ep
    # --- data log events
    if datal:
        dl = list(datal.values())[0].copy()
        dl["t"] = pd.to_datetime(dl["Timestamp"], unit="ms")
        R["datalog"] = dl
        ctrl = dl[dl.DataKey == "DigCtrlNet0ControlVal"].groupby("Address").size().rename("ctrl_events")
        resets = dl[dl.DataKey.str.contains("RESET", na=False)]
        R["resets"] = resets[["t", "Address", "DataKey", "Source"]]
    else:
        ctrl, resets = pd.Series(dtype=int, name="ctrl_events"), pd.DataFrame()

    # --- loop map / FCU table
    if loops:
        main = main_loop if main_loop in loops else list(loops)[0]
        links, fcu = loops[main]
        R["links"], R["main_loop"] = links, main
        fcu = fcu.set_index("Addr")
        if len(loops) > 1:
            cmp = pd.DataFrame({n: f.set_index("Addr").Status for n, (_, f) in loops.items()})
            R["loop_compare"] = cmp[cmp.nunique(axis=1) > 1]
        bad_links = links[links["Link OK"] != "OK"] if not links.empty else links
        if len(bad_links):
            fnd.append(F("High", "Loop", f"{len(bad_links)} link(s)", "Loop links not OK",
                         ", ".join(bad_links["From Device"] + "->" + bad_links["To Device"]), "Check cable and terminals between these devices."))
    else:
        fcu = pd.DataFrame(index=pd.Index([], name="Addr"))

    # --- per-FCU table
    T = fcu.copy()
    if al is not None:
        T = T.join(raised, how="outer")
        T = T.join(ep[ep.AlarmKey == "Comms Loss"].groupby("Address").agg(cl_downtime_s=("seconds", "sum"), cl_open=("end", lambda s: bool(s.isna().any()))), how="left")
    T = T.join(ctrl, how="left")
    T.index.name = "Addr"
    T = T[~T.index.isin(SYSTEM_ADDR)]
    num = [c for c in T.columns if c.startswith("n_") or c in ("cl_downtime_s", "ctrl_events", "Failures")]
    T[num] = T[num].apply(pd.to_numeric, errors="coerce").fillna(0)
    for c in ("n_Comms_Loss", "n_Manual_Movement", "n_Battery_Low", "n_General_Alarm", "cl_downtime_s", "Failures"):
        if c not in T: T[c] = 0
    T["cl_open"] = T.get("cl_open", False)
    T["cl_open"] = T["cl_open"].fillna(False).astype(bool)
    T["maint"] = (T.get("Status", "") == "Maintenance Required") if "Status" in T else False
    T["Health"] = (100 - np.minimum(40, 6 * T.n_Comms_Loss) - 20 * T.cl_open - 15 * T.maint
                   - np.minimum(15, 3 * T.Failures) - np.minimum(10, 2 * T.n_Manual_Movement)).clip(0, 100)
    feats = ["n_Comms_Loss", "cl_downtime_s", "Failures", "n_Manual_Movement", "n_Battery_Low", "n_General_Alarm", "ctrl_events"]
    X = T[feats].astype(float)
    T["Anomaly"] = 0.0
    if len(X) >= 10 and X.std().sum() > 0:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import RobustScaler
        iso = IsolationForest(n_estimators=300, contamination="auto", random_state=0).fit(RobustScaler().fit_transform(X))
        s = -iso.score_samples(RobustScaler().fit_transform(X))
        T["Anomaly"] = ((s - s.min()) / (s.max() - s.min() + 1e-9)).round(2)
    T["Rank"] = T.Health.rank(method="min")
    R["fcu"] = T.reset_index().sort_values(["Health", "Anomaly"], ascending=[True, False])

    # --- FCU findings
    for addr, r in T.iterrows():
        tag = f"FCU {addr}" + (f" ({r['Tag']})" if "Tag" in r and isinstance(r["Tag"], str) else "")
        if r.cl_open:
            fnd.append(F("High", "FCU", tag, "Comms Loss never cleared in log (offline at end)", f"{int(r.n_Comms_Loss)} Comms Loss events, {r.cl_downtime_s:.0f}s cleared downtime",
                         "Check actuator power, loop wiring on both sides, then field unit comms card."))
        if r.n_Comms_Loss >= 3:
            fnd.append(F("Medium" if r.n_Comms_Loss < 10 else "High", "FCU", tag, "Repeated Comms Loss",
                         f"{int(r.n_Comms_Loss)} events, {r.cl_downtime_s:.0f}s total downtime",
                         "Intermittent comms: check termination/screen continuity near this device and its loop neighbours; compare with neighbours in the loop map."))
        if r.n_Manual_Movement and r.n_Manual_Movement >= 5:
            fnd.append(F("Low", "FCU", tag, "Frequent manual movement alarms", f"{int(r.n_Manual_Movement)} events", "Confirm local operation was intentional."))
    top = R["fcu"][R["fcu"].Anomaly >= 0.75].head(5)
    for _, r in top.iterrows():
        fnd.append(F("Info", "FCU", f"FCU {r.Addr}", "Unusual compared with peers (Isolation Forest)", f"anomaly score {r.Anomaly}, health {r.Health:.0f}", "Review alarms and loop-map entry for this device."))

    # --- loop segment findings
    if loops:
        f0 = fcu.reset_index().sort_values("Position")
        bad = (f0.Status != "Normal").to_numpy()
        i = 0
        while i < len(f0):
            if bad[i]:
                j = i
                while j + 1 < len(f0) and bad[j + 1]: j += 1
                if j - i + 1 >= 3:
                    seg = f0.iloc[i:j + 1]
                    fnd.append(F("Medium", "Loop", f"positions {seg.Position.min():.0f}-{seg.Position.max():.0f}", f"{len(seg)} adjacent devices in Maintenance Required",
                                 "addresses " + ", ".join(seg.Addr.astype(int).astype(str)),
                                 "Neighbours failing together suggests a shared cause (cable section, junction, supply) rather than individual actuators."))
                i = j + 1
            else:
                i += 1
    if al is not None:
        lf = al[(al.Address.isin(SYSTEM_ADDR)) & (al.AlarmKey == "Classic Loop Fault") & (al.AlarmLevel != "Cleared")]
        if len(lf):
            near = ""
            if len(resets):
                n = sum(((resets.t - t).abs() < pd.Timedelta("2min")).any() for t in lf.t)
                near = f"; {n} of them within 2 min of a network/loop reset command"
            fnd.append(F("High", "Loop", "10001", "Classic Loop Faults", f"{len(lf)} faults between {lf.t.min():%d %b %H:%M} and {lf.t.max():%d %b %H:%M}{near}",
                         "Check loop continuity; faults that follow resets may be operator-induced."))

    # --- host traffic (Side B view of transactions)
    tx_all, cov_rows, gap_rows, cmd_rows = [], [], [], []
    for side, chan, df in hosts:
        tx, fr = parse_host(df, chan)
        tx["file_side"] = side
        tx_all.append(tx)
        c = side_a_coverage(fr)
        if c is not None:
            cov_rows.append(dict(file_side=side, channel=chan, **c))
        g = polling_gaps(fr); g["channel"], g["file_side"] = chan, side
        gap_rows.append(g)
    if tx_all:
        TX = pd.concat(tx_all, ignore_index=True)
        R["tx"] = TX
        T2 = TX[TX.status != "unmatched_response"]
        S = T2.groupby(["file_side", "channel", "ep"]).agg(
            requests=("status", "size"), answered=("status", lambda s: (s != "not_logged").sum()),
            exceptions=("status", lambda s: (s == "exception").sum()), bad=("status", lambda s: (s == "bad_length_or_echo").sum()),
            rt_p50=("rt_ms", "median"), rt_p95=("rt_ms", lambda s: s.quantile(.95)), rt_max=("rt_ms", "max")).round(1).reset_index()
        R["host_summary"] = S
        cls = T2.groupby(["file_side", "channel", "ep", "fc", "qty"]).status.agg(
            requests="size", answered=lambda s: (s != "not_logged").sum()).reset_index()
        cls["answered_%"] = (100 * cls.answered / cls.requests).round(1)
        R["request_classes"] = cls
        R["coverage"] = pd.DataFrame(cov_rows)
        R["gaps"] = pd.concat(gap_rows, ignore_index=True) if gap_rows else pd.DataFrame()
        for r in S.itertuples():
            tgt = f"Side {r.file_side} / {r.channel} / {r.ep}"
            exc_rate = 100 * r.exceptions / max(r.answered, 1)
            if r.exceptions:
                e = TX[(TX.file_side == r.file_side) & (TX.channel == r.channel) & (TX.ep == r.ep) & (TX.status == "exception")]
                top = e.groupby(["fc", "start", "qty", "exc"]).size().sort_values(ascending=False).head(3)
                ev = f"{r.exceptions} exceptions ({exc_rate:.1f}% of logged responses). Most common (fc,start,qty,code): " + "; ".join(f"{tuple(int(x) for x in k)}x{v}" for k, v in top.items())
                fnd.append(F("Medium" if exc_rate < 5 else "High", "Host Modbus", tgt, "Host receives Modbus exception responses", ev,
                             "Code 2 = illegal data address: the host reads registers not mapped in the RMS. Fix the host register range or the RMS map."))
            if r.bad:
                fnd.append(F("Medium", "Host Modbus", tgt, "Write echo mismatch", f"{r.bad} writes", "Echo differs from request: command may have been rejected."))
            if r.rt_p95 and r.rt_p95 > 500:
                fnd.append(F("Low", "Host Modbus", tgt, "Slow responses", f"p95 {r.rt_p95:.0f} ms, max {r.rt_max:.0f} ms", "Check RMS load and serial baud rate."))
        for r in cls.itertuples():
            tgt = f"Side {r.file_side} / {r.channel} / {r.ep}"
            if r.requests >= 20 and 5 < r._8 < 95:
                fnd.append(F("Medium", "Host Modbus", tgt, "Some requests get no response", f"fc{r.fc} start-class qty {int(r.qty)}: {r._8}% of {r.requests} answered",
                             "Partial loss suggests a real comms/timeout problem on this channel."))
            elif r.requests >= 20 and r._8 <= 5:
                fnd.append(F("Info", "Host Modbus", tgt, "No logged response for this request type", f"fc{r.fc} qty {int(r.qty)}: 0 of {r.requests} responses in analyser log",
                             "Consistent 0% usually means the analyser did not capture large responses, not a comms fault - confirm with a packet capture."))
        for r in R["coverage"].itertuples():
            if min(r.requests_heard, r.responses_heard) < 95:
                fnd.append(F("Medium", "Side A/B", f"{r.channel} (file Side {r.file_side})", "Side A does not log all frames Side B handles",
                             f"Side A also logged {r.requests_heard}% of requests and {r.responses_heard}% of responses",
                             "Could be an A-side RS-485 receive problem or a log-capture limit; check A-side bus wiring/termination, then re-capture both sides simultaneously."))
        if not R["gaps"].empty:
            for r in R["gaps"].itertuples():
                if r.median_gap_ms and r.max_gap_ms > 20 * r.median_gap_ms and r.max_gap_ms > 2000:
                    fnd.append(F("Medium", "Host Modbus", f"{r.channel}/{r.ep}", "Polling gap", f"max gap {r.max_gap_ms/1000:.1f}s vs median {r.median_gap_ms:.0f} ms",
                                 "Host stopped polling for a period: check DCS comms or network."))
    # command acknowledgement
    if tx_all:
        w = TX[TX.fc == 5]
        if len(w):
            ack = w.groupby(["file_side", "channel", "ep"]).status.apply(lambda s: round((s == "ok").sum() / max((s != "not_logged").sum(), 1) * 100, 1)).rename("write_ack_%").reset_index()
            R["write_ack"] = ack
            for r in ack.itertuples():
                if r._4 < 99 and (w[(w.file_side == r.file_side) & (w.channel == r.channel) & (w.ep == r.ep)].status != 'not_logged').any():
                    fnd.append(F("High", "Commands", f"Side {r.file_side}/{r.channel}/{r.ep}", "Write commands not echoed/acknowledged", f"{r._4}% acknowledged", "Check whether commands reached the RMS and were rejected."))

    # syslog
    for side, s in sys_logs.items():
        R[f"syslog_{side}"] = s
        for r in s.head(40).itertuples():
            if "Failed to connect to Modbus server" in r.message:
                fnd.append(F("Medium", "RMS software", f"Side {side}", "RMS cannot connect to internal Modbus server", f"{r.count}x: {r.message}", "RTU channel service not reachable: check RTU port configuration/restart."))
            elif r.count >= 1000:
                fnd.append(F("Low", "RMS software", f"Side {side}", "High-volume error in syslog", f"{r.count}x [{r.source}] {r.message}", "Send to Rotork support if this is not seen on a healthy unit."))

    fnd.sort(key=lambda f: SEV_ORDER[f["severity"]])
    R["findings_df"] = pd.DataFrame(fnd)
    return R
