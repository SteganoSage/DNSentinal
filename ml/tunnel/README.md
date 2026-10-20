# Tunnel dataset workflow

Each CSV is a separate capture session with columns `timestamp,src_ip,qname`.
The extractor may also provide `qtype`, `rcode`, and `response_size`.

Record ordinary DNS traffic with Wireshark's capture interface, then export
the DNS queries with the same command:

```powershell
python -m ml.tunnel.capture --interface 1 --duration 300 `
  --pcap ml\data\normal-session-1.pcap `
  --queries ml\data\normal-session-1.csv
```

Keep at least one normal and one tunnel capture entirely held out:

```powershell
python -m ml.tunnel.build_dataset `
  --train-positive ml\data\iodine-train.csv `
  --train-benign ml\data\normal-train.csv `
  --test-positive ml\data\dnscat2-test.csv `
  --test-benign ml\data\normal-test.csv `
  --output ml\data\tunnel-windows.jsonl

python -m ml.tunnel.train `
  --positive ml\data\iodine-train.csv `
  --benign ml\data\normal-train.csv `
  --test-positive ml\data\dnscat2-test.csv `
  --test-benign ml\data\normal-test.csv `
  --output models\tunnel_rf.joblib
```

The trainer reports the confusion matrix, false-alarm count, and false-alarm
rate for both a supervised Random Forest and an unsupervised Isolation Forest.
The Isolation Forest is fitted only on benign training windows; an anomaly is
reported as a tunnel. It does not synthesize benign traffic or split
overlapping windows from one capture across train and test. The Isolation
Forest model is saved as `models\tunnel_if.joblib`.
