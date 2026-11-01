# The DNS tunnel detector the analyzer ships

Trained with this command, at commit `8a91997`, dataset SHA-256 `883d390…`:

```bash
python -m ml.tunnel.pipeline --mode final --features V,N,R,D --params ml/tunnel/params/tuned_VNRD.json --final-model lgbm
```

It was then copied here with `python -m ml.tunnel.export <final folder> models/tunnel`. It was built on a laptop (2026-11-01) with Kaggle's library versions and 4 threads (numpy 2.1.3, scikit-learn 1.6.1, LightGBM 4.6.0). The same command reproduces Kaggle's random forest there tree for tree. The evaluation runs that chose it ran on Kaggle (`ml/tunnel/README.md`, "Final runs").

| File | |
|---|---|
| `tunnel_lgbm.txt` | LightGBM text model: 600 trees, 8,407 leaves, at most 104 leaves per tree |
| `model.json` | See below |
| `run_info_final.json` | How it was run: arguments, library versions, machine |

`model.json` holds:
- the 24 features (groups V, N, R and D) and their order;
- the threshold: 0.00301, flagging 0.01% of the windows of each benign set it was calibrated on;
- the windows (60 s, every 10 s) and the alert rule (two consecutive `high` windows of one client and domain);
- the training counts: 154,541 tunnel and 955,915 benign windows, from 236 captures of 10 tools.

Run it with `python -m analyzer.tunnel_analyzer events.jsonl --model models/tunnel`, or live with `python -m analyzer.live --model models/tunnel`. It needs LightGBM (any 4.x reads the text model): 4.7.0, as `ml/requirements.txt` pins it, scores 58,012 real windows exactly as 4.6.0 does. It takes 0.16 ms per window, one at a time.

How well it does at 0.01% FPR per benign set. These are the same settings evaluated with the test captures left out of training:
- **Tools never trained on:** 0.966 mean recall per tool; 42 of 43 captures caught. The missed one is a one-window capture, and alerts need two windows.
- **Known tool left out of training:** 0.999.
- **Rates:** every known-tool capture caught at full speed down to 1/100, median 15 s to the alert; 86% at 1/1000.
- **False alerts:** 6 in 39.7 h of real browsing (1 with the popular-site allowlist).
- **Weak spots:**
  - Cobalt Strike is the hardest tool (0.83 of its windows).
  - Wildcard DNS, never trained on, draws about 260 false alerts a day even with the allowlist.

Details are in `ml/tunnel/README.md`, "Final runs".
