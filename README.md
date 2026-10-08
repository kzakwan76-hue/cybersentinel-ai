# CyberSentinel AI

An AI-assisted security log analysis platform. Upload authentication and server logs, and CyberSentinel parses them, detects suspicious behavior with both **explicit rules** and a **machine-learning anomaly detector**, assigns a risk level, **explains why** each source was flagged, and presents the results in a dashboard with downloadable PDF reports.

> Defensive and educational. It analyzes logs only. It contains no attack tooling and is evaluated on **synthetic data**.

![Dashboard](docs/dashboard..png)
![ML findings](docs/ml-findings..png)
![Threats](Threats ss.png)

[Sample PDF report](docs/sample-report.pdf)

## Features

- Log upload, parsing and normalization (bad lines are reported, never fatal)
- Rule-based detection: brute force, brute-force compromise, sensitive-path access without login, path enumeration
- ML anomaly detection (Isolation Forest + learned range guard) for behavior the rules cannot express
- LOW / MEDIUM / HIGH / CRITICAL severity, with a plain-English reason and evidence line numbers for every finding
- User accounts: Argon2 password hashing, JWT login, strict per-user data isolation
- Dashboard: statistics, severity chart, top source IPs, threat cards, search and filters, upload history
- PDF security report per upload
- Measured evaluation: precision, recall, F1, confusion matrices (below)

## Architecture

```
 Browser dashboard (HTML/JS)
        | REST + JWT
 FastAPI  -- auth, upload, findings, stats, PDF report
        |
 Parser -> Rule detectors ----+
        |                     +--> Findings (severity + reason + evidence) --> SQLite via SQLAlchemy
        +-> Features -> Isolation Forest + range guard (only IPs the rules did not flag)
```

| Layer | Choice |
|---|---|
| Backend | Python, FastAPI, Pydantic |
| Database | SQLite via SQLAlchemy (switch to PostgreSQL by changing `DATABASE_URL`) |
| ML | scikit-learn `IsolationForest`, NumPy |
| Auth | Argon2 (pwdlib), JWT (PyJWT) |
| Reports | ReportLab |
| Tests | pytest |

## Run it (Windows)

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the printed value into `.env` as `SECRET_KEY=...`, then train the model and start the server:

```
python backend\train_anomaly.py
cd backend
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/dashboard/ (interactive API docs at `/docs`). Upload `data/synthetic/sample.log` or `data/synthetic/ml_demo.log`.
Run the tests from the project root with `pytest`. The server also works without a trained model (rules only).

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/register`, `/auth/login` | Create account, get a token |
| GET | `/auth/me` | Current user |
| POST | `/analyze` | Upload a log file, detect threats, save results |
| GET | `/findings` | Your threats (`severity`, `q`, `limit` filters) |
| GET | `/uploads` | Your upload history |
| GET | `/uploads/{id}/report.pdf` | PDF report for one upload |
| GET | `/stats` | Totals, counts by severity, top source IPs |

## Security design

- Passwords are stored only as Argon2 hashes. Login takes similar time whether or not the email exists.
- Secrets live in `.env` (git-ignored). The app refuses to start without `SECRET_KEY`.
- Every data query is scoped to the logged-in user. Another user's upload returns `404`, the same as a missing one.
- Upload size is limited, files must be UTF-8, and all inputs are validated with Pydantic.
- Log content is untrusted: it is HTML-escaped in the dashboard and escaped before it reaches the PDF library.
- Saved model files are only loaded from a local path (joblib files can execute code if loaded from untrusted sources).

## Machine learning and evaluation

**Features** (per source IP): total events, failed logins, successful logins, page requests, failure ratio, distinct paths, sensitive-path hits, longest failure streak.

**Model:** an Isolation Forest trained on **normal behavior only**, plus a range guard that flags any feature far beyond the most extreme normal training example. Every ML finding lists the features that deviate most from the baseline, so each flag can be explained.

**Data:** 1,000 synthetic IP sessions (800 normal, 200 attack) generated with a fixed seed. Labels come from how each session was generated, never from the detection rules. Normal types: typical, heavy, forgetful (3-4 mistyped passwords), admin. Attack types: brute force (with and without success), scanner, sensitive-path probe, post-login abuse (valid login then many sensitive pages), bulk access (valid login then a very large number of requests).

**Protocol:** stratified 70/30 split. The model trains only on normal training sessions and is tested on 300 unseen sessions (240 normal, 60 attacks). Reproduce with `python backend\train_anomaly.py`.

| Method | Precision | Recall | F1 | TP | FP | FN | TN |
|---|---|---|---|---|---|---|---|
| Rules only | 0.60 | 0.65 | 0.62 | 39 | 26 | 21 | 214 |
| Isolation Forest only | 0.79 | 0.80 | 0.79 | 48 | 13 | 12 | 227 |
| ML (forest + range guard) | 0.82 | 0.98 | 0.89 | 59 | 13 | 1 | 227 |
| Rules + ML (what the app runs) | 0.69 | 1.00 | 0.82 | 60 | 27 | 0 | 213 |

Sessions flagged per type (test set):

| Session type | Attack? | Total | Rules | Forest | ML (full) | Both |
|---|---|---|---|---|---|---|
| typical_user | no | 160 | 0 | 0 | 0 | 0 |
| heavy_user | no | 31 | 0 | 1 | 1 | 1 |
| admin_user | no | 23 | 0 | 0 | 0 | 0 |
| forgetful_user | no | 26 | 26 | 12 | 12 | 26 |
| brute_force | yes | 16 | 16 | 16 | 16 | 16 |
| brute_no_success | yes | 12 | 12 | 12 | 12 | 12 |
| scanner | yes | 7 | 7 | 7 | 7 | 7 |
| sensitive_probe | yes | 4 | 4 | 3 | 3 | 4 |
| bulk_access | yes | 10 | 0 | 10 | 10 | 10 |
| post_login_abuse | yes | 11 | 0 | 0 | 11 | 11 |

**Findings**

- Rules and ML fail in different places. Rules cannot see attackers with valid credentials (`bulk_access`, `post_login_abuse`: 0 of 21). ML catches both but missed one `sensitive_probe` that the rules caught. Together they missed none of these test attacks.
- The range guard raised ML recall from 0.80 to 0.98 with no additional false alarms in this run.
- The main weakness is **forgetful users**: the "3 failures then success" rule flags all of them, and the combined system's precision falls to 0.69 because of it. Timing information (failures within seconds versus spread over minutes) is the next planned improvement.

**Limitations (honest)**

- All data is synthetic and was designed by the author, so these numbers demonstrate the method, not real-world performance.
- Results come from one train/test split with one seed; repeated runs or cross-validation would give confidence intervals.
- The range guard was added after a test exposed a weakness, and its margin (1.25) was not tuned on a separate validation set.
- Detection operates per source IP with no time dimension yet; there is no IP-reputation data.
- ML findings are fixed at MEDIUM severity and should be read as leads to investigate, not confirmed attacks.

## Roadmap

- [x] Parser, rule engine, tests
- [x] FastAPI + database, authentication, dashboard
- [x] ML anomaly detection with evaluation
- [x] PDF reports
- [ ] Timing features (failure rate, events per minute) to separate forgetful users from attacks
- [ ] IP reputation lookups via a legitimate API
- [ ] Docker, then cloud deployment
- [ ] Migrations (Alembic) and PostgreSQL

## Responsible use

For defensive analysis and learning only. Use synthetic or properly authorized data. Detections are estimates and should be verified by a person before any action is taken.