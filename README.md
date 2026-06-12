# 🛡️ PhishGuard — AI-Powered Phishing Detection Tool

> **PhishGuard** is an intelligent, Flask-based web application that leverages Machine Learning and heuristic analysis to detect phishing URLs and emails in real time. Designed for cybersecurity awareness and education, it empowers users to identify social engineering threats before they cause harm.

---

## 📑 Table of Contents

1. [Introduction](#-introduction)
2. [Problem Statement](#-problem-statement)
3. [Objectives](#-objectives)
4. [Features](#-features)
5. [System Architecture](#-system-architecture)
6. [Technology Stack](#-technology-stack)
7. [Project Structure](#-project-structure)
8. [Module Descriptions](#-module-descriptions)
9. [Machine Learning Model](#-machine-learning-model)
10. [URL Analysis Pipeline](#-url-analysis-pipeline)
11. [Email Analysis Pipeline](#-email-analysis-pipeline)
12. [User Interface](#-user-interface)
13. [Installation & Setup](#-installation--setup)
14. [Deployment](#-deployment-on-render)
15. [Testing & Results](#-testing--results)
16. [Limitations](#-limitations)
17. [Future Enhancements](#-future-enhancements)
18. [Conclusion](#-conclusion)
19. [References](#-references)
20. [License](#-license)

---

## 📖 Introduction

Phishing is one of the most prevalent and damaging forms of cybercrime in the modern digital landscape. Attackers craft deceptive URLs and emails that closely mimic legitimate organizations to trick users into revealing sensitive information such as login credentials, financial data, and personal details.

**PhishGuard** addresses this challenge by combining the predictive power of a **Random Forest machine learning classifier** with rule-based **heuristic pattern analysis** to provide a dual-layered defense against phishing threats. The application provides an intuitive, modern web interface where users can scan suspicious URLs and email content and receive instant, actionable risk assessments.

This project was developed as a cybersecurity tool to demonstrate the practical application of machine learning in threat detection, while also serving as an educational resource to raise phishing awareness.

---

## 🎯 Problem Statement

Phishing attacks continue to grow in sophistication and volume, accounting for over **36%** of all data breaches globally. Traditional blacklist-based approaches fail to detect newly created phishing sites (zero-day phishing). Users often lack the technical knowledge to identify subtle phishing indicators in URLs and emails.

There is a need for an accessible, intelligent tool that can:
- Analyze URLs beyond simple blacklist lookups using structural and behavioral features
- Detect social engineering patterns in email content
- Present results in a clear, non-technical format that any user can understand
- Operate in real time with minimal latency

---

## 🏆 Objectives

1. **Develop an ML-based URL scanner** — Train and deploy a Random Forest classifier capable of distinguishing phishing URLs from legitimate ones based on extracted structural features.
2. **Build an email content analyzer** — Implement heuristic-based email analysis that detects phishing indicators across 8 categories of social engineering tactics.
3. **Create a user-friendly web interface** — Design a modern, responsive UI with a cybersecurity dark theme that makes security analysis accessible to non-technical users.
4. **Provide risk-level assessments** — Combine ML predictions with pattern analysis to produce graduated risk levels (Low, Medium, High) with human-readable explanations.
5. **Enable cloud deployment** — Package the application for seamless deployment on cloud platforms like Render using Gunicorn.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🔗 URL Scanner** | Analyzes any URL for phishing indicators using a trained Random Forest ML model combined with 9+ pattern-based checks |
| **📧 Email Scanner** | Detects phishing attempts in email content using heuristic analysis across 8 indicator categories with 80+ keywords |
| **📊 Risk Assessment** | Provides graduated risk levels (Low / Medium / High) with detailed explanations for each scan |
| **🔍 Pattern Analysis** | Detects IP-based URLs, URL shorteners, suspicious keywords, excessive subdomains, missing HTTPS, and more |
| **📚 Help Center** | Comprehensive educational guide on phishing awareness, attack types, and safety best practices |
| **🎨 Dark Cybersecurity Theme** | Premium glassmorphism UI with animated backgrounds, micro-animations, and responsive design |
| **☁️ Cloud-Ready** | Pre-configured for Render deployment with `Procfile`, `requirements.txt`, and dynamic port binding |
| **⚡ Real-Time Analysis** | Instant results with no external API dependencies — all processing happens on the server |

---

## 🏗️ System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         USER (Browser)                          │
│          Homepage  │  URL Scanner  │  Email Scanner  │  Help    │
└────────────────────────────┬─────────────────────────────────────┘
                             │  HTTP Requests (GET / POST)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Flask Web Server (app.py)                   │
│                                                                  │
│  ┌──────────────┐   ┌──────────────────┐   ┌─────────────────┐  │
│  │  URL Routes  │   │  Email Routes    │   │  Static Routes  │  │
│  │  /scan-url   │   │  /scan-email     │   │  /  /help       │  │
│  └──────┬───────┘   └──────┬───────────┘   └─────────────────┘  │
│         │                  │                                     │
│         ▼                  ▼                                     │
│  ┌──────────────┐   ┌──────────────────┐                        │
│  │ URL Analysis │   │ Email Analysis   │                        │
│  │  Pipeline    │   │  Pipeline        │                        │
│  └──────┬───────┘   └──────┬───────────┘                        │
│         │                  │                                     │
│    ┌────┴────┐        ┌────┴────┐                               │
│    ▼         ▼        ▼         ▼                               │
│ ┌──────┐ ┌──────┐ ┌──────┐ ┌───────┐                           │
│ │  ML  │ │Patt. │ │Heuri.│ │Brand  │                           │
│ │Model │ │Anal. │ │Match │ │Detect │                           │
│ └──┬───┘ └──┬───┘ └──┬───┘ └──┬────┘                           │
│    └────┬───┘        └────┬───┘                                 │
│         ▼                 ▼                                     │
│  ┌──────────────┐  ┌──────────────────┐                         │
│  │ Risk Level   │  │ Risk Level       │                         │
│  │ Computation  │  │ Computation      │                         │
│  └──────┬───────┘  └──────┬───────────┘                         │
│         │                 │                                      │
└─────────┼─────────────────┼──────────────────────────────────────┘
          ▼                 ▼
┌──────────────────────────────────────────────────────────────────┐
│              Jinja2 HTML Templates + CSS Theme                  │
│     result.html  │  email_result.html  │  help.html             │
└──────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Backend** | Flask (Python 3.8+) | Web framework, routing, request handling |
| **Machine Learning** | scikit-learn (Random Forest) | URL phishing classification |
| **Data Processing** | NumPy, Pandas | Feature extraction, array operations |
| **Model Serialization** | Pickle | Saving/loading trained ML model |
| **Templating** | Jinja2 | Dynamic HTML rendering |
| **Frontend** | HTML5, CSS3 | Responsive UI with glassmorphism theme |
| **Typography** | Google Fonts (Inter, JetBrains Mono) | Modern, readable typography |
| **Production Server** | Gunicorn | WSGI HTTP server for deployment |
| **Cloud Hosting** | Render | Platform-as-a-Service deployment |

---

## 📂 Project Structure

```
phishguard/
├── app.py                  # Main Flask application — routes, analysis logic, ML integration
├── train_model.py          # ML model training script — synthetic data + Random Forest
├── model.pkl               # Serialized trained ML model (Random Forest classifier)
├── requirements.txt        # Python package dependencies
├── Procfile                # Gunicorn configuration for Render deployment
├── README.md               # Project documentation (this file)
│
├── templates/              # Jinja2 HTML templates
│   ├── index.html          # Homepage with navigation cards
│   ├── url_scanner.html    # URL scanner input page
│   ├── email_scanner.html  # Email scanner input page
│   ├── result.html         # URL scan results page
│   ├── email_result.html   # Email scan results page
│   └── help.html           # Help center & phishing education
│
└── static/                 # Static assets
    └── style.css           # Dark cybersecurity theme (1000+ lines)
```

---

## 📦 Module Descriptions

### `app.py` — Main Application (432 lines)

The core Flask application that handles all routing, URL/email analysis logic, and ML model integration. Key components:

| Component | Description |
|-----------|-------------|
| `validate_url()` | Validates URL format using regex, auto-prepends `http://` if missing |
| `extract_features()` | Extracts 14 numeric features from a URL for ML prediction |
| `analyze_url_patterns()` | Performs 9 heuristic checks to detect suspicious URL patterns |
| `compute_url_risk()` | Combines ML prediction + pattern score into a risk level (Low/Medium/High) |
| `analyze_email()` | Scans email content against 8 categories of phishing indicators (80+ keywords) |
| `compute_email_risk()` | Determines email risk level based on total score and category count |
| **Routes** | `GET /` · `GET /url-scanner` · `POST /scan-url` · `GET /email-scanner` · `POST /scan-email` · `GET /help` |

### `train_model.py` — Model Training (182 lines)

Trains a Random Forest classifier on a curated dataset of **40 safe URLs** and **40 phishing URLs**. Features:

- Extracts 14 structural features from each URL
- Applies **noise augmentation** (Gaussian noise, σ=0.5) for model robustness
- Uses `class_weight='balanced'` to handle any class imbalance
- Configured with 100 decision trees (`n_estimators=100`) and max depth of 10
- Outputs `model.pkl` via Python's `pickle` serialization

### `static/style.css` — UI Theme (1019 lines)

A comprehensive CSS design system implementing:

- **Glassmorphism** effects with `backdrop-filter: blur(20px)`
- Animated radial gradient backgrounds with cyber grid overlay
- CSS custom properties (variables) for consistent theming
- Fade-in animations with staggered delays
- Risk-level color coding (green → yellow → red)
- Responsive design for mobile and desktop

---

## 🤖 Machine Learning Model

### Algorithm: Random Forest Classifier

| Parameter | Value |
|-----------|-------|
| Algorithm | Random Forest (Ensemble of Decision Trees) |
| Number of Trees | 100 (`n_estimators=100`) |
| Max Depth | 10 |
| Class Weighting | Balanced (auto-adjusted for class proportions) |
| Random State | 42 (reproducible results) |
| Training Data | 80 URLs (40 safe + 40 phishing) × 2 (with noise augmentation) = 160 samples |

### Feature Vector (14 Features)

| Index | Feature | Description | Phishing Signal |
|-------|---------|-------------|-----------------|
| 0 | URL Length | Total character count | Long URLs often obfuscate the real domain |
| 1 | Dot Count | Number of `.` characters | Excessive dots indicate many subdomains |
| 2 | Dash Count | Number of `-` characters | Hyphens used to mimic legitimate domains |
| 3 | @ Symbol | Presence of `@` in URL | Used to redirect to attacker's site |
| 4 | Double-Slash Count | Occurrences of `//` | Redirect tricks within the URL path |
| 5 | HTTPS Flag | Whether URL uses HTTPS | Phishing sites often lack SSL certificates |
| 6 | Digits in Domain | Whether the domain contains numbers | IP-based or randomized domains |
| 7 | Suspicious Keywords | Count of phishing-related keywords | Terms like "login", "verify", "password" |
| 8 | URL Shortener | Whether URL uses a known shortener | Shorteners hide the actual destination |
| 9 | Slash Count | Total `/` characters | Deep paths can indicate phishing pages |
| 10 | Query Parameters | Number of `?` characters | Excessive query strings for tracking |
| 11 | Equals Signs | Count of `=` characters | Many parameters, often for session hijacking |
| 12 | Domain Length | Length of the domain portion | Very long domains are suspicious |
| 13 | Many Subdomains | Flag if dots > 4 | Subdomain abuse to mimic legitimate sites |

---

## 🔗 URL Analysis Pipeline

The URL scanner follows a **dual-analysis** approach:

```
User Input (URL string)
       │
       ▼
┌──────────────────┐
│  Input Validation │  ── regex check, auto-prefix http://
└────────┬─────────┘
         │
    ┌────┴─────┐
    ▼          ▼
┌────────┐ ┌──────────────┐
│ ML     │ │ Pattern      │
│ Model  │ │ Analysis     │
│ Predict│ │ (9 checks)   │
└───┬────┘ └──────┬───────┘
    │             │
    └──────┬──────┘
           ▼
    ┌──────────────┐
    │   Combined   │
    │ Risk Engine  │
    └──────┬───────┘
           ▼
    ┌──────────────┐
    │    Result    │
    │  (Level +   │
    │ Explanation) │
    └──────────────┘
```

### Pattern Checks Performed

| # | Check | Risk Score |
|---|-------|-----------|
| 1 | IP address used instead of domain name | +3 |
| 2 | Unusually long URL (>75 characters) | +2 |
| 3 | `@` symbol detected (credential redirect trick) | +3 |
| 4 | Excessive dashes in domain (≥3) | +2 |
| 5 | Excessive subdomains (>3 dots in hostname) | +2 |
| 6 | URL shortener detected (bit.ly, tinyurl, etc.) | +2 |
| 7 | Missing HTTPS encryption | +1 |
| 8 | Suspicious keywords in URL | +1 to +3 |
| 9 | Unusual encoded/special characters | +1 |

### Risk Level Decision Matrix

| ML Prediction | Pattern Score | Final Risk Level |
|:---:|:---:|:---:|
| Phishing | ≥ 4 | 🔴 **High** |
| Phishing | < 4 | 🔴 **High** |
| Safe | ≥ 6 | 🔴 **High** |
| Safe | 3 – 5 | 🟡 **Medium** |
| Safe | 1 – 2 | 🟢 **Low** |
| Safe | 0 | 🟢 **Low** |

---

## 📧 Email Analysis Pipeline

The email scanner uses a **keyword-based heuristic** approach across 8 categories:

### Indicator Categories

| Category | Examples | Description |
|----------|----------|-------------|
| **Urgency** | "act now", "expires today", "limited time" | Creates pressure to act without thinking |
| **Credential Request** | "verify your account", "update your password" | Directly asks for login information |
| **Threat** | "account will be suspended", "unauthorized access" | Threatens negative consequences |
| **Reward** | "you have won", "free gift", "cash prize" | Lures with too-good-to-be-true offers |
| **Impersonation** | "dear customer", "security department" | Pretends to be an authority figure |
| **Suspicious Links** | "click here", "open attachment" | Directs to malicious links or files |
| **Sensitive Info Request** | "credit card number", "social security" | Requests highly sensitive personal data |
| **Spoofed Sender** | "noreply@", "support@secure" | Uses suspicious sender addresses |

### Additional Email Checks

- **Embedded suspicious URLs** — Detects URLs containing phishing keywords within the email body
- **IP-based URLs in email** — Flags URLs using IP addresses instead of domain names
- **Excessive capitalization** — Detects "shouting" text (>3 fully uppercase words)
- **Brand misspellings** — Identifies typosquatting patterns (e.g., "paypa1", "amaz0n", "g00gle")

### Email Risk Scoring

| Condition | Risk Level |
|-----------|-----------|
| Phishing flag + score ≥ 8 | 🔴 **High** |
| Phishing flag + ≥ 3 categories | 🔴 **High** |
| Phishing flag (score ≥ 3) | 🟡 **Medium** |
| Score ≥ 2 (below threshold) | 🟢 **Low** |
| Score < 2 | 🟢 **Low** (Safe) |

---

## 🎨 User Interface

The application features a **cybersecurity dark theme** with the following design elements:

- **Color Palette**: Deep navy backgrounds (`#020a1a`) with electric blue accents (`#1e90ff`)
- **Glassmorphism**: Semi-transparent card backgrounds with `backdrop-filter: blur(20px)`
- **Animated Background**: Radial gradient orbs with a subtle cyber grid overlay
- **Typography**: Inter (UI text) + JetBrains Mono (URL/code display) from Google Fonts
- **Micro-Animations**: Fade-in-up effects with staggered delays, pulse indicators, and result pop animations
- **Risk Color Coding**: Green (safe) → Yellow (medium) → Red (danger) with glowing badges
- **Responsive Layout**: Max-width container (900px) that adapts to mobile screens

### Pages

| Page | Route | Description |
|------|-------|-------------|
| **Homepage** | `/` | Hero section, feature stats, and navigation cards to URL/Email scanners |
| **URL Scanner** | `/url-scanner` | Input form for URL analysis with validation feedback |
| **Email Scanner** | `/email-scanner` | Textarea input for pasting email content |
| **URL Result** | `/scan-url` (POST) | Displays phishing verdict, risk level, explanation, and pattern findings |
| **Email Result** | `/scan-email` (POST) | Shows phishing verdict with categorized indicator tags |
| **Help Center** | `/help` | Educational content on phishing types, prevention tips, and safety guidelines |

---

## 🚀 Installation & Setup

### Prerequisites

- **Python** 3.8 or higher
- **pip** (Python package manager)

### Step-by-Step Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd phishguard
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate        # Linux/macOS
   venv\Scripts\activate           # Windows
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Train the ML model** (if `model.pkl` doesn't exist):
   ```bash
   python train_model.py
   ```
   This will output `model.pkl` in the project root.

5. **Run the application:**
   ```bash
   python app.py
   ```

6. **Open your browser:**
   Navigate to `http://localhost:5000`

### Dependencies (`requirements.txt`)

| Package | Purpose |
|---------|---------|
| `flask` | Web framework |
| `gunicorn` | Production WSGI server |
| `scikit-learn` | Machine learning (Random Forest) |
| `pandas` | Data manipulation |
| `numpy` | Numerical operations |
| `pickle-mixin` | Model serialization support |

---

## 🌐 Deployment on Render

PhishGuard is pre-configured for one-click deployment on **Render**:

1. Push the project to a **GitHub** repository.
2. Create a new **Web Service** on [Render](https://render.com).
3. Connect your GitHub repository.
4. Render will automatically detect the `Procfile` and `requirements.txt`.
5. The app will be deployed and accessible via a public URL.

> **Note:** PhishGuard uses dynamic port binding via the `PORT` environment variable (`os.environ.get('PORT', 5000)`) for seamless cloud deployment.

### Procfile Configuration

```
web: gunicorn app:app
```

---

## 🧪 Testing & Results

### URL Scanner Testing

| Test URL | Expected Result | ML Prediction | Pattern Score | Final Verdict |
|----------|----------------|:---:|:---:|:---:|
| `https://www.google.com` | Safe | Safe | 0 | 🟢 Low |
| `https://www.github.com` | Safe | Safe | 0 | 🟢 Low |
| `http://192.168.1.1/login/verify` | Phishing | Phishing | 6+ | 🔴 High |
| `http://paypal-secure-update.com/confirm` | Phishing | Phishing | 4+ | 🔴 High |
| `http://bit.ly/3xYz123` | Suspicious | Varies | 3+ | 🟡 Medium |

### Email Scanner Testing

| Test Case | Indicators Found | Risk Level |
|-----------|:---:|:---:|
| Normal business email | 0 | 🟢 Low |
| Email with "verify your account" + "click here" | 2+ categories | 🟡 Medium |
| Email with urgency + threats + credential requests + suspicious URLs | 4+ categories | 🔴 High |
| Email containing "paypa1.com" (brand misspelling) | Spoofed domain | 🔴 High |

---

## ⚠️ Limitations

1. **Training Data Size** — The ML model is trained on 80 synthetic URLs (40 safe + 40 phishing). A larger, real-world dataset would significantly improve accuracy.
2. **Static Analysis Only** — The tool analyzes URL structure and email text without visiting the actual websites or performing real-time DNS/WHOIS lookups.
3. **No Real-Time Database** — The system does not query live phishing databases (e.g., Google Safe Browsing, PhishTank) for known threats.
4. **Email Metadata Not Analyzed** — Only the email body text is scanned; headers, SPF/DKIM records, and sender reputation are not analyzed.
5. **English-Only Detection** — Phishing keyword detection is limited to English-language indicators.
6. **No User Authentication** — The application does not require user login, so scan history is not persisted per user.

---

## 🔮 Future Enhancements

1. **Expanded Training Dataset** — Integrate large-scale phishing datasets from PhishTank, OpenPhish, or Kaggle for improved ML accuracy.
2. **Deep Learning Models** — Experiment with LSTM or Transformer-based models for character-level URL analysis.
3. **Live URL Inspection** — Add real-time website screenshots, SSL certificate verification, and WHOIS data lookups.
4. **API Integration** — Query Google Safe Browsing API, VirusTotal, and PhishTank for enhanced threat intelligence.
5. **Browser Extension** — Develop a Chrome/Firefox extension for real-time URL scanning while browsing.
6. **Scan History & Dashboard** — Add user authentication and a dashboard with scan history, statistics, and trends.
7. **Email Header Analysis** — Parse full email headers to verify SPF, DKIM, and DMARC authentication.
8. **Multi-Language Support** — Extend keyword detection to cover phishing patterns in other languages.
9. **REST API** — Expose scan functionality as a REST API for integration with other security tools.

---

## 📝 Conclusion

**PhishGuard** successfully demonstrates the practical application of machine learning and heuristic analysis in combating phishing threats — one of the most pervasive cybersecurity challenges of our time.

### Key Accomplishments

- **Dual-Layer Detection Engine** — By combining a **Random Forest ML classifier** (trained on 14 URL features) with a **rule-based pattern analysis system** (9 heuristic checks), PhishGuard achieves a more robust detection capability than either approach alone. The ML model captures complex feature interactions, while the pattern analyzer catches explicit red flags that provide interpretable results to the user.

- **Comprehensive Email Analysis** — The heuristic email scanner covers **8 distinct phishing indicator categories** with over **80 keywords**, including detection of brand typosquatting (e.g., "paypa1", "amaz0n"), IP-based embedded URLs, and excessive capitalization — achieving meaningful detection of common social engineering tactics.

- **Accessible Security Tool** — The glassmorphism-styled dark theme UI with **graduated risk levels** (Low → Medium → High) and **plain-language explanations** makes complex security analysis accessible to users without cybersecurity expertise. The application serves as both a practical tool and an educational resource.

- **Production-Grade Architecture** — Built with Flask and Gunicorn, the application follows best practices including input validation, error handling, environment-based configuration, and cloud deployment readiness — making it suitable for real-world hosting on platforms like Render.

### Summary

This project illustrates how modern web development and machine learning techniques can be combined to create an effective, user-friendly cybersecurity tool. While PhishGuard serves primarily as an educational proof-of-concept, its modular architecture and extensible design provide a solid foundation for future enhancements — including real-time threat intelligence integration, deep learning models, and browser extension development.

**PhishGuard reinforces the principle that cybersecurity is not just a technical challenge but a user awareness challenge** — and tools that are easy to understand and use play a critical role in protecting individuals from phishing attacks.

---

## 📚 References

1. **Anti-Phishing Working Group (APWG)** — Phishing Activity Trends Reports — [https://apwg.org](https://apwg.org)
2. **scikit-learn Documentation** — Random Forest Classifier — [https://scikit-learn.org/stable/modules/ensemble.html#forests-of-randomized-trees](https://scikit-learn.org/stable/modules/ensemble.html#forests-of-randomized-trees)
3. **Flask Documentation** — Web Framework — [https://flask.palletsprojects.com](https://flask.palletsprojects.com)
4. **OWASP Foundation** — Phishing Prevention Cheat Sheet — [https://cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org)
5. **Verizon DBIR 2024** — Data Breach Investigations Report — [https://www.verizon.com/business/resources/reports/dbir](https://www.verizon.com/business/resources/reports/dbir)
6. **Google Safe Browsing** — Transparency Report — [https://transparencyreport.google.com/safe-browsing](https://transparencyreport.google.com/safe-browsing)

---

## ⚠️ Disclaimer

> This tool is for **educational and cybersecurity awareness purposes only**. PhishGuard is not a replacement for professional cybersecurity solutions. No automated tool is 100% accurate. Always exercise caution and use multiple layers of security to protect yourself online.

---

## 👨‍💻 Author

**Siva Sankar** — Developer & Cybersecurity Enthusiast

---

## 📄 License

This project is open source under the [MIT License](LICENSE).
