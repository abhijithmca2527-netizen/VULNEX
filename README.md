<div align="center">

# 🛡️ VULNEX

### AI-Driven Website Vulnerability Assessment & Security Intelligence Platform

*Scan a website, understand its weaknesses, and get clear, actionable security insights.*

<br>

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-vulnex--web1.onrender.com-46E3B7?style=for-the-badge)](https://vulnex-web1.onrender.com/)
[![Figma](https://img.shields.io/badge/🎨_Design-Figma-F24E1E?style=for-the-badge&logo=figma&logoColor=white)](https://www.figma.com/design/sjVzXuRTy4bkdos5ulYl96/Untitled?node-id=0-1&t=FxHjzgeyGmoUvZRd-1)

![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)
![Django](https://img.shields.io/badge/Django-092E20?style=flat-square&logo=django&logoColor=white)
![Celery](https://img.shields.io/badge/Celery-37814A?style=flat-square&logo=celery&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat-square&logo=redis&logoColor=white)
![Supabase](https://img.shields.io/badge/Supabase-3ECF8E?style=flat-square&logo=supabase&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=flat-square&logo=scikitlearn&logoColor=white)
![Render](https://img.shields.io/badge/Deployed_on-Render-46E3B7?style=flat-square&logo=render&logoColor=white)

**[🌐 Live Demo](https://vulnex-web1.onrender.com/)** · **[🎨 Design](https://www.figma.com/design/sjVzXuRTy4bkdos5ulYl96/Untitled?node-id=0-1&t=FxHjzgeyGmoUvZRd-1)** · **[🐛 Report a Bug](../../issues)** · **[💡 Request a Feature](../../issues)**

</div>

---

## 📑 Table of Contents

- [About](#-about)
- [Live Demo](#-live-demo)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Tech Stack](#-tech-stack)
- [Getting Started](#-getting-started)
- [Environment Variables](#-environment-variables)
- [Deployment](#-deployment)
- [Design Reference](#-design-reference)
- [Roadmap](#-roadmap)
- [Responsible Use](#%EF%B8%8F-responsible-use)
- [Contributing](#-contributing)
- [License](#-license)

---

## 📖 About

**VULNEX** is a web-based platform that assesses websites for security vulnerabilities and turns the raw findings into readable intelligence. Scans run in the background, so the interface stays responsive while the analysis is in progress, and machine-learning models help classify and prioritise what is found.

---

## 🚀 Live Demo

> **👉 [vulnex-web1.onrender.com](https://vulnex-web1.onrender.com/)**

> [!NOTE]
> The demo runs on a free hosting tier. After about 15 minutes of inactivity the service sleeps, so the **first load can take 30–60 seconds**. Once it wakes up, it's fast.

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🔍 | **Website scanning** | Submit a URL and run a vulnerability assessment against it |
| ⚡ | **Background processing** | Scans run asynchronously with Celery, with live status updates in the UI |
| 🤖 | **ML-assisted analysis** | scikit-learn models help classify and prioritise findings |
| 🧠 | **Optional LLM insights** | Toggle AI-written explanations with a single environment flag |
| 🔐 | **OTP authentication** | One-time-password verification for secure sign-in |
| 📊 | **Dashboard** | Review scans and results in one place |
| 👤 | **User profiles** | Personal account area for each user |

---

## 🧩 How It Works

```mermaid
flowchart LR
    A[👤 User] -->|Submits URL| B[🌐 Django Web App]
    B -->|Queues scan| C[(⚡ Redis)]
    C -->|Delivers task| D[⚙️ Celery Worker]
    D -->|Scans & analyses| E[🤖 ML / LLM Analysis]
    D -->|Stores results| F[(🗄️ Supabase Postgres)]
    B -->|Polls status| D
    B -->|Reads results| F
    B -->|Shows report| A
```

1. The user submits a website URL from the dashboard.
2. Django places the scan task on a Redis queue.
3. A Celery worker picks up the task and runs the assessment.
4. Findings are analysed and stored in the database.
5. The UI polls the task status and displays the report when it's ready.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python, Django, Gunicorn |
| **Task queue** | Celery + Redis |
| **Database** | PostgreSQL via Supabase |
| **Analysis** | scikit-learn (optional LLM analysis) |
| **Hosting** | Render |
| **Design** | Figma |

---

## 🏁 Getting Started

### Prerequisites

- Python 3.12+
- A running Redis instance
- A PostgreSQL database (a Supabase project works well)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/VULNEX.git
cd VULNEX

# 2. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your .env file (see the table below)
cp .env.example .env

# 5. Apply database migrations
python manage.py migrate

# 6. Start the Django server
python manage.py runserver
```

In a **second terminal** (with the virtual environment active), start the Celery worker:

```bash
celery -A Vulnex worker --loglevel=info
```

Then open **http://127.0.0.1:8000**.

> [!TIP]
> On Windows, if Celery gives you trouble, add `--pool=solo` to the worker command.

---

## 🔑 Environment Variables

Create a `.env` file in the project root:

| Variable | Description | Example |
|---|---|---|
| `DJANGO_SECRET_KEY` | Django's secret key. Keep it private | `your-secret-key` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `REDIS_URL` | Redis connection URL for the Celery broker | `redis://localhost:6379` |
| `ENABLE_LLM_ANALYSIS` | Turns AI-generated analysis on or off | `False` |
| `PYTHON_VERSION` | Python version used on Render | `3.12.8` |
| *Email / SMS settings* | Credentials used to send OTP codes | *see `settings.py`* |

> [!WARNING]
> Never commit your `.env` file or real credentials to the repository. Make sure `.env` is listed in `.gitignore`.

---

## ☁️ Deployment

VULNEX is deployed on **[Render](https://render.com)**.

**Build command**

```bash
pip install -r requirements.txt
```

**Start command** (web server and Celery worker in a single service)

```bash
celery -A Vulnex worker --loglevel=info --pool=solo & gunicorn Vulnex.wsgi --workers 1 --threads 2 --timeout 120 --bind 0.0.0.0:$PORT
```

Add the variables from the table above under **Environment** in the Render dashboard.

> [!NOTE]
> Running the worker inside the web service keeps hosting free, but both share one small instance. For heavier workloads, move Celery to its own **Background Worker** service.

---

## 🎨 Design Reference

The interface was designed in Figma before development.

**[View the design on Figma →](https://www.figma.com/design/sjVzXuRTy4bkdos5ulYl96/Untitled?node-id=0-1&t=FxHjzgeyGmoUvZRd-1)**

---

## 🗺️ Roadmap

- [x] Background scan processing with Celery
- [x] Dashboard and user profiles
- [x] OTP-based authentication
- [x] Live deployment on Render
- [ ] Exportable PDF scan reports
- [ ] Scan history and comparison over time
- [ ] Severity scoring and remediation guidance
- [ ] Scheduled and recurring scans

---

## ⚖️ Responsible Use

VULNEX is built for **education and authorised security testing**. Only scan websites that you own or have **explicit written permission** to test. Scanning systems without authorisation may be illegal. The authors accept no responsibility for misuse.

---

## 🤝 Contributing

Contributions, issues and feature requests are welcome.

1. Fork the project
2. Create your branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m "Add amazing feature"`
4. Push the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

---

## 📄 License

Distributed under the **MIT License**. Add a `LICENSE` file to the repository, or change this section to match the license you choose.

---

<div align="center">

**If you find VULNEX useful, consider giving it a ⭐**

Made with ❤️ and a healthy respect for security

</div>
