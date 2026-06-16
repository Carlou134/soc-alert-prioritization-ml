# SOC Alert Prioritization ML

Machine Learning system for cybersecurity alert classification and prioritization.
Final degree project — Universidad Peruana de Ciencias Aplicadas (UPC).

---

## Description

Automates the classification and prioritization of cybersecurity alerts in Security Operations Centers (SOC) using Machine Learning (LightGBM) and graph-based analysis. Reduces analyst workload, improves response times, and enhances decision-making in cybersecurity environments.

---

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| Backend | Python, Django 6, Django REST Framework, JWT |
| ML | LightGBM, Scikit-learn, SHAP, Pandas, NumPy |
| Reporting | ReportLab, Matplotlib, OpenPyXL |
| AI | Anthropic Claude API |
| Frontend | Django Templates, Tailwind CSS |
| Database | SQLite (development) · PostgreSQL (production) |
| Deployment | Azure App Service · Gunicorn |

---

## Architecture

Django multi-app project under `soc_project/`:

- **accounts** — authentication, roles, user management
- **predictor** — ML pipeline, alert processing, SHAP explanations, PDF/Excel reports
- **theme** — Tailwind CSS integration

The ML model (`soc_model.pkl`) is trained automatically on first startup if not present.

---

## Running the project

### 1. Prerequisites

- Python 3.11+
- pip

Verify:

```bash
python --version
pip --version
```

---

### 2. Clone the repository

```bash
git clone https://github.com/Carlou134/soc-alert-prioritization-ml.git
cd soc-alert-prioritization-ml
```

---

### 3. Create and activate virtual environment

```bash
python -m venv venv
```

**Windows:**

```bash
venv\Scripts\activate
```

**Linux / Mac:**

```bash
source venv/bin/activate
```

---

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 5. Configure environment variables

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env` at the project root:

```env
# Django
DJANGO_SECRET_KEY=your-secret-key-here
DJANGO_DEBUG=True
ALLOWED_HOSTS=

# Anthropic
ANTHROPIC_API_KEY=your-anthropic-api-key-here

# PostgreSQL (leave DB_HOST empty to use SQLite in local development)
DB_NAME=soc_db
DB_USER=postgres
DB_PASSWORD=your-db-password
DB_HOST=
DB_PORT=5432
```

> `ANTHROPIC_API_KEY` is required for the AI-assisted alert analysis feature.  
> Set `DB_HOST` only for PostgreSQL (production/Azure). Leave empty to use SQLite locally.

---

### 6. Apply migrations

Move into the Django project folder first:

```bash
cd soc_project
python manage.py migrate
```

This command does three things automatically:
1. Creates the database schema (SQLite locally, PostgreSQL in production)
2. Seeds the default users (see credentials below)
3. **Trains the ML model** — if `predictor/ml/soc_model.pkl` does not exist, the model is trained from `dataset_soc_alertas_train.csv` automatically. This may take a few minutes on first run.

---

### 7. Run the development server

```bash
python manage.py runserver
```

Open your browser at:

```
http://127.0.0.1:8000/
```

---

## Default credentials

These users are created automatically by the migrations:

| Username | Password | Role |
|----------|----------|------|
| `admin_soc` | `Admin@2025` | Admin |
| `jacobo` | `Jacobo@2025` | Analyst N1 |
| `gian` | `Gian@2025` | Analyst N2 |
| `senior` | `Senior@2025` | Analyst N3 |
| `practicante_rios` | `Practicante@2025` | Trainee |

---

## ML Model

The model is trained from `soc_project/dataset_soc_alertas_train.csv` and saved to `soc_project/predictor/ml/soc_model.pkl`.

If you need to retrain from scratch, delete `soc_model.pkl` and restart the server.

---

## Academic Context

Developed as a final degree project at **Universidad Peruana de Ciencias Aplicadas (UPC)**.

**Authors:** Carlos Vásquez · Giancarlo Moreno
