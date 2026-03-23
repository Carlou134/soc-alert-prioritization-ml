# SOC Alert Prioritization ML

Machine Learning system for cybersecurity alert classification and prioritization using graph analysis.
Final degree project (UPC).

---

## 📌 Description

This project aims to automate the classification and prioritization of cybersecurity alerts in Security Operations Centers (SOC) using Machine Learning and graph-based analysis.

The system is designed to reduce analyst workload, improve response times, and enhance decision-making processes in cybersecurity environments.

---

## 🎯 General Objective

Develop an automated system for classification and prioritization of cybersecurity alerts with accuracy > 92%, based on Machine Learning and graph analysis techniques, to optimize incident management in SOCs in Lima Metropolitana by reducing manual workload and improving response times to cyberattacks.

---

## 🎯 Specific Objectives

* **OE1:** Analyze and evaluate machine learning models and graph-based techniques for alert correlation and cyber campaign detection in SOC environments.
* **OE2:** Design the physical and logical architecture of a web-based system capable of integrating and managing cybersecurity alert data from multiple sources.
* **OE3:** Implement and validate the system's performance using real cybersecurity datasets, evaluating accuracy and efficiency.
* **OE4:** Propose a sustainability plan ensuring economic, financial, and organizational viability of the system.

---

## 🛠️ Tech Stack

* Python
* Django
* Django REST Framework
* JWT Authentication
* Scikit-learn
* Pandas / NumPy
* Joblib

---

## 🏗️ Architecture

The system follows a modular architecture using Django apps:

* **soc_project:** Core configuration and routing
* **predictor:** Machine Learning logic, data processing, and predictions

Machine learning models are loaded using Joblib, and predictions are exposed through web views and APIs.

---

## ⚙️ Installation Guide

### 🔹 1. Install Python

Download and install Python from:
https://www.python.org/downloads/

👉 Verify installation:

```bash
python --version
```

---

### 🔹 2. Verify pip

```bash
pip --version
```

If needed, update pip:

```bash
python -m pip install --upgrade pip
```

---

### 🔹 3. Clone the repository

```bash
git clone https://github.com/TU_USUARIO/soc-alert-prioritization-ml.git
cd soc-alert-prioritization-ml
```

---

### 🔹 4. Create virtual environment

```bash
python -m venv venv
```

---

### 🔹 5. Activate virtual environment

**Windows:**

```bash
venv\Scripts\activate
```

**Linux / Mac:**

```bash
source venv/bin/activate
```

---

### 🔹 6. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 🔹 7. Apply migrations

```bash
python manage.py migrate
```

---

### 🔹 8. Run the server

```bash
python manage.py runserver
```

---

### 🔹 9. Access the application

Open your browser and go to:

```text
http://127.0.0.1:8000/
```

---

## 🚀 Usage

The system allows users to:

* Input cybersecurity alert data
* Classify alerts using ML models
* Prioritize alerts based on risk level
* Analyze historical alert data

---

## 🎓 Academic Context

This project was developed as a final degree project at
**Universidad Peruana de Ciencias Aplicadas (UPC)**.

---

## 👨‍💻 Authors

- Carlos Vásquez
- Giancarlo Moreno

---

## 📌 Notes

* The database is generated automatically using Django migrations.
* Machine learning models must be available in the expected paths for predictions to work.
* This project is intended for academic and research purposes.

-----