# ZERO TRUST — Threat Intelligence Platform (phishing-osint)

A fully-featured phishing detection, reporting, and OSINT threat intelligence platform built with Python and Streamlit.

## Features

- **Threat Scanner**: Utilize OSINT engine capabilities to analyze URLs and identify potential phishing threats.
- **Interactive UI**: Clean, asset-driven user interface built on Streamlit with custom styling, navigation, and robust page rendering.
- **Command Center**: Secure operator authentication widget (Admin Panel) for managing databases, reports, and investigations.
- **Educational Resources**: In-built modules to educate users about phishing tactics and zero-trust principles.
- **Incident Reporting**: Simplified user flow to report suspicious links or content to administrators.

## Tech Stack

- **Framework**: [Streamlit](https://streamlit.io/)
- **OSINT & Network Tools**: `requests`, `tldextract`, `python-whois`
- **Data Processing**: `pandas`
- **Environment Handling**: `python-dotenv`

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/mondayrx8/phishing-osint.git
   cd phishing-osint
   ```

2. **Create a virtual environment (Recommended)**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

To start the platform, run the main entry point from the root directory:

```bash
streamlit run app.py
```

The application will be served locally, typically at `http://localhost:8501`.

## Project Structure

- `app.py`: Main entry point and top-level application orchestrator.
- `core/`: Core internal services including configuration (`config.py`), database management (`database.py`), asset pipeline (`assets.py`), and the `OSINTEngine`.
- `ui/`: Custom Streamlit UI components, styling engine (`styles.py`), page renderers (`pages.py`), and the Admin Panel logic (`admin.py`).
- `tools/`: Helper utilities and scripts.
