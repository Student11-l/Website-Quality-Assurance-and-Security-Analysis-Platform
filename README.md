WebQA Pro – Website Quality & Security Analysis Platform
WebQA Pro is a full‑stack web application that automatically audits any public website across seven categories: HTML, CSS, JavaScript, SEO, security, accessibility, and performance. It provides an interactive dashboard, analysis history, report comparison, JSON export, and a rule‑based chatbot that answers questions about your scan results. No database is required – everything is stored in lightweight JSON files.

✨ Features
7‑in‑1 analysis – HTML, CSS, JS, SEO, security, accessibility, performance

User authentication – registration/login with password hashing

Live result dashboard – animated score ring, severity doughnut, category radar

Expandable issue cards with explanations and copy‑able fix suggestions

History & comparison – search, sort, paginate, compare two reports side‑by‑side

Rule‑based chatbot – ask questions like “What is my security score?”

JSON export – download full analysis reports

Caching – 1‑hour TTL to speed up repeated scans

Rate limiting & brute‑force protection – 5 analyses/min, lockout after 5 failed logins

No database – uses JSON files with thread‑safe writes

🛠️ Tech Stack
Layer	Technology
Backend	Flask (Python), requests, BeautifulSoup4
Frontend	Tailwind CSS, Chart.js, Font Awesome
Storage	JSON files with thread locking
Chatbot	Custom rule‑based intent matching
📦 Installation
Clone the repository

bash
git clone https://github.com/yourusername/webqa-pro.git
cd webqa-pro
Create a virtual environment

bash
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows
Install dependencies

bash
pip install -r requirements.txt
(Optional) Create a .env file with a secret key:

text
SECRET_KEY=your-secret-key-here
DEBUG=True
Run the application

bash
python app.py
Open your browser at http://localhost:5000

🚀 Usage
Register a new account or log in.

On the Analyzer page, enter a URL (e.g., https://example.com) and click Analyze.

Wait for the progress steps – results appear with:

Score ring & grade (Excellent / Good / Fair / Needs Improvement)

Doughnut chart (issue severity)

Radar chart (category scores)

Expandable issue list with fix suggestions

“Copy fix” button

Use the dashboard to view, search, sort, compare, and delete past reports.

Click the chatbot icon (bottom‑right) to ask questions about your latest analysis.

📁 Project Structure
text
webqa-pro/
├── app.py                 # Main Flask application
├── config.py              # Configuration (environment variables)
├── requirements.txt
├── .env.example
├── data/
│   ├── users.json         # User credentials (hashed)
│   └── analyses.json      # Analysis history
├── utils/
│   ├── analysis.py        # Core analysis orchestrator
│   ├── security_check.py
│   ├── seo_check.py
│   ├── html_check.py
│   └── js_css_check.py
├── templates/
│   ├── base.html
│   ├── home.html
│   ├── index.html         # Analyzer page
│   ├── dashboard.html
│   ├── analysis_detail.html
│   ├── compare.html
│   ├── login.html
│   └── register.html
└── static/
    ├── css/style.css
    └── js/
        ├── charts.js
        └── chatbot.js
🔧 Configuration
Key settings in config.py (can be overridden with environment variables):

Variable	Default	Description
SECRET_KEY	dev-secret-key	Flask session encryption
DEBUG	True	Debug mode (set False in production)
RATE_MAX_ANALYSES	5	Max analyses per minute per user
ANALYSIS_CACHE_TTL	3600	Cache lifetime in seconds
📊 API Endpoints
Method	Endpoint	Description
POST	/register	Create account
POST	/login	Log in (returns session cookie)
GET	/analyzer	Main analysis page
POST	/analyze	Start a website scan
GET	/dashboard	User history page
GET	/api/analyses	Paginated analysis list (JSON)
GET	/api/stats	User statistics (JSON)
POST	/compare	Compare two reports (renders HTML)
DELETE	/delete/<analysis_id>	Delete a single report
POST	/delete-multiple	Bulk delete reports
GET	/export/<analysis_id>	Download JSON report
POST	/api/chat	Chatbot (rule‑based)
🧪 Testing
Run unit tests (example):

bash
python -m unittest discover tests/
Manual testing is also available – register a test user and scan several URLs.

🤝 Acknowledgements
Flask – web framework

BeautifulSoup – HTML parsing

Chart.js – interactive charts

Tailwind CSS – styling

Font Awesome – icons

📄 License
This project is for educational purposes as part of a final year project. Please do not redistribute without permission.

⚠️ Disclaimer
This tool is intended for legitimate website quality and security auditing only. Do not use it to scan websites without permission. The author is not responsible for any misuse.
