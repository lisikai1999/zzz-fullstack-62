import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(BASE_DIR, "traffic_analyzer.db")

os.makedirs(UPLOAD_DIR, exist_ok=True)
