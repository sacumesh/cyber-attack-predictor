import pathlib

# General
ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent


# Logging
LOG_CONFIG = ROOT_DIR / "logging-config.json" 

# Data Directory
DATA_DIR = ROOT_DIR / "data/"

# App Data Directory
APP_DATA_DIR = DATA_DIR / "app/"

# CSV Files Used in app
APP_DATA_BROWSERS_CSV_FILE = APP_DATA_DIR / "browser.csv"
APP_DATA_OS_CSV_FILE = APP_DATA_DIR / "os.csv"
APP_DATA_DEVICES_CSV_FILE = APP_DATA_DIR / "device.csv"

