import pathlib

# General
ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent


# Logging
LOG_CONFIG = ROOT_DIR / "logging-config.json" 

# trained ml models directory
ML_MODELS = ROOT_DIR / "ml_models/"

