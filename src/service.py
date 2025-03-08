from src import config
import pandas as pd
import joblib
import logging
import os
from src.model import NetworkLogEntry

logger = logging.getLogger(__file__)


def get_os_list():
    df_os = pd.read_csv(config.APP_DATA_OS_CSV_FILE)
    return df_os.values


def get_device_list():
    df_os = pd.read_csv(config.APP_DATA_DEVICES_CSV_FILE)
    return df_os.values


def get_browser_list():
    df_browsers = pd.read_csv(config.APP_DATA_BROWSERS_CSV_FILE)
    return df_browsers.values


def load_preiction_model(model_path):
    try:
        prediction_model = joblib.load(model_path)
        logger.info(f"prediction model {os.path.basename(model_path)}")
        return prediction_model
    except Exception as e:
        logger.error(e)
        raise e


def predict(network_log: NetworkLogEntry):
    model_path = r'C:\Users\SachiththaKonaraMudi\Desktop\projects\ML\cyber-attack-predictor\src\model.pk1'
    logger.info(network_log)
    model = load_preiction_model(model_path)
