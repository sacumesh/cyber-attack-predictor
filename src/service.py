from src import config
import pandas as pd


def get_os_list():
    df_os = pd.read_csv(config.APP_DATA_OS_CSV_FILE)
    return df_os.values


def get_device_list():
    df_os = pd.read_csv(config.APP_DATA_DEVICES_CSV_FILE)
    return df_os.values


def get_browser_list():
    df_browsers = pd.read_csv(config.APP_DATA_BROWSERS_CSV_FILE)
    return df_browsers.values
