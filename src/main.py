import config
import json
import pathlib
import logging
import logging.config
import logging.handlers
import streamlit as st

def setup_logging():

    with open(config.LOG_CONFIG) as f:
        logging_config = json.load(f)

    logging.config.dictConfig(logging_config)


def main():
    setup_logging()
    routes = [
        "./pages/home.py",
        "./pages/test.py"
    ]
    pg = st.navigation([st.Page(route) for route in routes])
    pg.run()


if __name__ == '__main__':
    main()
