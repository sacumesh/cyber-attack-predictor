import config
import json
import pathlib
import logging
import logging.config
import logging.handlers


def setup_logging():

    with open(config.LOG_CONFIG) as f:
        logging_config = json.load(f)

    logging.config.dictConfig(logging_config)


def main():
    setup_logging()


if __name__ == '__main__':
    main()
