import config
import pandas as pd
import joblib
import logging
import os
from model import NetworkLogEntry, NetworkFeatureExtractor

logger = logging.getLogger(__file__)


def load_preiction_model():
    
    model_path = config.ML_MODELS / 'xg_cls.pkl'
    try:
        prediction_model = joblib.load(model_path)
        return prediction_model
    except Exception as e:
        logger.error(e)
        raise e
    


def predict(network_log: NetworkLogEntry):
    ntf_extractor = NetworkFeatureExtractor(network_log)
    model_features = ntf_extractor.extract()
    model = load_preiction_model()
    attack_type = ntf_extractor.label_attack_type(model.predict(model_features)[0])
    return attack_type
