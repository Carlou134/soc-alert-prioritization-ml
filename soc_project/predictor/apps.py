import sys
import logging
from pathlib import Path
from django.apps import AppConfig

logger = logging.getLogger(__name__)

_MODEL_PATH   = Path(__file__).resolve().parent / 'ml' / 'soc_model.pkl'
_TRAIN_SCRIPT = Path(__file__).resolve().parent.parent / 'train_model.py'


class PredictorConfig(AppConfig):
    name = 'predictor'

    def ready(self):
        if not _MODEL_PATH.exists():
            if not _TRAIN_SCRIPT.exists():
                logger.critical(f'train_model.py no encontrado en {_TRAIN_SCRIPT} — modelo no disponible.')
                return
            logger.warning('soc_model.pkl no encontrado — iniciando entrenamiento del modelo ML...')
            import subprocess
            try:
                subprocess.run([sys.executable, str(_TRAIN_SCRIPT)], check=True)
                logger.info('Modelo ML entrenado y guardado exitosamente.')
            except subprocess.CalledProcessError as e:
                logger.critical(f'Entrenamiento del modelo falló con código {e.returncode}.')
                return

        from .utils import _load_model, _get_shap_explainers
        if _load_model():
            _get_shap_explainers()
            logger.info('Modelo ML y explainers SHAP precargados en memoria.')
