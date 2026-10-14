"""El sondeo interno de Azure (host no permitido) no ensucia el log, pero
sigue siendo rechazado.

No se usa caplog: pytest cuelga sus propios handlers en los loggers, así que
el registro "se maneja" y nunca se ve el camino de producción, donde un logger
sin handlers cae en logging.lastResort e imprime igual en stderr."""
import logging

import pytest
from django.test import Client


class _Recorder(logging.Handler):
    def __init__(self):
        super().__init__(logging.WARNING)
        self.records = []

    def emit(self, record):
        self.records.append(record)


def _own_handlers(logger):
    return [h for h in logger.handlers if not type(h).__module__.startswith('_pytest')]


def test_disallowed_host_reaches_no_output(monkeypatch):
    logger = logging.getLogger('django.security.DisallowedHost')
    # Dentro del test y no en un fixture: pytest vuelve a colgar sus handlers
    # al empezar la fase de ejecución.
    monkeypatch.setattr(logger, 'handlers', _own_handlers(logger))
    last_resort = _Recorder()
    monkeypatch.setattr(logging, 'lastResort', last_resort)

    logger.error("Invalid HTTP_HOST header: '169.254.129.2:8000'.")

    assert last_resort.records == []
    assert logger.propagate is False
    assert not [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]


@pytest.mark.django_db
def test_disallowed_host_is_still_rejected():
    resp = Client(HTTP_HOST='169.254.129.2:8000').get('/login/')

    assert resp.status_code == 400
