"""El sondeo interno de Azure (host no permitido) no ensucia el log, pero
sigue siendo rechazado.

No se usa caplog: pytest cuelga sus propios handlers de captura en el logger,
así que lo vería igual aunque en producción no llegue a la consola."""
import logging

import pytest
from django.conf import settings
from django.test import Client


def test_disallowed_host_logger_has_no_console_output():
    logger = logging.getLogger('django.security.DisallowedHost')

    assert settings.LOGGING['loggers']['django.security.DisallowedHost']['handlers'] == []
    assert logger.propagate is False
    assert not [h for h in logger.handlers if type(h) is logging.StreamHandler]


@pytest.mark.django_db
def test_disallowed_host_is_still_rejected():
    resp = Client(HTTP_HOST='169.254.129.2:8000').get('/login/')

    assert resp.status_code == 400
