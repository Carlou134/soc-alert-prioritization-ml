"""CP026 — reporte sin datos: se informa y no se descarga ningún archivo."""
import pytest
from django.test import Client

from accounts.models import ACTION_REPORT_EXPORT, UserActionLog
from predictor.views.reports import NO_DATA_MESSAGE

pytestmark = pytest.mark.django_db

EXPORT_URLS = ['/reports/export/excel/', '/reports/export/pdf/', '/reports/export/incidents/pdf/']


def _client(user):
    client = Client()
    client.force_login(user)
    return client


def test_report_page_shows_no_data_notice(admin_user):
    resp = _client(admin_user).get('/reports/')

    assert resp.status_code == 200
    assert resp.context['no_data'] is True
    assert b'data-testid="report-no-data"' in resp.content
    assert b'data-testid="report-filter-form"' in resp.content


def test_report_page_hides_notice_when_there_is_data(admin_user, make_alert):
    make_alert(admin_user)

    resp = _client(admin_user).get('/reports/')

    assert resp.context['no_data'] is False
    assert b'data-testid="report-no-data"' not in resp.content


@pytest.mark.parametrize('url', EXPORT_URLS)
def test_export_without_data_downloads_nothing(admin_user, url):
    resp = _client(admin_user).get(f'{url}?severity=high', follow=True)

    assert resp.redirect_chain[-1][0] == '/reports/?severity=high'
    assert 'Content-Disposition' not in resp
    assert NO_DATA_MESSAGE in resp.content.decode()
    assert not UserActionLog.objects.filter(action=ACTION_REPORT_EXPORT).exists()


def test_filters_that_match_nothing_block_export(admin_user, make_alert):
    make_alert(admin_user, severity='low')

    resp = _client(admin_user).get('/reports/export/excel/?severity=critical')

    assert resp.status_code == 302
    assert 'Content-Disposition' not in resp


def test_incidents_pdf_blocked_when_alerts_exist_but_no_incidents(admin_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso')

    resp = _client(admin_user).get('/reports/export/incidents/pdf/', follow=True)

    assert 'Content-Disposition' not in resp
    assert NO_DATA_MESSAGE in resp.content.decode()
