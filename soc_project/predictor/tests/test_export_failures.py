"""CP027-A / CP027-B — falla la generación del reporte exportado."""
from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone

from accounts.models import ACTION_REPORT_EXPORT, UserActionLog
from devtools.models import FaultFlag
from predictor.models import ErrorLog
from predictor.views.reports import EXPORT_ERROR_MESSAGE

pytestmark = pytest.mark.django_db

EXPORTS = [
    ('export_pdf',   '/reports/export/pdf/',           'report_export_pdf_view'),
    ('export_pdf',   '/reports/export/incidents/pdf/', 'report_export_incidents_pdf_view'),
    ('export_excel', '/reports/export/excel/',         'report_export_excel_view'),
]


@pytest.fixture
def enable_faults(settings):
    settings.ENABLE_FAULT_INJECTION = True


def _activate(key):
    FaultFlag.objects.create(key=key, expires_at=timezone.now() + timedelta(minutes=5))


@pytest.mark.parametrize('fault_key, url, view_name', EXPORTS)
def test_export_failure_shows_message_on_report_page(
    admin_user, make_alert, enable_faults, fault_key, url, view_name,
):
    make_alert(admin_user, predicted_class='malicioso')
    _activate(fault_key)
    client = Client()
    client.force_login(admin_user)

    resp = client.get(f'{url}?severity=high', follow=True)

    assert resp.redirect_chain[-1][0] == '/reports/?severity=high'
    assert resp.status_code == 200
    assert EXPORT_ERROR_MESSAGE in resp.content.decode()
    assert ErrorLog.objects.filter(context=view_name).count() == 1
    assert not UserActionLog.objects.filter(action=ACTION_REPORT_EXPORT).exists()


def test_pdf_fault_does_not_break_excel_export(admin_user, make_alert, enable_faults):
    make_alert(admin_user, predicted_class='malicioso')
    _activate('export_pdf')
    client = Client()
    client.force_login(admin_user)

    resp = client.get('/reports/export/excel/')

    assert resp.status_code == 200
    assert resp['Content-Disposition'].endswith('.xlsx"')


@pytest.mark.parametrize('fault_key, url, view_name', EXPORTS)
def test_export_succeeds_once_fault_is_disabled(
    admin_user, make_alert, enable_faults, fault_key, url, view_name,
):
    make_alert(admin_user, predicted_class='malicioso')
    _activate(fault_key)
    client = Client()
    client.force_login(admin_user)
    client.get(url)

    FaultFlag.objects.all().delete()
    resp = client.get(url)

    assert resp.status_code == 200
    assert 'attachment' in resp['Content-Disposition']
