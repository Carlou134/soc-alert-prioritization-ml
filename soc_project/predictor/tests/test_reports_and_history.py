import pytest
from django.test import Client

from accounts.models import UserActionLog


# ── HU026 — report_view ──────────────────────────────────────────────────────

@pytest.mark.django_db
def test_report_view_summarizes_alerts(admin_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso', severity='critical')
    make_alert(admin_user, predicted_class='benigno', severity='low')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/reports/')

    assert resp.status_code == 200
    assert resp.context['summary']['total'] == 2


@pytest.mark.django_db
def test_report_view_empty_state_no_crash(admin_user):
    """HU026 Esc.2 — sin datos disponibles: no debe romper."""
    client = Client()
    client.force_login(admin_user)
    resp = client.get('/reports/')
    assert resp.status_code == 200
    assert resp.context['summary']['total'] == 0


@pytest.mark.django_db
def test_report_view_blocked_for_non_admin(analyst_n3_user):
    client = Client()
    client.force_login(analyst_n3_user)
    resp = client.get('/reports/')
    assert resp.status_code == 302


# ── HU027 — report_export_excel_view ─────────────────────────────────────────

@pytest.mark.django_db
def test_report_export_excel_returns_xlsx_attachment(admin_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/reports/export/excel/')

    assert resp.status_code == 200
    assert resp['Content-Type'] == 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    assert 'attachment' in resp['Content-Disposition']
    assert UserActionLog.objects.filter(user=admin_user, action='report_export').exists()


@pytest.mark.django_db
def test_report_export_excel_blocked_for_non_admin(analyst_n2_user):
    client = Client()
    client.force_login(analyst_n2_user)
    resp = client.get('/reports/export/excel/')
    assert resp.status_code == 302


# ── HU028 — alert_history_view ────────────────────────────────────────────────

@pytest.mark.django_db
def test_history_shows_only_classified_alerts(admin_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso', label='clasificada')
    make_alert(admin_user, predicted_class=None, label='sin-clasificar')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/history/')

    labels = {a.label for a in resp.context['page_obj'].object_list}
    assert labels == {'clasificada'}


@pytest.mark.django_db
def test_history_empty_state_no_crash(admin_user):
    """HU028 Esc.2 — sin historial: no debe romper."""
    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/history/')
    assert resp.status_code == 200
    assert resp.context['total_count'] == 0


@pytest.mark.django_db
def test_history_blocked_for_analyst_n1(analyst_n1_user):
    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.get('/alerts/history/')
    assert resp.status_code == 302
