import pytest
from django.test import Client


# ── HU016/017 — dashboard_view: visualización de alertas y métricas ─────────

@pytest.mark.django_db
def test_dashboard_counts_alerts_by_class(admin_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso')
    make_alert(admin_user, predicted_class='benigno')
    make_alert(admin_user, predicted_class='a_investigar')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/dashboard/')

    assert resp.status_code == 200
    ctx = resp.context
    assert ctx['total_alerts'] == 3
    assert ctx['total_malicioso'] == 1
    assert ctx['total_benigno'] == 1
    assert ctx['total_investigar'] == 1
    assert ctx['total_pending'] == 0


@pytest.mark.django_db
def test_dashboard_empty_state_no_crash(admin_user):
    """HU017 Esc.2 — sin datos suficientes: no debe romper, todo en cero."""
    client = Client()
    client.force_login(admin_user)
    resp = client.get('/dashboard/')

    assert resp.status_code == 200
    assert resp.context['total_alerts'] == 0
    assert resp.context['total_pending'] == 0


# ── HU016 — alert_list_view: visibilidad por rol ─────────────────────────────

@pytest.mark.django_db
def test_alert_list_n1_only_sees_benign(admin_user, analyst_n1_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso', label='mal-1')
    make_alert(admin_user, predicted_class='benigno', label='ben-1')

    client = Client()
    client.force_login(analyst_n1_user)
    resp = client.get('/alerts/')

    labels = {a.label for a in resp.context['page_obj'].object_list}
    assert labels == {'ben-1'}


@pytest.mark.django_db
def test_alert_list_n2_excludes_benign_and_unclassified(admin_user, analyst_n2_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso', label='mal-1')
    make_alert(admin_user, predicted_class='a_investigar', label='inv-1')
    make_alert(admin_user, predicted_class='benigno', label='ben-1')
    make_alert(admin_user, predicted_class=None, label='sin-clasificar')

    client = Client()
    client.force_login(analyst_n2_user)
    resp = client.get('/alerts/')

    labels = {a.label for a in resp.context['page_obj'].object_list}
    assert labels == {'mal-1', 'inv-1'}


@pytest.mark.django_db
def test_alert_list_admin_sees_everything(admin_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso', label='mal-1')
    make_alert(admin_user, predicted_class='benigno', label='ben-1')
    make_alert(admin_user, predicted_class=None, label='sin-clasificar')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/')

    labels = {a.label for a in resp.context['page_obj'].object_list}
    assert labels == {'mal-1', 'ben-1', 'sin-clasificar'}


# ── HU018 — filtros ───────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_alert_list_severity_filter_matches(admin_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso', severity='critical', label='crit')
    make_alert(admin_user, predicted_class='malicioso', severity='low', label='low')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/', {'severity': 'critical'})

    labels = {a.label for a in resp.context['page_obj'].object_list}
    assert labels == {'crit'}


@pytest.mark.django_db
def test_alert_list_filter_no_matches_returns_empty(admin_user, make_alert):
    """HU018 Esc.2 — sin coincidencias: página vacía, sin 500."""
    make_alert(admin_user, predicted_class='malicioso', severity='critical')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/', {'severity': 'low'})

    assert resp.status_code == 200
    assert list(resp.context['page_obj'].object_list) == []


# ── HU019 — orden ─────────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_alert_list_order_by_risk_desc(admin_user, make_alert):
    make_alert(admin_user, predicted_class='benigno', label='riesgo-bajo')
    make_alert(admin_user, predicted_class='malicioso', label='riesgo-alto')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/', {'order': 'risk_desc'})

    ordered_labels = [a.label for a in resp.context['page_obj'].object_list]
    assert ordered_labels[0] == 'riesgo-alto'


@pytest.mark.django_db
def test_alert_list_order_by_date_asc(admin_user, make_alert):
    first = make_alert(admin_user, predicted_class='malicioso', label='primera')
    second = make_alert(admin_user, predicted_class='malicioso', label='segunda')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/', {'order': 'date_asc'})

    ordered_labels = [a.label for a in resp.context['page_obj'].object_list]
    assert ordered_labels == ['primera', 'segunda']


# ── HU021 — filtro por prioridad de analista ─────────────────────────────────

@pytest.mark.django_db
def test_alert_list_priority_filter(admin_user, make_alert):
    critical = make_alert(admin_user, predicted_class='malicioso', label='prioridad-critica')
    critical.workflow.analyst_priority = 'critical'
    critical.workflow.save(update_fields=['analyst_priority'])
    make_alert(admin_user, predicted_class='malicioso', label='sin-prioridad')

    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/', {'analyst_priority': 'critical'})

    labels = {a.label for a in resp.context['page_obj'].object_list}
    assert labels == {'prioridad-critica'}


# ── HU020 — alert_shap_view ───────────────────────────────────────────────────

@pytest.mark.django_db
def test_alert_shap_view_renders_and_computes_shap(admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    assert alert.latest_prediction.shap_values is None

    client = Client()
    client.force_login(admin_user)
    resp = client.get(f'/alerts/{alert.pk}/shap/')

    assert resp.status_code == 200
    alert.latest_prediction.refresh_from_db()
    assert alert.latest_prediction.shap_values is not None


@pytest.mark.django_db
def test_alert_shap_view_redirects_when_not_classified(admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class=None)

    client = Client()
    client.force_login(admin_user)
    resp = client.get(f'/alerts/{alert.pk}/shap/')

    assert resp.status_code == 302
    assert resp.url == '/alerts/'


@pytest.mark.django_db
def test_alert_shap_view_404_for_nonexistent_alert(admin_user):
    client = Client()
    client.force_login(admin_user)
    resp = client.get('/alerts/999999/shap/')
    assert resp.status_code == 404
