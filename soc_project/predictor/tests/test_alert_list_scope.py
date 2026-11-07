"""Bug 0003085 / HU016 — el listado explica su alcance por rol y solo ofrece
las clases ML que ese rol puede ver; el dashboard aclara que es global."""
import pytest
from django.test import Client

pytestmark = pytest.mark.django_db


def _get(user, url):
    client = Client()
    client.force_login(user)
    resp = client.get(url)
    assert resp.status_code == 200
    return resp


def _class_values(resp):
    return [value for value, _ in resp.context['class_options']]


def test_n2_class_filter_hides_benign_and_pending(analyst_n2_user):
    resp = _get(analyst_n2_user, '/alerts/')

    assert _class_values(resp) == ['malicioso', 'a_investigar']
    assert 'value="benigno"' not in resp.content.decode()


@pytest.mark.parametrize('fixture', ['analyst_n1_user', 'trainee_user'])
def test_n1_and_trainee_class_filter_only_benign(request, fixture):
    resp = _get(request.getfixturevalue(fixture), '/alerts/')

    assert _class_values(resp) == ['benigno']


@pytest.mark.parametrize('fixture', ['admin_user', 'analyst_n3_user'])
def test_admin_and_n3_see_every_class_option(request, fixture):
    resp = _get(request.getfixturevalue(fixture), '/alerts/')

    assert _class_values(resp) == ['malicioso', 'a_investigar', 'benigno', 'pending']


def test_n2_scope_note_explains_missing_benign_and_escalated(analyst_n2_user):
    note = _get(analyst_n2_user, '/alerts/').context['scope_note']

    assert 'No incluye alertas benignas ni alertas escaladas a incidente' in note


def test_admin_scope_note_points_to_incident_desk(admin_user):
    resp = _get(admin_user, '/alerts/')

    assert 'Mesa de Incidentes' in resp.context['scope_note']
    assert 'data-testid="alert-list-scope-note"' in resp.content.decode()


def test_dashboard_total_is_labeled_as_global(analyst_n2_user):
    resp = _get(analyst_n2_user, '/')

    assert 'Total en el sistema (todos los niveles)' in resp.content.decode()


# ── Acceso al detalle de la alerta por rol ─────────────────────────────────────

def _open_detail(user, alert):
    client = Client()
    client.force_login(user)
    return client.get(f'/alerts/{alert.pk}/shap/', follow=True)


def test_n2_cannot_open_benign_alert_detail(analyst_n2_user, admin_user, make_alert):
    benign = make_alert(admin_user, predicted_class='benigno')

    resp = _open_detail(analyst_n2_user, benign)

    assert resp.redirect_chain[-1][0] == '/alerts/'
    assert 'No tienes permisos para acceder a esta alerta.' in resp.content.decode()


@pytest.mark.parametrize('predicted_class', ['malicioso', 'a_investigar'])
def test_n1_cannot_open_non_benign_alert_detail(analyst_n1_user, admin_user, make_alert, predicted_class):
    alert = make_alert(admin_user, predicted_class=predicted_class)

    resp = _open_detail(analyst_n1_user, alert)

    assert resp.redirect_chain[-1][0] == '/alerts/'


def test_n2_can_open_malicious_alert_detail(analyst_n2_user, admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')

    resp = _open_detail(analyst_n2_user, alert)

    assert resp.redirect_chain == []


def test_admin_can_open_benign_alert_detail(admin_user, make_alert):
    benign = make_alert(admin_user, predicted_class='benigno')

    assert _open_detail(admin_user, benign).redirect_chain == []


def test_dashboard_hides_detail_link_for_alerts_the_role_cannot_open(analyst_n2_user, admin_user, make_alert):
    benign = make_alert(admin_user, predicted_class='benigno')
    malicious = make_alert(admin_user, predicted_class='malicioso')

    content = _get(analyst_n2_user, '/').content.decode()

    assert f'data-testid="dashboard-shap-link-{benign.pk}"' not in content
    assert f'data-testid="dashboard-no-access-{benign.pk}"' in content
    assert f'data-testid="dashboard-shap-link-{malicious.pk}"' in content
    assert f'data-testid="dashboard-no-access-{malicious.pk}"' not in content
