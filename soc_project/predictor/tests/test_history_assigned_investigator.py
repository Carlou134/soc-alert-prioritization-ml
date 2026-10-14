"""HU028 — el historial muestra el investigador asignado (9 columnas)."""
import pytest
from django.test import Client

pytestmark = pytest.mark.django_db

HISTORY_COLUMNS = [
    'Fecha', 'Categoría / Ataque', 'Táctica MITRE', 'Severidad', 'Clase ML',
    'Riesgo', 'Estado', 'Evaluación ML', 'Investigador asignado',
]


def _history(user, params=None):
    client = Client()
    client.force_login(user)
    return client.get('/alerts/history/', params or {})


def _assign(alert, user):
    alert.workflow.assigned_to = user
    alert.workflow.save(update_fields=['assigned_to'])


def test_history_shows_all_nine_columns(admin_user, make_alert):
    make_alert(admin_user, predicted_class='malicioso')

    content = _history(admin_user).content.decode()

    for column in HISTORY_COLUMNS:
        assert f'<th class="px-4 py-3">{column}</th>' in content


def test_history_shows_assigned_investigator(admin_user, analyst_n2_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso')
    _assign(alert, analyst_n2_user)

    content = _history(admin_user).content.decode()

    cell_start = content.index(f'data-testid="alert-history-assigned-{alert.pk}"')
    cell = content[cell_start:content.index('</td>', cell_start)]
    assert analyst_n2_user.username in cell


def test_history_marks_unassigned_alerts(admin_user, make_alert):
    make_alert(admin_user, predicted_class='benigno')

    assert 'Sin asignar' in _history(admin_user).content.decode()


def test_analyst_filter_matches_assigned_investigator(admin_user, analyst_n2_user, make_alert):
    assigned = make_alert(admin_user, predicted_class='malicioso', label='asignada')
    make_alert(admin_user, predicted_class='malicioso', label='otra')
    _assign(assigned, analyst_n2_user)

    resp = _history(admin_user, {'analyst': analyst_n2_user.username})

    assert [a.label for a in resp.context['page_obj'].object_list] == ['asignada']
