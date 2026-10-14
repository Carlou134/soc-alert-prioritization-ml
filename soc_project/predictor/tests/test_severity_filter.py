"""HU018 / CP018 — filtro por severidad con niveles sin alertas."""
import pytest
from django.test import Client

pytestmark = pytest.mark.django_db


def _get(user, params=None):
    client = Client()
    client.force_login(user)
    return client.get('/alerts/', params or {})


def test_all_standard_levels_listed_even_without_alerts(admin_user, make_alert):
    make_alert(admin_user, severity='low')

    values = [value for value, _ in _get(admin_user).context['severity_choices']]

    assert values[:5] == ['critical', 'high', 'medium', 'low', 'unknown']


def test_non_standard_stored_values_are_added_once(admin_user, make_alert):
    make_alert(admin_user, severity='informational')
    make_alert(admin_user, severity='High')  # mismo nivel estándar, otra capitalización

    values = [value for value, _ in _get(admin_user).context['severity_choices']]

    assert values.count('informational') == 1
    assert 'High' not in values


def test_filter_by_level_without_alerts_shows_no_results(admin_user, make_alert):
    """CP018: no hay alertas críticas → "sin resultados" y el filtro queda seleccionado."""
    make_alert(admin_user, severity='low')

    resp = _get(admin_user, {'severity': 'critical'})

    content = resp.content.decode()
    assert resp.status_code == 200
    assert 'data-testid="alert-list-no-results"' in content
    assert '<option value="critical" selected>' in content
    assert 'data-testid="alert-list-filter-clear"' in content


def test_filter_matches_case_insensitively(admin_user, make_alert):
    make_alert(admin_user, severity='High', label='alta')

    resp = _get(admin_user, {'severity': 'high'})

    assert [a.label for a in resp.context['page_obj'].object_list] == ['alta']


def test_other_filters_also_show_no_results_message(admin_user, make_alert):
    make_alert(admin_user)

    resp = _get(admin_user, {'investigation_status': 'false_positive'})

    assert b'data-testid="alert-list-no-results"' in resp.content
