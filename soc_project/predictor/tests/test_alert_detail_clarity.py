"""HU030 / bug 0003081 — el detalle traduce la etiqueta real y explica el
risk score, para que no se lean como contradicciones."""
import pytest
from django.test import Client

from predictor.views.alerts import _true_label_class

pytestmark = pytest.mark.django_db


def _detail(user, alert):
    client = Client()
    client.force_login(user)
    resp = client.get(f'/alerts/{alert.pk}/shap/')
    assert resp.status_code == 200
    return resp


@pytest.mark.parametrize('label, expected', [
    ('0', 'benigno'), ('1', 'a_investigar'), ('2', 'malicioso'),
    ('Malicioso', 'malicioso'), (' a_investigar ', 'a_investigar'),
    ('', ''), ('desconocida', ''),
])
def test_true_label_class_accepts_codes_and_names(label, expected):
    assert _true_label_class(label) == expected


def test_detail_shows_true_label_name_and_mismatch_warning(admin_user, make_alert):
    """Caso del reporte (#30): modelo dice Benigno, etiqueta real 1 = A investigar."""
    alert = make_alert(admin_user, predicted_class='benigno', label='1')

    resp = _detail(admin_user, alert)
    content = resp.content.decode()

    assert resp.context['true_label_display'] == 'A investigar'
    assert 'Etiqueta real' in content
    assert 'Label original' not in content
    assert 'data-testid="alert-label-mismatch"' in content


def test_detail_has_no_mismatch_warning_when_model_matches_label(admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso', label='2')

    content = _detail(admin_user, alert).content.decode()

    assert 'data-testid="alert-label-mismatch"' not in content


def test_unrecognized_label_is_shown_as_is_without_warning(admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='malicioso', label='otro')

    resp = _detail(admin_user, alert)

    assert resp.context['true_label_display'] == 'otro'
    assert resp.context['label_mismatch'] is False


def test_classified_detail_explains_risk_formula(admin_user, make_alert):
    alert = make_alert(admin_user, predicted_class='a_investigar')

    content = _detail(admin_user, alert).content.decode()

    assert 'Riesgo = P(Malicioso) + 0,5 × P(A investigar)' in content


def test_risk_formula_matches_risk_weights():
    """Si cambian los pesos del risk score, el texto explicativo debe cambiar también."""
    from predictor.utils import calculate_risk_score

    assert calculate_risk_score({'benigno': 0.6234, 'a_investigar': 0.3756, 'malicioso': 0.0020}) == 0.1898
