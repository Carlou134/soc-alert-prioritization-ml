import pytest

from predictor.utils import calculate_shap_values, compute_shap_safe


@pytest.mark.django_db
def test_calculate_shap_values_returns_structured_explanation(valid_record):
    """HU013 — Interpretación de factores / HU015 — Cálculo SHAP correcto."""
    result = calculate_shap_values(valid_record)

    assert set(result.keys()) == {'s1', 's2'}
    for stage in ('s1', 's2'):
        assert 'features' in result[stage]
        assert 'base_value' in result[stage]
        assert isinstance(result[stage]['base_value'], float)
        features = result[stage]['features']
        assert 1 <= len(features) <= 15
        for f in features:
            assert set(f.keys()) == {'name', 'value', 'shap'}
            assert isinstance(f['name'], str) and f['name']
            assert isinstance(f['shap'], float)

        # Ordenado por |shap| descendente — el factor más influyente primero.
        magnitudes = [abs(f['shap']) for f in features]
        assert magnitudes == sorted(magnitudes, reverse=True)


@pytest.mark.django_db
def test_compute_shap_safe_returns_none_on_failure():
    """compute_shap_safe nunca debe propagar una excepción — devuelve None."""
    assert compute_shap_safe(None) is None


@pytest.mark.django_db
def test_compute_shap_safe_returns_dict_on_success(valid_record):
    result = compute_shap_safe(valid_record)
    assert result is not None
    assert 's1' in result and 's2' in result
