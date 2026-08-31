import json

from django.core.files.uploadedfile import SimpleUploadedFile

from predictor.pipeline import (
    REQUIRED_COLUMNS,
    apply_mapping,
    clean_records,
    parse_file,
    validate_columns,
)


def _base_row(**overrides):
    row = {
        'event_category': ' Malware ',
        'protocol': 'TCP',
        'traffic_type': 'HTTPS',
        'mitre_tactic': 'Execution',
        'kill_chain_stage': 'Delivery',
        'severity': 'HIGH',
        'ids_ips_alert': 'Suspicious',
        'asset_criticality': 'High',
        'log_source': 'EDR',
        'firewall_action': 'Blocked',
        'failed_login_attempts': '3',
        'request_rate_per_min': '15.5',
    }
    row.update(overrides)
    return row


def test_clean_records_strips_and_lowercases_categoricals():
    clean, stats = clean_records([_base_row()])
    assert clean[0]['severity'] == 'high'
    assert clean[0]['event_category'] == 'malware'
    assert stats['total_clean'] == 1


def test_clean_records_removes_duplicates():
    clean, stats = clean_records([_base_row(), _base_row()])
    assert stats['duplicates_removed'] == 1
    assert stats['total_clean'] == 1


def test_clean_records_fills_null_categoricals_as_unknown_and_numerics_with_median():
    rows = [
        _base_row(failed_login_attempts='10', correlation_id='INC-1'),
        _base_row(failed_login_attempts=None, event_category=None, correlation_id=None),
    ]
    clean, stats = clean_records(rows)
    assert stats['nulls_filled'] >= 2
    second = clean[1]
    assert second['event_category'] == 'unknown'
    assert second['correlation_id'] == 'unknown'
    assert second['failed_login_attempts'] == 10  # mediana del único otro valor (10)


def test_clean_records_drops_negative_numeric_rows():
    clean, stats = clean_records([_base_row(failed_login_attempts='-5')])
    assert stats['invalid_rows_removed'] == 1
    assert stats['total_clean'] == 0


def test_clean_records_drops_out_of_range_anomaly_score():
    clean, stats = clean_records([_base_row(anomaly_score='1.5')])
    assert stats['invalid_rows_removed'] == 1
    assert stats['total_clean'] == 0


def test_validate_columns_detects_missing_required():
    detected, missing = validate_columns([{'event_category': 'x'}])
    assert 'protocol' in missing
    assert 'event_category' not in missing


def test_validate_columns_empty_records():
    detected, missing = validate_columns([])
    assert detected == []
    assert missing == list(REQUIRED_COLUMNS)


def test_apply_mapping_renames_source_columns():
    records = [{'cat': 'malware', 'other': 'x'}]
    mapped = apply_mapping(records, {'event_category': 'cat'})
    assert mapped[0]['event_category'] == 'malware'
    assert 'cat' not in mapped[0]


def test_parse_file_json_normalizes_keys():
    content = json.dumps([{'Event Category': 'malware', 'Protocol': 'tcp'}]).encode()
    file = SimpleUploadedFile('alerts.json', content, content_type='application/json')
    records, error = parse_file(file)
    assert error is None
    assert records[0]['event_category'] == 'malware'


def test_parse_file_csv_parses_rows():
    csv_content = 'event_category,protocol\nmalware,tcp\n'.encode()
    file = SimpleUploadedFile('alerts.csv', csv_content, content_type='text/csv')
    records, error = parse_file(file)
    assert error is None
    assert records[0]['event_category'] == 'malware'


def test_parse_file_invalid_json_returns_error():
    file = SimpleUploadedFile('alerts.json', b'{not valid json', content_type='application/json')
    records, error = parse_file(file)
    assert records is None
    assert error is not None


def test_parse_file_unsupported_extension_returns_error():
    file = SimpleUploadedFile('alerts.txt', b'data', content_type='text/plain')
    records, error = parse_file(file)
    assert records is None
    assert 'no soportado' in error
