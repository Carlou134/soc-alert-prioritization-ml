import json

import pytest
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

CLASSES = {'benigno', 'a_investigar', 'malicioso'}


def _auth_client(user):
    client = APIClient()
    token = RefreshToken.for_user(user)
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {token.access_token}')
    return client


@pytest.mark.django_db
def test_predict_api_requires_authentication(valid_record):
    client = APIClient()
    resp = client.post('/api/predict/', data=valid_record, format='json')
    assert resp.status_code == 401


@pytest.mark.django_db
def test_predict_api_returns_prediction_for_valid_payload(analyst_n1_user, valid_record):
    client = _auth_client(analyst_n1_user)
    resp = client.post('/api/predict/', data=valid_record, format='json')
    assert resp.status_code == 200
    body = resp.json()
    assert body['predicted_class'] in CLASSES
    assert set(body['probabilities'].keys()) == CLASSES


@pytest.mark.django_db
def test_predict_api_rejects_missing_required_fields(analyst_n1_user):
    client = _auth_client(analyst_n1_user)
    resp = client.post('/api/predict/', data={'event_category': 'malware'}, format='json')
    assert resp.status_code == 400


@pytest.mark.django_db
def test_upload_alerts_api_processes_valid_json_file(analyst_n1_user, valid_record, benign_record):
    client = _auth_client(analyst_n1_user)
    payload = json.dumps([valid_record, benign_record]).encode()
    upload = SimpleUploadedFile('alerts.json', payload, content_type='application/json')
    resp = client.post('/api/upload-alerts/', data={'file': upload}, format='multipart')
    assert resp.status_code == 200
    body = resp.json()
    assert body['success'] is True
    assert body['processed'] == 2
    assert body['failed'] == 0
    assert {r['predicted_class'] for r in body['results']}.issubset(CLASSES)


@pytest.mark.django_db
def test_upload_alerts_api_reports_partial_failures(analyst_n1_user, valid_record):
    client = _auth_client(analyst_n1_user)
    bad_record = {'event_category': 'malware'}  # falta la mayoría de los campos requeridos
    payload = json.dumps([valid_record, bad_record]).encode()
    upload = SimpleUploadedFile('alerts.json', payload, content_type='application/json')
    resp = client.post('/api/upload-alerts/', data={'file': upload}, format='multipart')
    assert resp.status_code == 200
    body = resp.json()
    assert body['processed'] == 1
    assert body['failed'] == 1
    assert body['errors'][0]['record'] == 2


@pytest.mark.django_db
def test_upload_alerts_api_rejects_empty_file(analyst_n1_user):
    client = _auth_client(analyst_n1_user)
    upload = SimpleUploadedFile('alerts.json', b'', content_type='application/json')
    resp = client.post('/api/upload-alerts/', data={'file': upload}, format='multipart')
    assert resp.status_code == 400


@pytest.mark.django_db
def test_upload_alerts_api_rejects_unsupported_extension(analyst_n1_user):
    client = _auth_client(analyst_n1_user)
    upload = SimpleUploadedFile('alerts.txt', b'data', content_type='text/plain')
    resp = client.post('/api/upload-alerts/', data={'file': upload}, format='multipart')
    assert resp.status_code == 400


@pytest.mark.django_db
def test_upload_alerts_api_requires_authentication():
    client = APIClient()
    upload = SimpleUploadedFile('alerts.json', b'[]', content_type='application/json')
    resp = client.post('/api/upload-alerts/', data={'file': upload}, format='multipart')
    assert resp.status_code == 401
