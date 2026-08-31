# -*- coding: utf-8 -*-
"""
Lectura en runtime del cache local de metadata MITRE ATT&CK
(generado offline por `python manage.py sync_mitre_attack`, ver
predictor/management/commands/sync_mitre_attack.py). Nunca hace
llamadas de red — solo lee el JSON versionado en el repo.
"""
import json
from pathlib import Path

DATA_PATH = Path(__file__).resolve().parent / 'data' / 'mitre_technique_metadata.json'

_cache = None


def _load() -> dict:
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(DATA_PATH.read_text(encoding='utf-8'))
        except FileNotFoundError:
            _cache = {}
    return _cache


def resolve_techniques(raw: str) -> list:
    """
    'T1110;T1078.004' -> [{'code': 'T1110', 'name': 'Brute Force', ...}, ...]
    Códigos sin metadata sincronizada (modelo reentrenado sin sync_mitre_attack
    corrido de nuevo) devuelven solo el code, sin romper el template.
    """
    if not raw:
        return []
    metadata = _load()
    techniques = []
    for part in str(raw).split(';'):
        code = part.strip().upper()
        if not code:
            continue
        info = metadata.get(code, {})
        techniques.append({
            'code': code,
            'name': info.get('name'),
            'description': info.get('description'),
            'url': info.get('url'),
            'tactics': info.get('tactics', []),
        })
    return techniques
