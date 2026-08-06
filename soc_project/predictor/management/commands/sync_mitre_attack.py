# -*- coding: utf-8 -*-
"""
Sincroniza metadata real de MITRE ATT&CK (nombre, descripción, URL, tácticas)
para las técnicas que el modelo ML conoce (columnas mitre_tNNNN de
training_columns en soc_model.pkl).

No corre en request-time ni en producción — es un comando manual que un dev
ejecuta cuando el modelo se reentrena con técnicas nuevas. El resultado se
guarda en predictor/data/mitre_technique_metadata.json, versionado en git,
y la app lo lee de ahí en runtime sin depender de red.

Uso: python manage.py sync_mitre_attack
"""
import json
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from django.core.management.base import BaseCommand

STIX_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
OUTPUT_PATH = Path(__file__).resolve().parent.parent.parent / 'data' / 'mitre_technique_metadata.json'


class Command(BaseCommand):
    help = 'Descarga metadata oficial de MITRE ATT&CK para las técnicas usadas por el modelo ML.'

    def handle(self, *args, **options):
        technique_ids = self._get_model_technique_ids()
        if not technique_ids:
            self.stderr.write(self.style.ERROR(
                'No se pudo leer training_columns del modelo (soc_model.pkl). Abortando.'
            ))
            return
        self.stdout.write(f'Técnicas requeridas por el modelo: {sorted(technique_ids)}')

        raw_bundle = self._download_stix_bundle()
        metadata = self._extract_metadata(raw_bundle, technique_ids)

        missing = technique_ids - metadata.keys()
        if missing:
            self.stdout.write(self.style.WARNING(
                f'No encontradas en el bundle de MITRE (revocadas/deprecadas/ID inválido?): {sorted(missing)}'
            ))

        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT_PATH.write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True),
            encoding='utf-8',
        )
        self.stdout.write(self.style.SUCCESS(
            f'{len(metadata)} técnicas guardadas en {OUTPUT_PATH}'
        ))

    def _get_model_technique_ids(self) -> set:
        """mitre_t1078_004 (columna del modelo) -> 'T1078.004' (ID real de MITRE)."""
        import predictor.utils as utils_module

        if not utils_module._load_model():
            return set()

        ids = set()
        for col in utils_module.training_columns:
            m = re.match(r'^mitre_t(\d+)(?:_(\d+))?$', col)
            if m:
                base, sub = m.groups()
                ids.add(f'T{base}' + (f'.{sub}' if sub else ''))
        return ids

    def _download_stix_bundle(self) -> dict:
        """
        Intenta con urllib (portable, sin dependencias nuevas). Si falla por
        certificado (típico detrás de un proxy corporativo que reemplaza la
        cadena de confianza y que Python no reconoce aunque el SO sí), cae a
        curl como subprocess — usa el almacén de certificados del SO.
        """
        try:
            with urllib.request.urlopen(STIX_URL, timeout=90) as resp:
                self.stdout.write('Bundle descargado con urllib.')
                return json.load(resp)
        except urllib.error.URLError:
            self.stdout.write(self.style.WARNING(
                'urllib no pudo conectar/verificar el certificado (proxy/antivirus local?) — reintentando con curl.'
            ))
            with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
                tmp_path = tmp.name
            subprocess.run(['curl', '-sL', '-o', tmp_path, STIX_URL], check=True, timeout=120)
            with open(tmp_path, encoding='utf-8') as f:
                return json.load(f)

    def _extract_metadata(self, bundle: dict, technique_ids: set) -> dict:
        result = {}
        for obj in bundle.get('objects', []):
            if obj.get('type') != 'attack-pattern':
                continue
            if obj.get('revoked') or obj.get('x_mitre_deprecated'):
                continue

            ext_id, url = None, None
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    ext_id, url = ref.get('external_id'), ref.get('url')
                    break

            if ext_id not in technique_ids:
                continue

            description = (obj.get('description') or '').strip()
            description = re.sub(r'\(Citation:[^)]*\)', '', description).strip()
            first_sentence = description.split('. ')[0].strip()
            if len(first_sentence) > 240:
                first_sentence = first_sentence[:237].rstrip() + '...'
            elif description and not first_sentence.endswith('.'):
                first_sentence += '.'

            tactics = [
                kc['phase_name'].replace('-', ' ')
                for kc in obj.get('kill_chain_phases', [])
                if kc.get('kill_chain_name') == 'mitre-attack'
            ]

            result[ext_id] = {
                'name': obj.get('name'),
                'description': first_sentence,
                'url': url,
                'tactics': tactics,
            }
        return result
