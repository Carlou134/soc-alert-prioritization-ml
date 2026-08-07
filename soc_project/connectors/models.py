from django.contrib.auth.models import User
from django.db import models

# Campos de credenciales que existen en el universo de SIEMs soportados —
# unión de todos los tipos. Cada source_type solo usa un subconjunto
# (ver CREDENTIAL_FIELDS_BY_TYPE en forms.py). Guardado como JSONField en vez
# de columnas propias porque cada SIEM tiene una forma de auth distinta
# (OAuth, API key dual-header, Basic, token de sesión) — ver el mapeo que
# armamos con el usuario en el chat: Sentinel (OAuth), Cortex XSIAM
# (x-xdr-auth-id + Authorization), QRadar (header SEC), Elastic (ApiKey),
# Wazuh (JWT vía user/pass), Splunk (user/pass, job de búsqueda).
CREDENTIAL_FIELD_LABELS = {
    'username': 'Usuario',
    'password': 'Contraseña',
    'api_key': 'API Key',
    'api_key_id': 'API Key ID',
    'tenant_id': 'Tenant ID',
    'client_id': 'Client ID',
    'client_secret': 'Client Secret',
    'sec_token': 'SEC Token',
    'api_token': 'API Token',
}

# Config estructural NO secreta, específica de cada tipo de SIEM — separada
# a propósito de `credentials` (que es solo para secretos). Ej: subscription_id
# de Sentinel no es un secreto, no tiene sentido esconderlo como si lo fuera.
EXTRA_CONFIG_FIELD_LABELS = {
    'subscription_id': 'Subscription ID',
    'resource_group':  'Resource Group',
    'workspace_name':  'Workspace Name/ID',
    'index_pattern':   'Patrón de índice',
    'min_severity':    'Severidad mínima',
}


class SIEMConnector(models.Model):
    SOURCE_CHOICES = [
        # SIEM — centraliza logs crudos
        ('splunk', 'Splunk Enterprise / Cloud'),
        ('sentinel', 'Microsoft Sentinel'),
        ('qradar', 'IBM QRadar'),
        ('elastic', 'Elastic Security'),
        ('wazuh', 'Wazuh'),
        ('cortex_xsiam', 'Cortex XSIAM (Palo Alto)'),
        # XDR — entrega incidentes ya correlacionados/enriquecidos (MITRE ATT&CK)
        ('crowdstrike', 'CrowdStrike Falcon Insight XDR'),
        ('defender_xdr', 'Microsoft Defender XDR'),
        ('cortex_xdr', 'Cortex XDR (Palo Alto)'),
        ('trendmicro', 'Trend Micro Vision One'),
    ]
    # Pura función de source_type, no un campo propio — la categoría de un
    # conector no es algo que el admin deba poder desincronizar de su tipo
    # (no tendría sentido marcar "CrowdStrike" como categoría SIEM). Se
    # deriva aquí en vez de guardarse en una columna aparte.
    SOURCE_CATEGORY = {
        'splunk': 'SIEM', 'sentinel': 'SIEM', 'qradar': 'SIEM',
        'elastic': 'SIEM', 'wazuh': 'SIEM', 'cortex_xsiam': 'SIEM',
        'crowdstrike': 'XDR', 'defender_xdr': 'XDR', 'cortex_xdr': 'XDR', 'trendmicro': 'XDR',
    }
    STATUS_CHOICES = [
        ('not_tested', 'No probado'),
        ('connected', 'Conectado'),
        ('error', 'Error de conexión'),
    ]
    # Splunk y Elastic/Wazuh usan esta elección (Sentinel/QRadar/Cortex XSIAM
    # tienen un único método de auth fijo por tipo — ver CREDENTIAL_FIELDS_BY_TYPE
    # en forms.py). Se deja genérico en el modelo para no tener que migrar
    # de nuevo cuando otro SIEM sume su propia variante de auth.
    AUTH_TYPE_CHOICES = [
        ('user_password', 'Usuario y contraseña'),
        ('bearer_token', 'Token (Bearer)'),
        ('api_key', 'API Key'),
    ]

    name = models.CharField(max_length=100)
    source_type = models.CharField(max_length=20, choices=SOURCE_CHOICES)

    # Reemplaza a un base_url único — más claro para el analista (typea
    # "localhost", no "https://localhost:8089") y permite precargar el
    # puerto por defecto de cada SIEM (8089 en Splunk).
    host = models.CharField(max_length=255, help_text='Host o IP del servidor, sin esquema (ej: localhost, splunk.miempresa.com)')
    port = models.PositiveIntegerField(null=True, blank=True)

    auth_type = models.CharField(max_length=20, choices=AUTH_TYPE_CHOICES, default='user_password')

    # Lenguaje nativo de consulta del SIEM — SPL en Splunk, KQL en Sentinel,
    # AQL en QRadar. Reetiquetado por tipo en el JS del template.
    custom_query = models.TextField(blank=True)
    batch_size = models.PositiveIntegerField(default=50)
    verify_ssl = models.BooleanField(default=True)

    # Config no-secreta específica de cada tipo (subscription_id/resource_group/
    # workspace_name en Sentinel, index_pattern en Elastic/Wazuh, min_severity
    # en Cortex XSIAM). Se separa de `credentials` porque no son secretos —
    # ver EXTRA_CONFIG_FIELD_LABELS. Igual que `credentials`, cada source_type
    # usa solo el subconjunto que le corresponde (ver EXTRA_CONFIG_FIELDS_BY_TYPE
    # en forms.py). Campos usados por un solo tipo van aquí en vez de ser
    # columnas propias — evita agregar 4+ columnas casi siempre NULL a la tabla.
    extra_config = models.JSONField(default=dict, blank=True)

    poll_interval_minutes = models.PositiveIntegerField(default=5)
    is_active = models.BooleanField(default=True)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='not_tested')
    last_tested_at = models.DateTimeField(null=True, blank=True)
    last_test_message = models.CharField(max_length=255, blank=True)

    # Checkpointing de ingesta incremental — lo va a setear el worker real
    # (no implementado todavía) después de cada sync exitoso, para pedirle
    # al SIEM solo lo nuevo desde aquí y no reprocesar alertas ya traídas.
    # No es un campo del form: es de solo lectura para el analista.
    last_synced_at = models.DateTimeField(null=True, blank=True)

    # Nunca se vuelve a mostrar en texto plano en ningún template — solo se
    # informa qué claves están configuradas (ver masked_credential_fields()).
    credentials = models.JSONField(default=dict, blank=True)

    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='+')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Conector SOC'
        verbose_name_plural = 'Conectores SOC'

    def __str__(self):
        return f'{self.name} ({self.get_source_type_display()})'

    @property
    def category(self):
        return self.SOURCE_CATEGORY.get(self.source_type, 'SIEM')

    @property
    def connection_url(self):
        """https://{host}:{port} — usado por el futuro worker real, no por la UI."""
        if not self.host:
            return ''
        return f'https://{self.host}:{self.port}' if self.port else f'https://{self.host}'

    def masked_credential_fields(self):
        """Lista de campos de credenciales configurados, sin exponer valores."""
        return [
            {'key': k, 'label': CREDENTIAL_FIELD_LABELS.get(k, k)}
            for k, v in (self.credentials or {}).items() if v
        ]

    def configured_extra_fields(self):
        """Config no-secreta configurada, CON su valor — a diferencia de las
        credenciales, esto no es sensible y sí tiene sentido mostrarlo."""
        return [
            {'key': k, 'label': EXTRA_CONFIG_FIELD_LABELS.get(k, k), 'value': v}
            for k, v in (self.extra_config or {}).items() if v
        ]
