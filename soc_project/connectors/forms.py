from django import forms

from .models import SIEMConnector

INPUT_CLASS = (
    'w-full bg-slate-700 border border-slate-600 text-slate-100 '
    'placeholder:text-slate-500 rounded-md px-3 py-2 text-sm '
    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
)
SELECT_CLASS = (
    'w-full bg-slate-700 border border-slate-600 text-slate-100 '
    'rounded-md px-3 py-2 text-sm '
    'focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
)

SEVERITY_CHOICES = [('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('CRITICAL', 'Critical')]

# Qué campos de credenciales pide cada SIEM — controla tanto la validación
# server-side (clean()) como qué bloque de inputs muestra el JS del template
# según el <select> de source_type. 'None' es a propósito en los tipos cuyo
# set de credenciales depende también de auth_type, no solo del source_type
# — ver AUTH_TYPE_CREDENTIAL_FIELDS + required_credential_fields() más abajo.
CREDENTIAL_FIELDS_BY_TYPE = {
    'splunk':       None,  # depende de auth_type: user_password | bearer_token
    'sentinel':     ['tenant_id', 'client_id', 'client_secret'],
    'qradar':       ['sec_token'],
    'elastic':      None,  # depende de auth_type: api_key | user_password
    'wazuh':        None,  # depende de auth_type: api_key | user_password
    'cortex_xsiam': ['api_key_id', 'api_key'],
    # XDRs — mismas formas de auth que ya existían en algún SIEM, reutilizadas tal cual.
    'crowdstrike':  ['client_id', 'client_secret'],           # OAuth2 client credentials
    'defender_xdr': ['tenant_id', 'client_id', 'client_secret'],  # idéntico a Sentinel (mismo Azure AD)
    'cortex_xdr':   ['api_key_id', 'api_key'],                # idéntico a Cortex XSIAM
    'trendmicro':   ['api_token'],                            # token estático de larga duración
}

AUTH_TYPE_CREDENTIAL_FIELDS = {
    'user_password': ['username', 'password'],
    'bearer_token':  ['api_token'],
    'api_key':       ['api_key'],
}

# Qué opciones de auth_type tiene sentido ofrecer por tipo — Splunk no hace
# Basic+API Key como Elastic, cada uno tiene su propio par. Tipos ausentes aquí
# (sentinel/qradar/cortex_xsiam) no usan auth_type — su auth es fija.
AUTH_TYPE_CHOICES_BY_TYPE = {
    'splunk':  ['user_password', 'bearer_token'],
    'elastic': ['api_key', 'user_password'],
    'wazuh':   ['api_key', 'user_password'],
}

# Config no-secreta específica de cada tipo — ver EXTRA_CONFIG_FIELD_LABELS en models.py.
EXTRA_CONFIG_FIELDS_BY_TYPE = {
    'sentinel':     ['subscription_id', 'resource_group', 'workspace_name'],
    'elastic':      ['index_pattern'],
    'wazuh':        ['index_pattern'],
    'cortex_xsiam': ['min_severity'],
    'defender_xdr': ['min_severity'],
}

# Qué campo de la config (custom_query) tiene cada tipo, y cómo se llama en su propio lenguaje —
# usado solo por el JS del template para reetiquetar el mismo <textarea>/<input>.
QUERY_LANGUAGE_LABEL_BY_TYPE = {
    'splunk':      'Consulta SPL',
    'sentinel':    'Filtro KQL',
    'qradar':      'Filtro AQL',
    'crowdstrike': 'Filtro FQL',
}

# Qué campos del bloque "Configuración avanzada" se muestran para cada tipo —
# única fuente de verdad, tanto para el JS de visibilidad como para no
# repetir el mismo <select>/<input> en varios bloques del template (cada
# campo del form se renderiza UNA sola vez en el HTML; el JS solo lo mueve
# de visible a oculto según el tipo elegido).
ADV_FIELDS_BY_TYPE = {
    'splunk':       ['auth_type', 'custom_query', 'batch_size'],
    'sentinel':     ['subscription_id', 'resource_group', 'workspace_name', 'custom_query'],
    'qradar':       ['custom_query'],
    'elastic':      ['auth_type', 'index_pattern'],
    'wazuh':        ['auth_type', 'index_pattern'],
    'cortex_xsiam': ['min_severity'],
    'crowdstrike':  ['custom_query'],
    'defender_xdr': ['min_severity'],
    # cortex_xdr y trendmicro no tienen campos avanzados propios en el mapeo —
    # solo host + credenciales, igual que Cortex XSIAM sin el filtro de severidad.
}

_CREDENTIAL_FIELD_NAMES = (
    'username', 'password', 'api_key', 'api_key_id',
    'tenant_id', 'client_id', 'client_secret', 'sec_token', 'api_token',
)
_EXTRA_CONFIG_FIELD_NAMES = (
    'subscription_id', 'resource_group', 'workspace_name', 'index_pattern', 'min_severity',
)


def required_credential_fields(source_type, auth_type):
    """Qué claves de `credentials` hacen falta para este conector, dado su
    tipo (y, para los tipos con auth_type variable, también el método elegido)."""
    fixed = CREDENTIAL_FIELDS_BY_TYPE.get(source_type)
    if fixed is not None:
        return fixed
    return AUTH_TYPE_CREDENTIAL_FIELDS.get(auth_type, [])


def required_extra_fields(source_type):
    """Qué claves de `extra_config` hacen falta para este tipo de SIEM."""
    return EXTRA_CONFIG_FIELDS_BY_TYPE.get(source_type, [])


class SIEMConnectorForm(forms.ModelForm):
    # Credenciales (van a `credentials`, nunca se re-muestran en texto plano)
    username = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}))
    password = forms.CharField(required=False, widget=forms.PasswordInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'new-password'}, render_value=False))
    api_key = forms.CharField(required=False, widget=forms.PasswordInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}, render_value=False))
    api_key_id = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}))
    tenant_id = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}))
    client_id = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}))
    client_secret = forms.CharField(required=False, widget=forms.PasswordInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}, render_value=False))
    sec_token = forms.CharField(required=False, widget=forms.PasswordInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}, render_value=False))
    api_token = forms.CharField(required=False, widget=forms.PasswordInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}, render_value=False))

    # Config no-secreta (van a `extra_config`, sí se re-muestran al editar)
    subscription_id = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}))
    resource_group = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}))
    workspace_name = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': INPUT_CLASS, 'autocomplete': 'off'}))
    index_pattern = forms.CharField(required=False, widget=forms.TextInput(attrs={'class': INPUT_CLASS + ' font-mono', 'autocomplete': 'off'}))
    min_severity = forms.ChoiceField(required=False, choices=SEVERITY_CHOICES, widget=forms.Select(attrs={'class': SELECT_CLASS}))

    class Meta:
        model = SIEMConnector
        fields = [
            'name', 'source_type', 'host', 'port', 'auth_type',
            'custom_query', 'batch_size', 'verify_ssl',
            'poll_interval_minutes', 'is_active',
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': INPUT_CLASS, 'placeholder': 'ej: Splunk SOC principal'}),
            'source_type': forms.Select(attrs={'class': SELECT_CLASS}),
            'host': forms.TextInput(attrs={'class': INPUT_CLASS, 'placeholder': 'localhost'}),
            'port': forms.NumberInput(attrs={'class': INPUT_CLASS, 'min': 1, 'max': 65535, 'placeholder': '8089'}),
            'auth_type': forms.Select(attrs={'class': SELECT_CLASS}),
            'custom_query': forms.TextInput(attrs={'class': INPUT_CLASS + ' font-mono', 'placeholder': 'search index=soc_alerts'}),
            'batch_size': forms.NumberInput(attrs={'class': INPUT_CLASS, 'min': 1}),
            'verify_ssl': forms.CheckboxInput(attrs={'class': 'w-4 h-4 text-blue-500 bg-slate-700 border-slate-600 rounded'}),
            'poll_interval_minutes': forms.NumberInput(attrs={'class': INPUT_CLASS, 'min': 1}),
            'is_active': forms.CheckboxInput(attrs={'class': 'w-4 h-4 text-blue-500 bg-slate-700 border-slate-600 rounded'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['data-testid'] = f'connector-{field_name.replace("_", "-")}'
        for field_name in _CREDENTIAL_FIELD_NAMES:
            self.fields[field_name].widget.attrs['data-siem-field'] = field_name
        for field_name in _EXTRA_CONFIG_FIELD_NAMES:
            self.fields[field_name].widget.attrs['data-siem-field'] = field_name

    def clean(self):
        cleaned = super().clean()
        source_type = cleaned.get('source_type')
        auth_type = cleaned.get('auth_type')
        existing_credentials = self.instance.credentials if self.instance.pk else {}
        existing_extra = self.instance.extra_config if self.instance.pk else {}

        missing_creds = [
            f for f in required_credential_fields(source_type, auth_type)
            if not cleaned.get(f) and not existing_credentials.get(f)
        ]
        missing_extra = [
            f for f in required_extra_fields(source_type)
            if not cleaned.get(f) and not existing_extra.get(f)
        ]
        missing = missing_creds + missing_extra
        if missing:
            type_label = dict(SIEMConnector.SOURCE_CHOICES).get(source_type, source_type)
            raise forms.ValidationError(f'Para "{type_label}" faltan campos: {", ".join(missing)}.')
        return cleaned

    def build_credentials(self):
        """Combina lo tipeado en este submit con lo ya guardado — un campo
        vacío en edición NO borra la credencial existente (nunca se
        re-muestra el valor real en el form por seguridad, así que "vacío"
        significa "no lo toqué", no "borralo")."""
        existing = dict(self.instance.credentials) if self.instance.pk else {}
        for field_name in _CREDENTIAL_FIELD_NAMES:
            value = self.cleaned_data.get(field_name)
            if value:
                existing[field_name] = value
        relevant = set(required_credential_fields(self.cleaned_data['source_type'], self.cleaned_data.get('auth_type')))
        return {k: v for k, v in existing.items() if k in relevant}

    def build_extra_config(self):
        """Igual que build_credentials(), pero para config no-secreta — aquí
        además el form SÍ prefillea el valor existente al editar (ver
        connector_edit_view), así que en la práctica el campo nunca llega
        vacío salvo que el usuario lo borre a propósito."""
        existing = dict(self.instance.extra_config) if self.instance.pk else {}
        for field_name in _EXTRA_CONFIG_FIELD_NAMES:
            value = self.cleaned_data.get(field_name)
            if value:
                existing[field_name] = value
            elif field_name in required_extra_fields(self.cleaned_data['source_type']):
                existing.pop(field_name, None)
        relevant = set(required_extra_fields(self.cleaned_data['source_type']))
        return {k: v for k, v in existing.items() if k in relevant}
