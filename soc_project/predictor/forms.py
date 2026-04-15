from django import forms
import json

INPUT_CLASS = 'w-full bg-slate-700 border border-slate-600 text-slate-100 placeholder:text-slate-500 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
TEXTAREA_CLASS = 'w-full bg-slate-700 border border-slate-600 text-slate-100 placeholder:text-slate-500 rounded-md px-3 py-3 h-72 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
SELECT_CLASS = 'w-full bg-slate-700 border border-slate-600 text-slate-100 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'

SEVERITY_CHOICES = [('', '---'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')]
FIREWALL_CHOICES = [('', '---'), ('allow', 'Allow'), ('deny', 'Deny'), ('drop', 'Drop'), ('reject', 'Reject')]
CRITICALITY_CHOICES = [('', '---'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')]


class PredictionForm(forms.Form):
    event_category = forms.CharField(label='Categoría del evento', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    attack_type = forms.CharField(label='Tipo de ataque', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    attack_signature = forms.CharField(label='Firma del ataque', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    protocol = forms.CharField(label='Protocolo', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    traffic_type = forms.CharField(label='Tipo de tráfico', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    mitre_tactic = forms.CharField(label='Táctica MITRE', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    kill_chain_stage = forms.CharField(label='Kill Chain Stage', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    ids_ips_alert = forms.CharField(label='Alerta IDS/IPS', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    malware_indicator = forms.CharField(label='Indicador de malware', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    asset_criticality = forms.ChoiceField(
        label='Criticidad del activo',
        choices=CRITICALITY_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    log_source = forms.CharField(label='Fuente de log', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    firewall_action = forms.ChoiceField(
        label='Acción del firewall',
        choices=FIREWALL_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    severity = forms.ChoiceField(
        label='Severidad',
        choices=SEVERITY_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    failed_login_attempts = forms.IntegerField(
        label='Intentos fallidos de login',
        min_value=0,
        widget=forms.NumberInput(attrs={'class': INPUT_CLASS})
    )
    request_rate_per_min = forms.FloatField(
        label='Request rate por minuto',
        min_value=0.0,
        widget=forms.NumberInput(attrs={'class': INPUT_CLASS, 'step': '0.1'})
    )


class JSONPredictionForm(forms.Form):
    payload = forms.CharField(
        label='Pega tu JSON',
        widget=forms.Textarea(attrs={
            'class': TEXTAREA_CLASS,
            'placeholder': (
                '{\n'
                '  "event_category": "network",\n'
                '  "attack_type": "ddos",\n'
                '  "attack_signature": "SYN Flood",\n'
                '  "protocol": "tcp",\n'
                '  "traffic_type": "malicious",\n'
                '  "mitre_tactic": "initial-access",\n'
                '  "kill_chain_stage": "delivery",\n'
                '  "ids_ips_alert": "yes",\n'
                '  "malware_indicator": "no",\n'
                '  "asset_criticality": "high",\n'
                '  "log_source": "firewall",\n'
                '  "firewall_action": "deny",\n'
                '  "severity": "high",\n'
                '  "failed_login_attempts": 5,\n'
                '  "request_rate_per_min": 320.5\n'
                '}'
            )
        })
    )

    def clean_payload(self):
        raw = self.cleaned_data['payload']
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            raise forms.ValidationError('El JSON no es válido.')

        if not isinstance(data, dict):
            raise forms.ValidationError('El JSON debe ser un objeto.')

        required_fields = [
            'event_category', 'attack_type', 'attack_signature', 'protocol',
            'traffic_type', 'mitre_tactic', 'kill_chain_stage', 'ids_ips_alert',
            'malware_indicator', 'asset_criticality', 'log_source', 'firewall_action',
            'severity', 'failed_login_attempts', 'request_rate_per_min',
        ]
        missing = [f for f in required_fields if f not in data or data[f] is None]
        if missing:
            raise forms.ValidationError(f'Campos faltantes: {", ".join(missing)}')

        return data
