from django import forms
import json

INPUT_CLASS = 'w-full bg-slate-700 border border-slate-600 text-slate-100 placeholder:text-slate-500 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
TEXTAREA_CLASS = 'w-full bg-slate-700 border border-slate-600 text-slate-100 placeholder:text-slate-500 rounded-md px-3 py-3 h-72 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
SELECT_CLASS = 'w-full bg-slate-700 border border-slate-600 text-slate-100 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'

# Los valores de los choices deben coincidir exactamente con los del dataset de entrenamiento.
EVENT_CATEGORY_CHOICES = [
    ('', '---'),
    ('command_and_control', 'Command & Control'),
    ('credential_access', 'Credential Access'),
    ('data_collection', 'Data Collection'),
    ('data_exfiltration', 'Data Exfiltration'),
    ('evasion', 'Evasion'),
    ('execution', 'Execution'),
    ('impact', 'Impact'),
    ('intrusion_attempt', 'Intrusion Attempt'),
    ('lateral_movement', 'Lateral Movement'),
    ('malware_activity', 'Malware Activity'),
    ('other', 'Other'),
    ('persistence', 'Persistence'),
    ('privilege_escalation', 'Privilege Escalation'),
    ('reconnaissance', 'Reconnaissance'),
    ('suspicious_activity', 'Suspicious Activity'),
]
PROTOCOL_CHOICES = [('', '---'), ('tcp', 'TCP'), ('udp', 'UDP')]
TRAFFIC_TYPE_CHOICES = [
    ('', '---'),
    ('dns', 'DNS'), ('ftp', 'FTP'), ('http', 'HTTP'), ('https', 'HTTPS'),
    ('icmp', 'ICMP'), ('ldap', 'LDAP'), ('rpc', 'RPC'),
    ('smb', 'SMB'), ('ssh', 'SSH'), ('tcp', 'TCP'),
]
MITRE_TACTIC_CHOICES = [
    ('', '---'),
    ('collection', 'Collection'),
    ('command and control', 'Command and Control'),
    ('credential access', 'Credential Access'),
    ('defense evasion', 'Defense Evasion'),
    ('discovery', 'Discovery'),
    ('execution', 'Execution'),
    ('exfiltration', 'Exfiltration'),
    ('impact', 'Impact'),
    ('initial access', 'Initial Access'),
    ('lateral movement', 'Lateral Movement'),
    ('persistence', 'Persistence'),
    ('privilege escalation', 'Privilege Escalation'),
    ('unknown', 'Unknown'),
]
KILL_CHAIN_CHOICES = [
    ('', '---'),
    ('collection', 'Collection'),
    ('command & control', 'Command & Control'),
    ('credential access', 'Credential Access'),
    ('defense evasion', 'Defense Evasion'),
    ('exfiltration', 'Exfiltration'),
    ('exploitation', 'Exploitation'),
    ('impact', 'Impact'),
    ('initial access', 'Initial Access'),
    ('lateral movement', 'Lateral Movement'),
    ('persistence', 'Persistence'),
    ('privilege escalation', 'Privilege Escalation'),
    ('reconnaissance', 'Reconnaissance'),
    ('unknown', 'Unknown'),
]
IDS_IPS_CHOICES = [
    ('', '---'),
    ('confirmed malicious indicator', 'Confirmed Malicious Indicator'),
    ('no alert', 'No Alert'),
    ('suspicious pattern', 'Suspicious Pattern'),
    ('unknown', 'Unknown'),
]
CRITICALITY_CHOICES = [('', '---'), ('low', 'Low'), ('medium', 'Medium'), ('high', 'High')]
LOG_SOURCE_CHOICES = [
    ('', '---'),
    ('edr', 'EDR'), ('firewall', 'Firewall'), ('ips', 'IPS'),
    ('siem', 'SIEM'), ('waf', 'WAF'),
]
FIREWALL_CHOICES = [('', '---'), ('blocked', 'Blocked'), ('unknown', 'Unknown')]
SEVERITY_CHOICES = [('', '---'), ('low', 'Low'), ('medium', 'Medium'), ('critical', 'Critical'), ('unknown', 'Unknown')]


class PredictionForm(forms.Form):
    event_category = forms.ChoiceField(
        label='Categoría del evento',
        choices=EVENT_CATEGORY_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    attack_type = forms.CharField(label='Tipo de ataque', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    attack_signature = forms.CharField(label='Firma del ataque', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    protocol = forms.ChoiceField(
        label='Protocolo',
        choices=PROTOCOL_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    traffic_type = forms.ChoiceField(
        label='Tipo de tráfico',
        choices=TRAFFIC_TYPE_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    mitre_tactic = forms.ChoiceField(
        label='Táctica MITRE',
        choices=MITRE_TACTIC_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    kill_chain_stage = forms.ChoiceField(
        label='Kill Chain Stage',
        choices=KILL_CHAIN_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    ids_ips_alert = forms.ChoiceField(
        label='Alerta IDS/IPS',
        choices=IDS_IPS_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    malware_indicator = forms.CharField(label='Indicador de malware', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    asset_criticality = forms.ChoiceField(
        label='Criticidad del activo',
        choices=CRITICALITY_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
    log_source = forms.ChoiceField(
        label='Fuente de log',
        choices=LOG_SOURCE_CHOICES,
        widget=forms.Select(attrs={'class': SELECT_CLASS})
    )
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
                '  "event_category": "intrusion_attempt",\n'
                '  "attack_type": "brute force",\n'
                '  "attack_signature": "SSH Brute Force",\n'
                '  "protocol": "tcp",\n'
                '  "traffic_type": "ssh",\n'
                '  "mitre_tactic": "initial access",\n'
                '  "kill_chain_stage": "initial access",\n'
                '  "ids_ips_alert": "suspicious pattern",\n'
                '  "malware_indicator": "no",\n'
                '  "asset_criticality": "high",\n'
                '  "log_source": "firewall",\n'
                '  "firewall_action": "blocked",\n'
                '  "severity": "critical",\n'
                '  "failed_login_attempts": 15,\n'
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
