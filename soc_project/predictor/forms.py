from django import forms
import json

INPUT_CLASS = 'w-full rounded-xl border border-slate-300 px-4 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500'
TEXTAREA_CLASS = 'w-full rounded-xl border border-slate-300 px-4 py-3 h-72 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500'

class PredictionForm(forms.Form):
    source_port = forms.IntegerField(label='Puerto origen', widget=forms.NumberInput(attrs={'class': INPUT_CLASS}))
    destination_port = forms.IntegerField(label='Puerto destino', widget=forms.NumberInput(attrs={'class': INPUT_CLASS}))
    protocol = forms.CharField(label='Protocolo', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    traffic_type = forms.CharField(label='Tipo de tráfico', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    host_affected = forms.CharField(label='Host afectado', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    event_category = forms.CharField(label='Categoría del evento', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    mitre_tactic = forms.CharField(label='Táctica MITRE', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    kill_chain_stage = forms.CharField(label='Kill Chain Stage', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    log_source = forms.CharField(label='Fuente de log', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    firewall_action = forms.CharField(label='Acción del firewall', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    anomaly_score = forms.FloatField(label='Anomaly score', widget=forms.NumberInput(attrs={'class': INPUT_CLASS, 'step': '0.01'}))
    failed_login_attempts = forms.IntegerField(label='Intentos fallidos', widget=forms.NumberInput(attrs={'class': INPUT_CLASS}))
    request_rate_per_min = forms.IntegerField(label='Request rate/min', widget=forms.NumberInput(attrs={'class': INPUT_CLASS}))
    asset_criticality = forms.CharField(label='Criticidad del activo', widget=forms.TextInput(attrs={'class': INPUT_CLASS}))
    hour = forms.IntegerField(label='Hora', min_value=0, max_value=23, widget=forms.NumberInput(attrs={'class': INPUT_CLASS}))
    day = forms.IntegerField(label='Día', min_value=1, max_value=31, widget=forms.NumberInput(attrs={'class': INPUT_CLASS}))
    month = forms.IntegerField(label='Mes', min_value=1, max_value=12, widget=forms.NumberInput(attrs={'class': INPUT_CLASS}))
    day_of_week = forms.IntegerField(label='Día semana', min_value=0, max_value=6, widget=forms.NumberInput(attrs={'class': INPUT_CLASS}))

class JSONPredictionForm(forms.Form):
    payload = forms.CharField(
        label='Pega tu JSON',
        widget=forms.Textarea(attrs={
            'class': TEXTAREA_CLASS,
            'placeholder': '{\n  "source_port": 443,\n  "destination_port": 8080,\n  "protocol": "tcp"\n}'
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
        return data