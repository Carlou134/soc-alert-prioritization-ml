import anthropic
from django.conf import settings

_client = None
_async_client = None


def _get_client():
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
    return _client


def _get_async_client():
    global _async_client
    if _async_client is None:
        _async_client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
    return _async_client


def _build_prompt(alert, prediction, shap_data: dict) -> str:
    predicted = prediction.predicted_class
    risk = round(prediction.risk_score or 0, 4)
    probabilities = prediction.probabilities or {}

    s1 = shap_data.get('s1', {})
    s2 = shap_data.get('s2', {})

    s1_features = s1.get('features', [])[:8]
    s2_features = s2.get('features', [])[:8]

    def fmt_features(features):
        lines = []
        for f in features:
            direction = "↑ empuja hacia la clase" if f['shap'] > 0 else "↓ aleja de la clase"
            lines.append(f"  - {f['name']}: SHAP={f['shap']:+.4f} ({direction})")
        return "\n".join(lines) if lines else "  (sin datos)"

    return f"""Eres un experto en ciberseguridad analizando alertas SOC. Tu tarea es explicar en español, de forma clara y concisa, los valores SHAP de una alerta analizada por un modelo de Machine Learning jerárquico de dos etapas.

DATOS DE LA ALERTA:
- Clasificación final: {predicted}
- Risk Score: {risk}
- Probabilidades: Benigno={probabilities.get('benigno', 0):.3f} | A investigar={probabilities.get('a_investigar', 0):.3f} | Malicioso={probabilities.get('malicioso', 0):.3f}
- Severidad: {alert.severity}
- Categoría del evento: {alert.event_category}
- Táctica MITRE: {alert.mitre_tactic}
- Acción del firewall: {alert.firewall_action}
- Alerta IDS/IPS: {alert.ids_ips_alert}

VALORES SHAP — ETAPA 1 (detección de amenaza, clase: malicioso):
{fmt_features(s1_features)}

VALORES SHAP — ETAPA 2 (clasificación, clase: a_investigar):
{fmt_features(s2_features)}

INSTRUCCIONES:
1. Explica en 2-3 párrafos qué significan estos valores SHAP para esta alerta específica.
2. Identifica los factores más incriminantes y los más exonerantes.
3. Da una recomendación concreta para el analista SOC (investigar, ignorar, escalar, etc.).
4. Usa lenguaje técnico pero comprensible. No uses listas extensas, preferiblemente usa párrafos fluidos.
5. Máximo 350 palabras."""


def generate_shap_explanation(alert, prediction) -> str:
    """
    Genera explicación en lenguaje natural de los valores SHAP de una alerta.
    Lanza excepción si la API falla — el caller decide cómo manejarlo.
    """
    shap_data = prediction.shap_values or {}
    prompt = _build_prompt(alert, prediction, shap_data)

    message = _get_client().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    return message.content[0].text


def _build_incident_prompt(alert, prediction, user_message: str) -> str:
    predicted = prediction.predicted_class if prediction else 'Sin clasificar'
    risk = round(prediction.risk_score or 0, 4) if prediction else 0
    return f"""Eres un asistente experto en ciberseguridad para un SOC. Ayudás a un Analista de Nivel 3 a investigar un incidente activo. Respondé en español, de forma técnica y concisa. Máximo 400 palabras.

CONTEXTO DEL INCIDENTE #{alert.pk}:
- Clasificación ML: {predicted}
- Risk Score: {risk}
- Severidad: {alert.severity}
- Categoría del evento: {alert.event_category}
- Tipo de ataque: {alert.attack_type or 'Desconocido'}
- Firma del ataque: {alert.attack_signature or 'N/A'}
- Táctica MITRE ATT&CK: {alert.mitre_tactic}
- Etapa Kill Chain: {alert.kill_chain_stage}
- Protocolo: {alert.protocol}
- Alerta IDS/IPS: {alert.ids_ips_alert}
- Indicador de malware: {alert.malware_indicator or 'N/A'}
- Técnicas MITRE: {alert.mitre_techniques or 'N/A'}
- Criticidad del activo: {alert.asset_criticality}

PREGUNTA DEL ANALISTA N3:
{user_message}"""


async def generate_incident_chat_async(alert, prediction, user_message: str) -> str:
    """Responde preguntas del Analista N3 sobre un incidente activo."""
    message = await _get_async_client().messages.create(
        model='claude-sonnet-4-6',
        max_tokens=1024,
        messages=[{'role': 'user', 'content': _build_incident_prompt(alert, prediction, user_message)}],
    )
    return message.content[0].text


async def generate_shap_explanation_async(alert, prediction) -> str:
    """
    Versión async de generate_shap_explanation.
    Permite manejar múltiples usuarios concurrentes sin bloquear el event loop.
    """
    shap_data = prediction.shap_values or {}
    prompt = _build_prompt(alert, prediction, shap_data)

    message = await _get_async_client().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    return message.content[0].text
