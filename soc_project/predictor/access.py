"""Qué alertas puede ver cada rol según su clasificación ML.

Única fuente de verdad para el listado (opciones del filtro), el detalle de la
alerta y los links del dashboard. Un rol sin entrada ve todas las clases.
"""

# 'pending' = sin clasificar; solo afecta a las opciones del filtro del listado.
ROLE_VISIBLE_CLASSES = {
    'analyst_n1': ('benigno',),
    'trainee':    ('benigno',),
    'analyst_n2': ('malicioso', 'a_investigar', 'pending'),
}

ALERT_ACCESS_DENIED_MESSAGE = 'No tienes permisos para acceder a esta alerta.'


def can_view_alert(role, alert):
    """True si el rol puede abrir el detalle de la alerta.

    Las alertas sin clasificar quedan visibles para todos (CP030): todavía no
    tienen una clase que las asigne a un nivel.
    """
    allowed = ROLE_VISIBLE_CLASSES.get(role)
    prediction = alert.latest_prediction
    if allowed is None or prediction is None:
        return True
    return prediction.predicted_class in allowed
