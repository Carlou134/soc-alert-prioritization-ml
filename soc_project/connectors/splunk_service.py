# -*- coding: utf-8 -*-
"""
Conexión REAL contra la REST API de management de Splunk (puerto 8089,
no confundir con el 8000 de la Web UI). Solo implementa lo necesario para
"Probar conexión" — GET /services/server/info, el endpoint más liviano
posible: no dispara ninguna búsqueda ni consume licencia de indexación,
solo confirma reachability + credenciales válidas.

Deliberadamente NO usa el SDK oficial `splunk-sdk` (splunklib) — para un
simple health-check de conexión es una dependencia pesada de más (trae
manejo completo de search jobs, saved searches, KV store, etc. que aquí no
hace falta) y no da más control sobre timeout que hacer el GET nosotros
mismos con httpx (que ya es una dependencia real del proyecto). Si más
adelante se implementa la ingesta real (crear el search job, hacer polling,
traer resultados), ahí sí conviene evaluar el SDK — mientras tanto, no.
"""
import httpx

REQUEST_TIMEOUT = 8.0  # segundos — nunca dejar un request de Django colgado esperando a un Splunk caído/lento


def test_connection(connector):
    """
    Prueba real de conectividad + autenticación contra un SIEMConnector de
    tipo Splunk. Devuelve (success: bool, message: str). Nunca levanta
    excepción — cualquier error de red/auth/parseo se traduce a un mensaje
    legible para el analista.
    """
    port = connector.port or 8089
    url = f'https://{connector.host}:{port}/services/server/info'

    headers = {}
    auth = None
    if connector.auth_type == 'bearer_token':
        token = connector.credentials.get('api_token', '')
        headers['Authorization'] = f'Bearer {token}'
    else:
        auth = (connector.credentials.get('username', ''), connector.credentials.get('password', ''))

    try:
        resp = httpx.get(
            url,
            params={'output_mode': 'json'},
            headers=headers,
            auth=auth,
            verify=connector.verify_ssl,
            timeout=REQUEST_TIMEOUT,
        )
    except httpx.ConnectTimeout:
        return False, f'Timeout conectando a {connector.host}:{port} — comprueba que Splunk esté corriendo y accesible.'
    except httpx.ConnectError as e:
        hint = ''
        if 'certificate' in str(e).lower() or 'ssl' in str(e).lower():
            hint = ' Parece un problema de certificado SSL — prueba desactivando "Verificar certificado SSL" si es una instancia local con certificado autofirmado.'
        return False, f'No se pudo conectar a {connector.host}:{port}.{hint} Verifica que sea el puerto de management (8089), no el de la Web UI (8000).'
    except httpx.TimeoutException:
        return False, f'Timeout tras {REQUEST_TIMEOUT}s esperando respuesta de {connector.host}:{port}.'
    except httpx.RequestError as e:
        return False, f'Error de red conectando a {connector.host}:{port}: {e}'

    if resp.status_code == 401:
        return False, 'Autenticación rechazada por Splunk — usuario/contraseña o token incorrectos.'
    if resp.status_code == 403:
        return False, 'Splunk rechazó el acceso (403) — el usuario no tiene permisos suficientes sobre la REST API.'
    if resp.status_code != 200:
        return False, f'Splunk respondió {resp.status_code} en lugar de 200.'

    try:
        entry = resp.json()['entry'][0]['content']
        version = entry.get('version', 'desconocida')
        server_name = entry.get('serverName', connector.host)
    except (KeyError, IndexError, ValueError):
        version, server_name = 'desconocida', connector.host

    return True, f'Conexión real exitosa — Splunk Enterprise v{version} ({server_name}).'
