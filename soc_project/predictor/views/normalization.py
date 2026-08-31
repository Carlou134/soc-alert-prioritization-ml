# ─────────────────────────────────────────────────────────────────────────────
# HU009 — Pipeline de normalización de datos
# ─────────────────────────────────────────────────────────────────────────────
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect, render

from accounts.decorators import analyst_required
from accounts.models import ACTION_PIPELINE_EXPORT, ACTION_PIPELINE_NORMALIZATION, log_action
from django_q.tasks import async_task

from ..models import Dataset, log_error
from ..pipeline import (
    REQUIRED_COLUMNS,
    OPTIONAL_COLUMNS,
    DISPLAY_COLUMNS,
    COLUMN_METADATA,
    parse_file,
    validate_columns,
    validate_column_types,
    apply_mapping,
    clean_records,
    export_to_csv,
    export_to_json,
)

_PIPELINE_SESSION_KEYS = [
    'pipeline_records',
    'pipeline_filename',
    'pipeline_columns',
    'pipeline_missing',
    'pipeline_mapping',
    'pipeline_clean_records',
    'pipeline_stats',
]


def _clear_pipeline_session(session):
    for key in _PIPELINE_SESSION_KEYS:
        session.pop(key, None)


@login_required
@analyst_required
def pipeline_view(request):
    """Paso 1: Formulario de carga de archivo."""
    _clear_pipeline_session(request.session)
    return render(request, 'predictor/pipeline.html', {
        'stage': 'upload',
        'required_cols': REQUIRED_COLUMNS,
    })


@login_required
@analyst_required
def pipeline_upload_view(request):
    """POST: Parsea el archivo, detecta columnas y decide el siguiente paso."""
    if request.method != 'POST':
        return redirect('pipeline')

    def _render_upload_error(error):
        return render(request, 'predictor/pipeline.html', {
            'stage': 'upload',
            'required_cols': REQUIRED_COLUMNS,
            'error': error,
        })

    file = request.FILES.get('file')
    if not file:
        return _render_upload_error('No se seleccionó ningún archivo.')
    if file.size == 0:
        return _render_upload_error('El archivo está vacío.')
    if file.size > 10 * 1024 * 1024:
        return _render_upload_error('El archivo supera el límite de 10 MB.')

    try:
        records, error = parse_file(file)
        if error:
            return _render_upload_error(error)
        if not records:
            return _render_upload_error('El archivo no contiene registros.')

        detected_cols, missing_cols = validate_columns(records)
        missing_optional = [c for c in OPTIONAL_COLUMNS if c not in detected_cols]
        missing_display  = [c for c in DISPLAY_COLUMNS  if c not in detected_cols]

        request.session['pipeline_records']          = records
        request.session['pipeline_filename']         = file.name
        request.session['pipeline_columns']          = detected_cols
        request.session['pipeline_missing']          = missing_cols
        request.session['pipeline_missing_optional'] = missing_optional
        request.session['pipeline_missing_display']  = missing_display
        request.session['pipeline_already_saved']    = False
    except Exception as exc:
        log_error(request.user, 'pipeline_upload', str(exc))
        return _render_upload_error(
            'No se pudo procesar el archivo. Verifique que el formato sea '
            'CSV o JSON válido e intente nuevamente.'
        )

    return redirect('pipeline_map')


def _map_ctx(detected_cols, filename, missing_required, missing_optional, missing_display, prev_mapping, type_warnings):
    """Construye el contexto del template para el paso de mapeo."""
    def _rows(cols):
        result = []
        for col in cols:
            meta = COLUMN_METADATA.get(col, {})
            result.append({
                'name':        col,
                'desc':        meta.get('desc', ''),
                'example':     meta.get('example', ''),
                'dtype':       meta.get('type', 'str'),
                'prev_source': prev_mapping.get(col, ''),
                'warning':     type_warnings.get(col),
            })
        return result

    req_rows  = _rows(missing_required)
    opt_rows  = _rows(missing_optional)
    disp_rows = _rows(missing_display)

    sections = [
        {
            'rows':           req_rows,
            'title':          'Columnas requeridas — el modelo no puede predecir sin estas',
            'header_class':   'bg-red-500/10 border-red-500/20',
            'dot_class':      'bg-red-400',
            'title_class':    'text-red-400',
            'col_name_class': 'text-red-400',
        },
        {
            'rows':           opt_rows,
            'title':          'Columnas opcionales — mejoran la predicción ML',
            'header_class':   'bg-amber-500/10 border-amber-500/20',
            'dot_class':      'bg-amber-400',
            'title_class':    'text-amber-400',
            'col_name_class': 'text-amber-400',
        },
        {
            'rows':           disp_rows,
            'title':          'Columnas de visualización — solo para la tabla de alertas, no afectan la predicción',
            'header_class':   'bg-slate-700/40 border-slate-600',
            'dot_class':      'bg-slate-400',
            'title_class':    'text-slate-400',
            'col_name_class': 'text-slate-400',
        },
    ]

    return {
        'stage':           'map',
        'detected_cols':   detected_cols,
        'filename':        filename,
        'required_rows':   req_rows,
        'optional_rows':   opt_rows,
        'display_rows':    disp_rows,
        'sections':        sections,
        'type_warnings':   type_warnings,
    }


@login_required
@analyst_required
def pipeline_map_view(request):
    """Paso 2: Mapeo de columnas — requeridas, opcionales y de visualización."""
    records = request.session.get('pipeline_records')
    if not records:
        return redirect('pipeline')

    detected_cols    = request.session.get('pipeline_columns', [])
    missing_required = request.session.get('pipeline_missing', [])
    missing_optional = request.session.get('pipeline_missing_optional', [])
    missing_display  = request.session.get('pipeline_missing_display', [])
    filename         = request.session.get('pipeline_filename', '')

    all_missing = missing_required + missing_optional + missing_display

    def _build_col_rows(cols, prev_mapping, type_warnings):
        rows = []
        for col in cols:
            meta = COLUMN_METADATA.get(col, {})
            rows.append({
                'name':         col,
                'desc':         meta.get('desc', ''),
                'example':      meta.get('example', ''),
                'dtype':        meta.get('type', 'str'),
                'prev_source':  prev_mapping.get(col, ''),
                'warning':      type_warnings.get(col),
            })
        return rows

    if request.method == 'POST':
        mapping = {}
        for col in all_missing:
            source = request.POST.get(f'map_{col}', '').strip()
            if source and source != '__skip__':
                mapping[col] = source

        type_warnings = validate_column_types(records, mapping)
        prev_mapping  = {col: request.POST.get(f'map_{col}', '') for col in all_missing}

        if type_warnings and not request.POST.get('force_continue'):
            return render(request, 'predictor/pipeline.html', _map_ctx(
                detected_cols, filename, missing_required, missing_optional, missing_display,
                prev_mapping, type_warnings,
            ))

        mapped_records = apply_mapping(records, mapping)
        new_detected, new_missing        = validate_columns(mapped_records)
        new_missing_optional = [c for c in OPTIONAL_COLUMNS if c not in new_detected]
        new_missing_display  = [c for c in DISPLAY_COLUMNS  if c not in new_detected]

        request.session['pipeline_records']          = mapped_records
        request.session['pipeline_mapping']          = mapping
        request.session['pipeline_columns']          = new_detected
        request.session['pipeline_missing']          = new_missing
        request.session['pipeline_missing_optional'] = new_missing_optional
        request.session['pipeline_missing_display']  = new_missing_display

        return redirect('pipeline_normalize')

    return render(request, 'predictor/pipeline.html', _map_ctx(
        detected_cols, filename, missing_required, missing_optional, missing_display, {}, {},
    ))


@login_required
@analyst_required
def pipeline_normalize_view(request):
    """
    GET: Muestra preview de datos en bruto y botón de normalización.
    POST: Ejecuta la limpieza y redirige al preview limpio.
    """
    records = request.session.get('pipeline_records')
    if not records:
        return redirect('pipeline')

    detected_cols = request.session.get('pipeline_columns', [])
    filename = request.session.get('pipeline_filename', '')
    missing_cols = [col for col in REQUIRED_COLUMNS if col not in detected_cols]

    if request.method == 'POST':
        if request.session.get('pipeline_already_saved'):
            return redirect('pipeline_preview')

        try:
            clean, stats = clean_records(records)
        except Exception as exc:
            log_error(request.user, 'pipeline_normalize', str(exc))
            return render(request, 'predictor/pipeline.html', {
                'stage': 'normalize',
                'filename': filename,
                'detected_cols': detected_cols,
                'preview_rows': [],
                'total_records': len(records),
                'missing_cols': missing_cols,
                'error': (
                    'Ocurrió un error durante la normalización de los datos. '
                    'Verifique que los campos numéricos contengan valores válidos.'
                ),
            })

        if not clean:
            return render(request, 'predictor/pipeline.html', {
                'stage': 'normalize',
                'filename': filename,
                'detected_cols': detected_cols,
                'preview_rows': [],
                'total_records': len(records),
                'missing_cols': missing_cols,
                'error': 'No quedaron registros tras la limpieza. Verifica el archivo.',
                'stats': stats,
            })

        request.session['pipeline_clean_records'] = clean
        request.session['pipeline_stats'] = stats

        dataset = Dataset.objects.create(
            filename=filename,
            row_count=len(clean),
            uploaded_by=request.user,
        )
        async_task('predictor.tasks.process_alert_batch', dataset.pk, clean, request.user.pk)

        request.session['pipeline_dataset_id'] = dataset.pk
        request.session['pipeline_already_saved'] = True
        request.session.modified = True

        log_action(
            request.user,
            ACTION_PIPELINE_NORMALIZATION,
            (
                f'Ejecutó pipeline de normalización sobre "{filename}". '
                f'Registros procesados: {stats["total_clean"]}. '
                f'Duplicados eliminados: {stats["duplicates_removed"]}. '
                f'Nulos rellenados: {stats["nulls_filled"]}. '
                f'Guardado en segundo plano (dataset #{dataset.pk}).'
            ),
        )
        return redirect('pipeline_preview')

    preview_rows = [
        [record.get(col, '') for col in detected_cols]
        for record in records[:10]
    ]

    return render(request, 'predictor/pipeline.html', {
        'stage': 'normalize',
        'filename': filename,
        'detected_cols': detected_cols,
        'preview_rows': preview_rows,
        'total_records': len(records),
        'missing_cols': missing_cols,
    })


@login_required
@analyst_required
def pipeline_preview_view(request):
    """Paso 4: Preview del dataset limpio y botones de exportación."""
    clean = request.session.get('pipeline_clean_records')
    if not clean:
        return redirect('pipeline')

    preview_rows = [
        [record.get(col, '') for col in REQUIRED_COLUMNS]
        for record in clean[:10]
    ]

    return render(request, 'predictor/pipeline.html', {
        'stage': 'preview',
        'filename': request.session.get('pipeline_filename', ''),
        'stats': request.session.get('pipeline_stats', {}),
        'required_cols': REQUIRED_COLUMNS,
        'preview_rows': preview_rows,
        'total_records': len(clean),
        'dataset_id': request.session.get('pipeline_dataset_id'),
    })


@login_required
@analyst_required
def pipeline_export_view(request):
    """POST: Genera y descarga el dataset limpio en CSV o JSON."""
    if request.method != 'POST':
        return redirect('pipeline_preview')

    clean = request.session.get('pipeline_clean_records')
    if not clean:
        return redirect('pipeline')

    export_format = request.POST.get('format', 'csv').lower()
    filename = request.session.get('pipeline_filename', 'dataset')
    base_name = filename.rsplit('.', 1)[0] if '.' in filename else filename

    try:
        if export_format == 'json':
            content = export_to_json(clean)
            response = HttpResponse(content, content_type='application/json; charset=utf-8')
            response['Content-Disposition'] = (
                f'attachment; filename="{base_name}_clean.json"'
            )
        else:
            content = export_to_csv(clean)
            response = HttpResponse(content, content_type='text/csv; charset=utf-8')
            response['Content-Disposition'] = (
                f'attachment; filename="{base_name}_clean.csv"'
            )
    except Exception as exc:
        log_error(request.user, 'pipeline_export', str(exc))
        messages.error(
            request,
            'No se pudo generar el archivo de exportación. Intente nuevamente.',
        )
        return redirect('pipeline_preview')

    log_action(
        request.user,
        ACTION_PIPELINE_EXPORT,
        (
            f'Exportó dataset limpio "{base_name}_clean.{export_format}". '
            f'Registros exportados: {len(clean)}. '
            f'Formato: {export_format.upper()}.'
        ),
    )

    return response
