import io
import csv
import json

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser
from rest_framework import status

from .serializers import PredictionRequestSerializer
from .utils import predict_alert, predict_batch


class PredictAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PredictionRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data
        predicted_class, probabilities = predict_alert(data)

        return Response({
            'message': 'Predicción realizada correctamente.',
            'predicted_class': predicted_class,
            'probabilities': probabilities,
            'source': 'api',
        }, status=status.HTTP_200_OK)


class UploadAlertsAPIView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
    SUPPORTED_EXTENSIONS = ('.json', '.csv')

    def post(self, request):
        file = request.FILES.get('file')

        if not file:
            return Response(
                {'success': False, 'message': 'No se proporcionó ningún archivo.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if file.size == 0:
            return Response(
                {'success': False, 'message': 'El archivo está vacío.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if file.size > self.MAX_FILE_SIZE:
            return Response(
                {'success': False, 'message': 'El archivo supera el límite de 5 MB.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        filename = file.name.lower()

        if filename.endswith('.json'):
            records, error = self._parse_json(file)
            source = 'upload_json'
        elif filename.endswith('.csv'):
            records, error = self._parse_csv(file)
            source = 'upload_csv'
        else:
            return Response(
                {
                    'success': False,
                    'message': (
                        f'Tipo de archivo no soportado: "{file.name}". '
                        f'Use {" o ".join(self.SUPPORTED_EXTENSIONS)}.'
                    ),
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        if error:
            return Response(
                {'success': False, 'message': error},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not records:
            return Response(
                {'success': False, 'message': 'El archivo no contiene registros.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        processed = []
        failed = []

        # Paso 1 — validar todos los registros
        valid_records = []
        for index, record in enumerate(records, start=1):
            serializer = PredictionRequestSerializer(data=record)
            if serializer.is_valid():
                valid_records.append((index, serializer.validated_data))
            else:
                failed.append({'record': index, 'errors': serializer.errors})

        # Paso 2 — batch prediction con fallback a individual
        if valid_records:
            valid_data_list = [data for _, data in valid_records]
            try:
                batch_results = predict_batch(valid_data_list)
            except Exception:
                batch_results = None

            for i, (index, data) in enumerate(valid_records):
                if batch_results is not None:
                    predicted_class, probabilities = batch_results[i]
                else:
                    predicted_class, probabilities = predict_alert(data)
                processed.append({
                    'record': index,
                    'predicted_class': predicted_class,
                })

        return Response({
            'success': True,
            'message': f'{len(processed)} alerta(s) procesada(s) correctamente.',
            'file': file.name,
            'total_records': len(records),
            'processed': len(processed),
            'failed': len(failed),
            'results': processed,
            'errors': failed,
        }, status=status.HTTP_200_OK)

    def _parse_json(self, file):
        try:
            content = file.read().decode('utf-8')
            data = json.loads(content)
        except UnicodeDecodeError:
            return None, 'El archivo no tiene codificación UTF-8 válida.'
        except json.JSONDecodeError:
            return None, 'El contenido del archivo no es JSON válido.'

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            return None, 'El JSON debe ser un array de objetos o un único objeto.'

        if not all(isinstance(item, dict) for item in data):
            return None, 'Cada elemento del JSON debe ser un objeto (clave-valor).'

        return data, None

    def _parse_csv(self, file):
        try:
            content = file.read().decode('utf-8')
            reader = csv.DictReader(io.StringIO(content))
            records = [row for row in reader]
        except UnicodeDecodeError:
            return None, 'El archivo CSV no tiene codificación UTF-8 válida.'
        except csv.Error:
            return None, 'El archivo CSV tiene un formato incorrecto.'

        if not records:
            return None, 'El CSV no contiene filas de datos (solo encabezado o vacío).'

        return records, None
