from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

from .serializers import PredictionRequestSerializer, PredictionLogSerializer
from .utils import predict_alert
from .models import PredictionLog

class PredictAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PredictionRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data
        predicted_class, probabilities = predict_alert(data)

        log = PredictionLog.objects.create(
            user=request.user,
            input_data=data,
            predicted_class=predicted_class,
            probabilities=probabilities,
            source='api'
        )

        return Response({
            'message': 'Predicción realizada correctamente.',
            'prediction_id': log.id,
            'predicted_class': predicted_class,
            'probabilities': probabilities,
            'source': 'api',
            'created_at': log.created_at,
        }, status=status.HTTP_200_OK)


class HistoryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        logs = PredictionLog.objects.filter(user=request.user).order_by('-created_at')
        serializer = PredictionLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)