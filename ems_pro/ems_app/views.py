from rest_framework import viewsets, permissions, status,generics
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import CustomUser, Machine,PLCConnection,MachineReading
from .serializers import *
from django.http import HttpResponse
import pandas as pd
from django.shortcuts import render, redirect
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout,authenticate
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .Permissions import IsAdmin
import logging
from pymodbus.client import ModbusTcpClient
import time
from datetime import datetime as dt,timedelta,timezone
from django.db import transaction
from django.shortcuts import get_object_or_404
from io import StringIO
import csv
from django.http import StreamingHttpResponse
from rest_framework.pagination import PageNumberPagination

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data['user_id']
            password = serializer.validated_data['password']
            user = authenticate(request, username=user_id, password=password)
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh_token': str(refresh),
                    'token': str(refresh.access_token),
                    'user_id': user.user_id,
                    'role': user.role
                })
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({'error': 'Refresh token is required'}, status=status.HTTP_400_BAD_REQUEST)
            
            token = RefreshToken(refresh_token)
            token.blacklist()  # Blacklist the refresh token
            
            return Response({'message': 'Successfully logged out'}, status=status.HTTP_205_RESET_CONTENT)
        
        except Exception as e:
            
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

class UserListCreateView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]

# User Retrieve/Update/Delete View
class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    lookup_field = 'id'

logger = logging.getLogger(__name__)
class ConnectView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        try:
            connection = PLCConnection.objects.first()
            serializer = PLCConnectionSerializer(connection) if connection else None
            return Response({
                'connection': serializer.data if serializer else None
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching connection: {e}")
            return Response({'error': f"Failed to fetch connection: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        serializer = PLCConnectionSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"Serializer errors: {serializer.errors}")
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            timeout = int(request.data.get('timeout', 10))
            retries = int(request.data.get('retries', 3))
            if timeout < 1 or timeout > 60:
                return Response({'error': 'Timeout must be between 1 and 60 seconds'}, status=status.HTTP_400_BAD_REQUEST)
            if retries < 0 or retries > 10:
                return Response({'error': 'Retries must be between 0 and 10'}, status=status.HTTP_400_BAD_REQUEST)

            # Test connection before saving
            client = ModbusTcpClient(
                host=request.data['ip_address'],
                port=request.data['port'],
                timeout=timeout
            )
            connection_successful = False
            for attempt in range(retries + 1):
                if client.connect():
                    connection_successful = True
                    logger.info(f"Connected to {request.data['ip_address']}:{request.data['port']} on attempt {attempt + 1}")
                    break
                else:
                    logger.warning(f"Connection attempt {attempt + 1} failed for {request.data['ip_address']}:{request.data['port']}")
                if attempt < retries:
                    time.sleep(1)

            if connection_successful:
                client.close()
                # Update or create the single PLC connection
                connection, created = PLCConnection.objects.update_or_create(
                    id=1,  # Ensure single record
                    defaults={
                        'ip_address': request.data['ip_address'],
                        'port': request.data['port']
                    }
                )
                return Response({
                    'message': f"Connection to {connection.ip_address}:{connection.port} saved successfully",
                    'connection': serializer.data
                }, status=status.HTTP_200_OK)
            else:
                logger.error(f"Failed to connect to {request.data['ip_address']}:{request.data['port']} after {retries + 1} attempts")
                return Response({'error': 'Failed to connect to Modbus server after retries'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Error saving connection: {e}")
            return Response({'error': f"Server error: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MachineListCreateView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        try:
            machines = Machine.objects.all()
            serializer = MachineSerializer(machines, many=True)
            return Response({
                'machines': serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching machines: {e}")
            return Response({'error': f"Failed to fetch machines: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request):
        serializer = MachineSerializer(data=request.data)
        if not serializer.is_valid():
            logger.error(f"Serializer errors: {serializer.errors}")
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            serializer.save()
            logger.info(f"Machine {request.data.get('name')} created successfully")
            return Response({
                'message': f"Machine {serializer.data['name']} created successfully",
                'machine': serializer.data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f"Error creating machine: {e}")
            return Response({'error': f"Failed to create machine: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MachineDetailView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get_object(self, pk):
        try:
            return Machine.objects.get(pk=pk)
        except Machine.DoesNotExist:
            logger.error(f"Machine with id {pk} not found")
            return None

    def get(self, request, pk):
        machine = self.get_object(pk)
        if not machine:
            return Response({'error': 'Machine not found'}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            serializer = MachineSerializer(machine)
            return Response({
                'machine': serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching machine {pk}: {e}")
            return Response({'error': f"Failed to fetch machine: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self, request, pk):
        machine = self.get_object(pk)
        if not machine:
            return Response({'error': 'Machine not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = MachineSerializer(machine, data=request.data, partial=True)
        if not serializer.is_valid():
            logger.error(f"Serializer errors for machine {pk}: {serializer.errors}")
            return Response({'error': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        try:
            serializer.save()
            logger.info(f"Machine {machine.name} updated successfully")
            return Response({
                'message': f"Machine {serializer.data['name']} updated successfully",
                'machine': serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error updating machine {pk}: {e}")
            return Response({'error': f"Failed to update machine: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, pk):
        machine = self.get_object(pk)
        if not machine:
            return Response({'error': 'Machine not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            machine_name = machine.name
            machine.delete()
            logger.info(f"Machine {machine_name} deleted successfully")
            return Response({
                'message': f"Machine {machine_name} deleted successfully"
            }, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            logger.error(f"Error deleting machine {pk}: {e}")
            return Response({'error': f"Failed to delete machine: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class MachineKwhSummaryPagination(PageNumberPagination):
    page_size = 2  # default items per page
    page_size_query_param = 'page_size'
    max_page_size = 100


class MachineKwhSummaryView(APIView):
    def get(self, request):
        now = dt.now()
        seven_days_ago = now - timedelta(days=1)
        print(seven_days_ago,"seve")

        machines = Machine.objects.all()
        paginator = MachineKwhSummaryPagination()
        paginated_machines = paginator.paginate_queryset(machines, request)

        result = []
        for machine in paginated_machines:
            readings = machine.readings.filter(timestamp__lte=now).order_by('timestamp')
            reading_7_days_ago = readings.filter(timestamp__lte=seven_days_ago).order_by('-timestamp').first()
            latest_reading = readings.last()
            print(reading_7_days_ago,latest_reading,"this is least reading ")

            if reading_7_days_ago and latest_reading:
                consumption = latest_reading.kwh - reading_7_days_ago.kwh
                print(consumption,"consumptio")
            else:
                print("yes")
                consumption = 0.0

            result.append({
                'machine_id': machine.id,
                'machine_name': machine.name,
                'kwh_consumed': round(consumption, 2)
            })

        return paginator.get_paginated_response(result)

class MachineReadingListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            queryset = MachineReading.objects.all()
            machine_id = request.query_params.get('machine')
            start_date = request.query_params.get('start_date')
            end_date = request.query_params.get('end_date')
            limit = request.query_params.get('limit')

            if machine_id and machine_id != 'all':
                queryset = queryset.filter(machine_id=machine_id)
            
            if start_date and end_date and not limit:
                try:
                    start = dt.strptime(start_date, '%Y-%m-%d')
                    end = dt.strptime(end_date, '%Y-%m-%d')
                    print(start,end)
                    end = end + timedelta(days=1) - timedelta(microseconds=1)
                    queryset = queryset.filter(timestamp__range=[start, end])
                    print(queryset,"query")
                except ValueError as e:
                    logger.error(f"Invalid date format: {e}")
                    return Response({'error': 'Invalid date format. Use YYYY-MM-DD'}, status=status.HTTP_400_BAD_REQUEST)
            
            if limit:
                try:
                    queryset = queryset.order_by('-timestamp')[:int(limit)]
                except ValueError as e:
                    logger.error(f"Invalid limit value: {e}")
                    return Response({'error': 'Invalid limit value'}, status=status.HTTP_400_BAD_REQUEST)
            
            serializer = MachineReadingSerializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Error fetching readings: {e}")
            return Response({'error': f"Failed to fetch readings: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ThresholdListCreateView(APIView):
    def get(self, request):
        thresholds = Threshold.objects.all()
        serializer = ThresholdSerializer(thresholds, many=True)
        return Response(serializer.data)

    def post(self, request):
        data = request.data

        # Check if it's a list (multiple levels)
        if isinstance(data, list):
            serializer = ThresholdSerializer(data=data, many=True)
        else:
            serializer = ThresholdSerializer(data=data)  # Single object fallback

        if serializer.is_valid():
            with transaction.atomic():
                serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ThresholdDetailView(APIView):
    def get_object(self, pk):
        return get_object_or_404(Threshold, pk=pk)

    def get(self, request, pk):
        threshold = self.get_object(pk)
        serializer = ThresholdSerializer(threshold)
        return Response(serializer.data)

    def put(self, request, pk):
        threshold = self.get_object(pk)
        serializer = ThresholdSerializer(threshold, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        threshold = self.get_object(pk)
        threshold.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    
class MachineReadingReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get query parameters
        machine_id = request.query_params.get('machine_id', '')
        date_filter = request.query_params.get('date_filter', '')
        start_date = request.query_params.get('start_date', '')
        end_date = request.query_params.get('end_date', '')

        # Base queryset
        readings = MachineReading.objects.all()

        # Filter by machine_id if provided
        if machine_id:
            readings = readings.filter(machine__id=machine_id)

        # Filter by date
        if date_filter == 'custom' and start_date and end_date:
            try:
                start_date = dt.strptime(start_date, '%Y-%m-%d')
                end_date = dt.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
                readings = readings.filter(timestamp__range=[start_date, end_date])
            except ValueError:
                return Response({'error': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)
        elif date_filter == 'last_week':
            start_date = dt.now() - timedelta(days=7)
            readings = readings.filter(timestamp__gte=start_date)
        elif date_filter == 'last_month':
            start_date = dt.now() - timedelta(days=30)
            readings = readings.filter(timestamp__gte=start_date)
        elif date_filter == 'last_six_months':
            start_date = dt.now() - timedelta(days=180)
            readings = readings.filter(timestamp__gte=start_date)

        # Order by timestamp descending
        readings = readings.order_by('-timestamp')

        # Calculate total kWh consumption
        total_kwh = None
        machine_kwh_totals = {}

        if machine_id:
            # Calculate total kWh for the selected machine
            kwh_readings = readings.filter(kwh__isnull=False).order_by('timestamp')
            if kwh_readings.exists():
                first_kwh = kwh_readings.last().kwh  # Earliest reading
                last_kwh = kwh_readings.first().kwh  # Latest reading
                total_kwh = last_kwh - first_kwh if first_kwh is not None and last_kwh is not None else 0
        else:
            # Calculate total kWh for each machine
            machines = Machine.objects.all()
            for machine in machines:
                machine_readings = MachineReading.objects.filter(machine=machine, kwh__isnull=False)
                if date_filter == 'custom' and start_date and end_date:
                    machine_readings = machine_readings.filter(timestamp__range=[start_date, end_date])
                elif date_filter == 'last_week':
                    machine_readings = machine_readings.filter(timestamp__gte=start_date)
                elif date_filter == 'last_month':
                    machine_readings = machine_readings.filter(timestamp__gte=start_date)
                elif date_filter == 'last_six_months':
                    machine_readings = machine_readings.filter(timestamp__gte=start_date)
                
                if machine_readings.exists():
                    machine_readings = machine_readings.order_by('timestamp')
                    first_kwh = machine_readings.last().kwh
                    last_kwh = machine_readings.first().kwh
                    if first_kwh is not None and last_kwh is not None:
                        machine_kwh_totals[machine.name] = last_kwh - first_kwh
                    else:
                        machine_kwh_totals[machine.name] = 0

        # Serialize data
        serializer = MachineReadingSerializer(readings, many=True)
        response_data = {
            'readings': serializer.data,
            'total_kwh': total_kwh if machine_id else machine_kwh_totals
        }
        return Response(response_data, status=status.HTTP_200_OK)

class MachineReadingExportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get query parameters
        machine_id = request.query_params.get('machine_id', '')
        date_filter = request.query_params.get('date_filter', '')
        start_date = request.query_params.get('start_date', '')
        end_date = request.query_params.get('end_date', '')

        # Base queryset
        readings = MachineReading.objects.all()

        # Filter by machine_id if provided
        if machine_id:
            readings = readings.filter(machine__id=machine_id)

        # Filter by date
        if date_filter == 'custom' and start_date and end_date:
            try:
                start_date = dt.strptime(start_date, '%Y-%m-%d')
                end_date = dt.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
                readings = readings.filter(timestamp__range=[start_date, end_date])
            except ValueError:
                return Response({'error': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)
        elif date_filter == 'last_week':
            start_date = dt.now() - timedelta(days=7)
            readings = readings.filter(timestamp__gte=start_date)
        elif date_filter == 'last_month':
            start_date = dt.now() - timedelta(days=30)
            readings = readings.filter(timestamp__gte=start_date)
        elif date_filter == 'last_six_months':
            start_date = dt.now() - timedelta(days=180)
            readings = readings.filter(timestamp__gte=start_date)

        # Order by timestamp descending
        readings = readings.order_by('-timestamp')

        # Calculate total kWh consumption
        total_kwh = None
        machine_kwh_totals = {}

        if machine_id:
            # Calculate total kWh for the selected machine
            kwh_readings = readings.filter(kwh__isnull=False).order_by('timestamp')
            if kwh_readings.exists():
                first_kwh = kwh_readings.last().kwh
                last_kwh = kwh_readings.first().kwh
                total_kwh = last_kwh - first_kwh if first_kwh is not None and last_kwh is not None else 0
        else:
            # Calculate total kWh for each machine
            machines = Machine.objects.all()
            for machine in machines:
                machine_readings = MachineReading.objects.filter(machine=machine, kwh__isnull=False)
                if date_filter == 'custom' and start_date and end_date:
                    machine_readings = machine_readings.filter(timestamp__range=[start_date, end_date])
                elif date_filter == 'last_week':
                    machine_readings = machine_readings.filter(timestamp__gte=start_date)
                elif date_filter == 'last_month':
                    machine_readings = machine_readings.filter(timestamp__gte=start_date)
                elif date_filter == 'last_six_months':
                    machine_readings = machine_readings.filter(timestamp__gte=start_date)
                
                if machine_readings.exists():
                    machine_readings = machine_readings.order_by('timestamp')
                    first_kwh = machine_readings.last().kwh
                    last_kwh = machine_readings.first().kwh
                    if first_kwh is not None and last_kwh is not None:
                        machine_kwh_totals[machine.name] = last_kwh - first_kwh
                    else:
                        machine_kwh_totals[machine.name] = 0

        # Create CSV response
        def stream_csv():
            output = StringIO()
            writer = csv.writer(output)
            # Write CSV header
            writer.writerow(['Machine Name', 'Machine ID', 'Timestamp', 'Current (A)', 'kWh', 'Voltage (V)'])
            # Write CSV rows
            for reading in readings:
                writer.writerow([
                    reading.machine.name,
                    reading.machine.id,
                    reading.timestamp.isoformat(),
                    reading.current if reading.current is not None else '-',
                    reading.kwh if reading.kwh is not None else '-',
                    reading.voltage if reading.voltage is not None else '-'
                ])
            # Write total kWh consumption
            writer.writerow([])
            if machine_id:
                writer.writerow(['Total kWh (Selected Machine)', total_kwh if total_kwh is not None else '-'])
            else:
                for machine_name, kwh_total in machine_kwh_totals.items():
                    writer.writerow([f'Total kWh ({machine_name})', kwh_total if kwh_total is not None else '-'])
            yield output.getvalue()

        # Set response headers for CSV download
        response = StreamingHttpResponse(stream_csv(), content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="machine_readings_report.csv"'
        return response
    
class TariffSetView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TariffSerializer(data=request.data)
        if serializer.is_valid():
            rate = serializer.validated_data['rate']
            tariff, created = Tariff.objects.get_or_create(id=1, defaults={'rate': rate})
            if not created:
                tariff.rate = rate
                tariff.save()
            return Response({'message': 'Tariff rate set successfully', 'tariff': TariffSerializer(tariff).data}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TariffReportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        machine_id = request.query_params.get('machine_id', '')
        date_filter = request.query_params.get('date_filter', '')
        start_date = request.query_params.get('start_date', '')
        end_date = request.query_params.get('end_date', '')

        # Base queryset for readings
        readings = MachineReading.objects.all()
        if machine_id:
            readings = readings.filter(machine__id=machine_id)

        # Determine date range for filtering
        if date_filter == 'custom' and start_date and end_date:
            try:
                start_date = dt.strptime(start_date, '%Y-%m-%d')
                end_date = dt.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
                readings = readings.filter(timestamp__range=[start_date, end_date])
            except ValueError:
                return Response({'error': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)
        elif date_filter == 'last_week':
            start_date = dt.now() - timedelta(days=7)
            end_date = dt.now()
            readings = readings.filter(timestamp__range=[start_date, end_date])
        elif date_filter == 'last_month':
            start_date = dt.now() - timedelta(days=30)
            end_date = dt.now()
            readings = readings.filter(timestamp__range=[start_date, end_date])

        readings = readings.order_by('-timestamp')

        # Get tariff rate
        try:
            tariff = Tariff.objects.get(id=1)
            tariff_rate = tariff.rate
        except Tariff.DoesNotExist:
            return Response({'error': 'Tariff rate not set'}, status=status.HTTP_400_BAD_REQUEST)

        total_tariff = None
        machine_tariff_totals = {}
        tariff_data = []

        if machine_id:
            # Calculate kWh consumption for the selected machine
            kwh_readings = readings.filter(kwh__isnull=False).order_by('timestamp')
            if kwh_readings.exists():
                # Get the earliest kWh reading within the date range
                first_kwh = kwh_readings.first().kwh
                # Get the most recent kWh reading within the date range
                last_kwh = kwh_readings.last().kwh
                total_kwh = last_kwh - first_kwh if first_kwh is not None and last_kwh is not None else 0
                total_tariff = total_kwh * tariff_rate
            for reading in readings:
                tariff_cost = reading.kwh * tariff_rate if reading.kwh is not None else None
                tariff_data.append({
                    'machine_name': reading.machine.name,
                    'machine_id': reading.machine.id,
                    'kwh': reading.kwh,
                    'tariff_cost': tariff_cost
                })
        else:
            # Calculate kWh consumption for all machines
            machines = Machine.objects.all()
            for machine in machines:
                machine_readings = MachineReading.objects.filter(machine=machine, kwh__isnull=False)
                if date_filter == 'custom' and start_date and end_date:
                    machine_readings = machine_readings.filter(timestamp__range=[start_date, end_date])
                elif date_filter == 'last_week':
                    machine_readings = machine_readings.filter(timestamp__range=[start_date, end_date])
                elif date_filter == 'last_month':
                    machine_readings = machine_readings.filter(timestamp__range=[start_date, end_date])
                if machine_readings.exists():
                    machine_readings = machine_readings.order_by('timestamp')
                    first_kwh = machine_readings.first().kwh
                    last_kwh = machine_readings.last().kwh
                    total_kwh = last_kwh - first_kwh if first_kwh is not None and last_kwh is not None else 0
                    machine_tariff_totals[machine.name] = total_kwh * tariff_rate
                for reading in machine_readings:
                    tariff_cost = reading.kwh * tariff_rate if reading.kwh is not None else None
                    tariff_data.append({
                        'machine_name': machine.name,
                        'machine_id': machine.id,
                        'kwh': reading.kwh,
                        'tariff_cost': tariff_cost
                    })

        response_data = {
            'tariff_data': tariff_data,
            'total_tariff': total_tariff if machine_id else machine_tariff_totals,
            'tariff_rate': tariff_rate
        }
        return Response(response_data, status=status.HTTP_200_OK)
from io import BytesIO
class TariffExportView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        machine_id = request.query_params.get('machine_id', '')
        date_filter = request.query_params.get('date_filter', '')
        start_date = request.query_params.get('start_date', '')
        end_date = request.query_params.get('end_date', '')

        # Base queryset for readings
        readings = MachineReading.objects.all()
        if machine_id:
            readings = readings.filter(machine__id=machine_id)
        if date_filter == 'custom' and start_date and end_date:
            try:
                start_date = dt.strptime(start_date, '%Y-%m-%d')
                end_date = dt.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)
                readings = readings.filter(timestamp__range=[start_date, end_date])
            except ValueError:
                return Response({'error': 'Invalid date format'}, status=status.HTTP_400_BAD_REQUEST)
        elif date_filter == 'last_week':
            start_date = dt.now() - timedelta(days=7)
            end_date = dt.now()
            readings = readings.filter(timestamp__range=[start_date, end_date])
        elif date_filter == 'last_month':
            start_date = dt.now() - timedelta(days=30)
            end_date = dt.now()
            readings = readings.filter(timestamp__range=[start_date, end_date])

        # Get tariff rate
        try:
            tariff = Tariff.objects.get(id=1)
            tariff_rate = tariff.rate
        except Tariff.DoesNotExist:
            tariff_rate = 0.0

        # Prepare data for Excel
        data = []
        if machine_id:
            kwh_readings = readings.filter(kwh__isnull=False).order_by('timestamp')
            if kwh_readings.exists():
                first_kwh = kwh_readings.first().kwh
                last_kwh = kwh_readings.last().kwh
                total_kwh = last_kwh - first_kwh if first_kwh is not None and last_kwh is not None else 0
                total_tariff = total_kwh * tariff_rate
                data.append({
                    'Machine Name': kwh_readings.first().machine.name,
                    'Tariff Value': total_tariff if total_tariff is not None else 0,
                    'Tariff Rate': tariff_rate
                })
        else:
            machines = Machine.objects.all()
            for machine in machines:
                machine_readings = readings.filter(machine=machine, kwh__isnull=False)
                if machine_readings.exists():
                    machine_readings = machine_readings.order_by('timestamp')
                    first_kwh = machine_readings.first().kwh
                    last_kwh = machine_readings.last().kwh
                    total_kwh = last_kwh - first_kwh if first_kwh is not None and last_kwh is not None else 0
                    total_tariff = total_kwh * tariff_rate
                    data.append({
                        'Machine Name': machine.name,
                        'Tariff Value': total_tariff if total_tariff is not None else 0,
                        'Tariff Rate': tariff_rate
                    })

        # Create Excel file
        df = pd.DataFrame(data, columns=['Machine Name', 'Tariff Value', 'Tariff Rate'])
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Tariff Report')

        # Prepare response
        output.seek(0)
        response = StreamingHttpResponse(
            output,
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = 'attachment; filename="tariff_report.xlsx"'
        return response

def dashboard(request):
    return render(request, 'dashboard.html')

def tariff_page(request):
    return render(request, 'tariff.html')


def users_page_view(request):
    return render(request, 'users.html')


def login_page(request):
    return render(request, 'login.html')

def create_user_view(request):
    return render(request, 'create_user.html')
def config_page(request):
    return render(request, 'config.html')

def create_config(request):
    return render(request, 'create_machine.html')

def report_page(request):
    return render(request, 'report.html')

def connection_page(request):
    return render(request, 'connection.html')

def Analytics_page(request):
    return render(request, 'Analytics.html')

def create_alarm_page(request):
    return render(request, 'create_alarm.html')

def alarm_page(request):
    return render(request, 'Alarm.html')

