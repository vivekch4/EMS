from rest_framework import serializers
from .models import CustomUser, Machine,PLCConnection,MachineReading,Threshold,Tariff

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'user_id', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            username=validated_data['username'],
            user_id=validated_data['user_id'],
            password=validated_data['password'],
            role=validated_data['role']
        )
        return user

    def update(self, instance, validated_data):
        instance.username = validated_data.get('username', instance.username)
        instance.user_id = validated_data.get('user_id', instance.user_id)
        instance.role = validated_data.get('role', instance.role)
        if 'password' in validated_data and validated_data['password']:
            instance.set_password(validated_data['password'])
        instance.save()
        return instance

class LoginSerializer(serializers.Serializer):
    user_id = serializers.CharField()
    password = serializers.CharField(write_only=True)

class PLCConnectionSerializer(serializers.ModelSerializer):
    class Meta:
        model = PLCConnection
        fields = ['ip_address', 'port']

class MachineSerializer(serializers.ModelSerializer):
    class Meta:
        model = Machine
        fields = ['id', 'name', 'location', 'description', 'current_tag', 'kwh_tag', 'voltage_tag', 'created_at', 'updated_at']

class MachineReadingSerializer(serializers.ModelSerializer):
    machine_name = serializers.CharField(source='machine.name', read_only=True)

    class Meta:
        model = MachineReading
        fields = ['id', 'machine', 'machine_name', 'timestamp', 'current', 'kwh', 'voltage']
        
class ThresholdSerializer(serializers.ModelSerializer):
    machine_name = serializers.CharField(source='machine.name', read_only=True)

    class Meta:
        model = Threshold
        fields = ['id', 'machine', 'machine_name', 'parameter', 'threshold_value', 'percentage', 'level', 'contact_email', 'created_at']

class TariffSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tariff
        fields = ['id', 'rate', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

    def validate_rate(self, value):
        if value <= 0:
            raise serializers.ValidationError("Tariff rate must be greater than zero.")
        return value