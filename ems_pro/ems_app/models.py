
# Create your models here.
from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('controller', 'Controller'),
        ('manager', 'Manager'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='admin')
    user_id = models.CharField(max_length=50, unique=True)
    username = models.CharField(max_length=150, unique=False)
    USERNAME_FIELD = "user_id"
    REQUIRED_FIELDS = ["username", "email"]

    def __str__(self):
        return self.username
from django.db import models

class PLCConnection(models.Model):
    ip_address = models.GenericIPAddressField()
    port = models.IntegerField()

    def __str__(self):
        return f"({self.ip_address}:{self.port})"

    class Meta:
        # Ensure only one PLCConnection exists
        constraints = [
            models.UniqueConstraint(fields=['id'], name='unique_plc_connection')
        ]

class Machine(models.Model):
    name = models.CharField(max_length=100, unique=True)
    location = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)
    current_tag = models.IntegerField()  # Modbus tag for current
    kwh_tag = models.IntegerField()     # Modbus tag for kWh
    voltage_tag = models.IntegerField() # Modbus tag for voltage
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']

class MachineReading(models.Model):
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE, related_name='readings')
    timestamp = models.DateTimeField(auto_now_add=True)
    current = models.FloatField(null=True, blank=True)  # Current reading
    kwh = models.FloatField(null=True, blank=True)      # kWh reading
    voltage = models.FloatField(null=True, blank=True)  # Voltage reading

    def __str__(self):
        return f"{self.machine.name} - {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['machine', 'timestamp'])
        ]

class Threshold(models.Model):
    PARAMETER_CHOICES = [
        ('kWh', 'Energy (kWh)'),
        ('current', 'Current (A)'),
        ('voltage', 'Voltage (V)'),
    ]

    machine = models.ForeignKey('Machine', on_delete=models.CASCADE, related_name='thresholds')
    parameter = models.CharField(max_length=20, choices=PARAMETER_CHOICES)

    threshold_value = models.FloatField(help_text="Full-scale value (e.g. 500 kWh)")
    percentage = models.FloatField(help_text="Trigger alarm when this % of value is exceeded")
    
    level = models.CharField(max_length=20)  # e.g., Level 1, Critical
    contact_email = models.EmailField()
    
    created_at = models.DateTimeField(auto_now_add=True)

    def trigger_point(self):
        """
        Returns the actual value at which the alarm should trigger
        """
        return (self.threshold_value * self.percentage) / 100

    def __str__(self):
        return f"{self.machine.name} - {self.parameter} - {self.level} ({self.percentage}%)"

class Alarm(models.Model):
    machine = models.ForeignKey(Machine, on_delete=models.CASCADE)
    parameter = models.CharField(max_length=20)  # 'kWh', 'current', etc.
    level = models.CharField(max_length=20)      # 'Level 1', 'Level 2', etc.
    value = models.FloatField()                  # Actual value that caused the alarm
    timestamp = models.DateTimeField(auto_now_add=True)
    notified_to = models.EmailField()

class Tariff(models.Model):
    rate = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)