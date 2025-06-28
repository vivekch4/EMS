from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import MachineReading, Threshold, Alarm
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
import json
from django.conf import settings
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from django.utils import timezone
from django.db.models import Min

@receiver(post_save, sender=MachineReading)
def broadcast_machine_reading(sender, instance, created, **kwargs):
    if created:
        # Broadcast reading to WebSocket
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "machine_readings",
            {
                "type": "reading_message",
                "message": {
                    "id": instance.id,
                    "machine_name": instance.machine.name,
                    "current": instance.current,
                    "kwh": instance.kwh,
                    "voltage": instance.voltage,
                    "timestamp": instance.timestamp.isoformat(),
                }
            }
        )

        # Get today's date
        today = timezone.now().date()

        # Find the first reading of the day for this machine
        first_reading = MachineReading.objects.filter(
            machine=instance.machine,
            timestamp__date=today
        ).order_by('timestamp').first()

        # Calculate daily kWh usage
        if first_reading:
            daily_usage = instance.kwh - first_reading.kwh if instance.kwh >= first_reading.kwh else 0
        else:
            daily_usage = 0  # If no previous reading, assume this is the first

        # Check thresholds for the machine (only kWh)
        thresholds = Threshold.objects.filter(machine=instance.machine, parameter='kWh')
        for threshold in thresholds:
            trigger_point = threshold.trigger_point()  # e.g., 100 * 50 / 100 = 50 for 50%
            # Check if daily usage exceeds the threshold
            if daily_usage > trigger_point:
                # Check if an alarm was already sent for this threshold today
                existing_alarm = Alarm.objects.filter(
                    machine=instance.machine,
                    parameter=threshold.parameter,
                    level=threshold.level,
                    timestamp__date=today
                ).exists()

                if not existing_alarm:
                    # Create alarm
                    alarm = Alarm.objects.create(
                        machine=instance.machine,
                        parameter=threshold.parameter,
                        level=threshold.level,
                        value=daily_usage,
                        notified_to=threshold.contact_email
                    )

                    # Send email notification using smtplib
                    subject = f'Alarm: {threshold.machine.name} - {threshold.parameter} Threshold Exceeded'
                    message = f"""
                    Hello,

                    A threshold has been exceeded for {threshold.machine.name}.

                    Parameter: {threshold.parameter}
                    Level: {threshold.level}
                    Daily Usage: {daily_usage} kWh
                    Threshold Trigger Point: {trigger_point} kWh
                    Timestamp: {instance.timestamp.isoformat()}

                    Please take appropriate action.

                    Best regards,
                    Your Monitoring Team
                    """

                    email = threshold.contact_email
                    msg = MIMEMultipart()
                    msg["From"] = settings.SMTP_EMAIL
                    msg["To"] = email
                    msg["Subject"] = subject
                    msg.attach(MIMEText(message, "plain"))

                    try:
                        with smtplib.SMTP("smtp.gmail.com", 587) as server:
                            server.starttls()
                            server.login(settings.SMTP_EMAIL, settings.SMTP_APP_PASSWORD)
                            server.send_message(msg)
                            # Broadcast notification to WebSocket
                            async_to_sync(channel_layer.group_send)(
                                "notifications",
                                {
                                    "type": "notification_message",
                                    "message": {
                                        "type": "success",
                                        "text": f"Notification email sent to {threshold.contact_email} for {threshold.machine.name} threshold exceedance"
                                    }
                                }
                            )
                    except Exception as e:
                        print(f"Failed to send email: {e}")
                        # Broadcast error notification
                        async_to_sync(channel_layer.group_send)(
                            "notifications",
                            {
                                "type": "notification_message",
                                "message": {
                                    "type": "error",
                                    "text": f"Failed to send notification email to {threshold.contact_email}"
                                }
                            }
                        )

                    # Broadcast alarm to WebSocket
                    async_to_sync(channel_layer.group_send)(
                        "alarms",
                        {
                            "type": "alarm_message",
                            "message": {
                                "id": alarm.id,
                                "machine_name": alarm.machine.name,
                                "parameter": alarm.parameter,
                                "level": alarm.level,
                                "value": alarm.value,
                                "timestamp": alarm.timestamp.isoformat(),
                                "notified_to": alarm.notified_to,
                            }
                        }
                    )