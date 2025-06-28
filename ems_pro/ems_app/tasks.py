from celery import shared_task
from django.utils import timezone
import logging
from .modbus_client import ModbusConnection
from .models import Machine, MachineReading


logger = logging.getLogger(__name__)

@shared_task()
def read_modbus_data():
    """
    Celery task to read Modbus holding register data for all machines
    and save to MachineReading model every minute unconditionally.
    """
    modbus = ModbusConnection(timeout=10, retries=3)
    client = modbus.get_client()

    if not client:
        logger.error("Failed to get Modbus client connection")
        return

    try:
        machines = Machine.objects.all()
        for machine in machines:
            try:

                readings = {}
                for tag, field in [
                    (machine.current_tag, 'current'),
                    (machine.kwh_tag, 'kwh'),
                    (machine.voltage_tag, 'voltage')
                ]:
                    try:
                        result = client.read_holding_registers(int(tag), count=1)
                        logger.warning(f"{result} for tag {tag} on machine {machine.name}")

                        if result.isError():
                            logger.error(f"Error reading {field} tag {tag} for {machine.name}")
                            readings[field] = None
                        else:
                            readings[field] = result.registers[0] if result.registers else None
                    except Exception as e:
                        logger.error(f"Error reading {field} tag {tag} for {machine.name}: {e}")
                        readings[field] = None

                MachineReading.objects.create(
                    machine=machine,
                    current=readings.get('current'),
                    kwh=readings.get('kwh'),
                    voltage=readings.get('voltage'),
                    timestamp=timezone.now()
                )
                logger.info(f"Saved reading for {machine.name}: {readings}")

            except Exception as e:
                logger.error(f"Error processing machine {machine.name}: {e}")
    finally:
        modbus.close()