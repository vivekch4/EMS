import logging
from pymodbus.client import ModbusTcpClient
import time
from .models import PLCConnection

logger = logging.getLogger(__name__)

class ModbusConnection:
    def __init__(self, timeout=10, retries=3):
        self.client = None
        self.timeout = timeout
        self.retries = retries

    def get_client(self):
        try:
            plc = PLCConnection.objects.first()  # Get the single PLC connection
            if not plc:
                logger.error("No PLC connection found in database")
                return None
            self.client = ModbusTcpClient(
                host=plc.ip_address,
                port=plc.port,
                timeout=self.timeout
            )
            for attempt in range(self.retries + 1):
                try:
                    if self.client.connect():
                        logger.info(f"Connected to Modbus server at {plc.ip_address}:{plc.port} on attempt {attempt + 1}")
                        return self.client
                    else:
                        logger.warning(f"Connection attempt {attempt + 1} failed for {plc.ip_address}:{plc.port}")
                except Exception as conn_error:
                    logger.error(f"Connection attempt {attempt + 1} error: {str(conn_error)}")
                if attempt < self.retries:
                    time.sleep(1)
            logger.error(f"Failed to connect to Modbus server at {plc.ip_address}:{plc.port} after {self.retries + 1} attempts")
            return None
        except Exception as e:
            logger.error(f"Error establishing Modbus connection: {e}")
            return None

    def close(self):
        if self.client and self.client.is_socket_open():
            self.client.close()
            logger.info("Modbus connection closed")