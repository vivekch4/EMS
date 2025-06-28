from channels.generic.websocket import AsyncWebsocketConsumer
import json

class MachineReadingConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.channel_layer.group_add("machine_readings", self.channel_name)
        await self.channel_layer.group_add("alarms", self.channel_name)
        await self.channel_layer.group_add("notifications", self.channel_name)  # Add notifications group
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard("machine_readings", self.channel_name)
        await self.channel_layer.group_discard("alarms", self.channel_name)
        await self.channel_layer.group_discard("notifications", self.channel_name)

    async def reading_message(self, event):
        await self.send(text_data=json.dumps(event["message"]))

    async def alarm_message(self, event):
        await self.send(text_data=json.dumps(event["message"]))

    async def notification_message(self, event):
        await self.send(text_data=json.dumps(event["message"]))