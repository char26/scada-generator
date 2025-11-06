import asyncio

from client.modbus_provider import ModbusProvider
from modbus_packet import ModbusPacket


class Coordinator:
    def __init__(self):
        self.providers = {}

    def add_provider(self, name: str, provider: ModbusProvider):
        self.providers[name] = provider

    async def start_all(self):
        """Start all providers concurrently"""
        tasks = [provider.start() for provider in self.providers.values()]
        await asyncio.gather(*tasks)

    async def stop_all(self):
        """Stop all providers concurrently"""
        tasks = [provider.stop() for provider in self.providers.values()]
        await asyncio.gather(*tasks)

    async def send_to_provider(self, provider_name: str, packet: ModbusPacket):
        provider = self.providers.get(provider_name)
        assert provider, f"Provider {provider_name} not found"
        await provider.send_packet(packet)
