from pymodbus.client import AsyncModbusTcpClient, AsyncModbusUdpClient
import asyncio
from modbus_packet import ModbusPacket


class ModbusProvider:
    """Represents a device communicating over Modbus"""

    def __init__(self, dest: tuple[str, int], mode: str = "tcp"):
        self.dest_address = dest[0]
        self.dest_port = dest[1]
        if mode == "tcp":
            self.client = AsyncModbusTcpClient(self.dest_address, port=self.dest_port)
        elif mode == "udp":
            self.client = AsyncModbusUdpClient(self.dest_address, port=self.dest_port)
        else:
            raise ValueError(f"Invalid mode: {mode}")
        self.queue = asyncio.Queue()
        self.running = False

    async def connect(self):
        await self.client.connect()
        if not self.client.connected:
            raise ConnectionError(
                f"Failed to connect to {self.dest_address}:{self.dest_port}"
            )
        print(f"Connected to {self.dest_address}:{self.dest_port}")

    async def start(self):
        """Start processing packets from queue"""
        await self.connect()
        self.running = True
        while self.running:
            try:
                packet = await self.queue.get()
                await self._process_packet(packet)
                print(f"Processed packet: {packet}")
            except Exception as e:
                print(f"Error processing packet: {e}")

    async def _process_packet(self, packet: ModbusPacket):
        if packet.func == 1:
            print("Address = ", packet.data[0], "Count = ", packet.data[1])
            result = await self.client.read_coils(packet.data[0], count=packet.data[1])
            print(
                f"Read coils result: {result.bits[0:packet.data[1]]}"
            )  # seems like a bug where it returns more than count sometimes (count > 9?)
        # TODO: more function codes

    async def send_packet(self, packet: ModbusPacket):
        """Add packet to queue for processing"""
        await self.queue.put(packet)

    async def stop(self):
        self.running = False
        if self.client:
            self.client.close()
