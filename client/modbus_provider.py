from pymodbus.client import AsyncModbusTcpClient, AsyncModbusUdpClient
import asyncio
from modbus_packet import ModbusPacket, ModbusFunction


class ModbusProvider:
    """Represents a device communicating over Modbus"""

    # TODO: this is currently assuming RTU mode, which is all we have data for.

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
            except Exception as e:
                print(f"Error processing packet: {e}")

    async def _process_packet(self, packet: ModbusPacket):
        # TODO: checksum validation
        if packet.func == ModbusFunction.READ_COILS:
            start_address = packet.data[0]
            quantity = packet.data[1]
            result = await self.client.read_coils(start_address, count=quantity)
            print(
                f"Read coils result: {result}"
            )  # seems like a bug where it returns more than quantity sometimes (quantity > 9?)

        elif packet.func == ModbusFunction.READ_DISCRETE_INPUTS:
            start_address = packet.data[0]
            quantity = packet.data[1]
            result = await self.client.read_discrete_inputs(
                start_address, count=quantity
            )
            print(f"Read discrete inputs result: {result}")

        elif packet.func == ModbusFunction.READ_HOLDING_REGISTERS:
            start_address = packet.data[0]
            quantity = packet.data[1]
            result = await self.client.read_holding_registers(
                start_address, count=quantity
            )
            print(f"Read holding registers result: {result}")

        elif packet.func == ModbusFunction.READ_INPUT_REGISTERS:
            start_address = packet.data[0]
            quantity = packet.data[1]
            result = await self.client.read_input_registers(
                start_address, count=quantity
            )
            print(f"Read input registers result: {result}")

        elif packet.func == ModbusFunction.WRITE_SINGLE_COIL:
            address = packet.data[0]
            value = packet.data[1]
            result = await self.client.write_coil(address, value)
            print(f"Write single coil result: {result}")

        elif packet.func == ModbusFunction.WRITE_SINGLE_REGISTER:
            address = packet.data[0]
            value = packet.data[1]
            result = await self.client.write_register(address, value)
            print(f"Write single register result: {result}")

        elif packet.func == ModbusFunction.WRITE_MULTIPLE_COILS:
            # this one is more complicated than the others
            start_address = packet.data[0]
            # Modbus protocol specifies quantity, but pymodbus infers it from len(write_data)
            # so quantity is ignored in write_multiple_coils.
            quantity = packet.data[1]

            byte_count = packet.data[2]
            # 0xCD01 -> 1 1 0 0 1 1 0 1 0 0 0 0 0 0 0 1
            # Starting at coil start_address, set the bits in the order they appear
            write_data = packet.data[3]
            coil_values: list[bool] = []
            for i in range(byte_count * 8):
                bit = (write_data >> i) & 1
                coil_values.insert(0, bool(bit))
            print(f"Coil values: {coil_values}")
            result = await self.client.write_coils(start_address, values=coil_values)
            print(f"Write multiple coils result: {result}")

        elif packet.func == ModbusFunction.WRITE_MULTIPLE_REGISTERS:
            start_address = packet.data[0]
            # Modbus protocol specifies quantity, but pymodbus infers it from len(write_data)
            # so quantity is ignored in write_multiple_coils.
            quantity = packet.data[1]
            byte_count = packet.data[2]
            # each register gets 2 bytes, so byte_count == 4 means 2 registers
            # this should be formatted as [0xHILO, 0xHILO, etc...]
            write_data = packet.data[3:]
            print(f"Register values: {write_data}")
            result = await self.client.write_registers(start_address, values=write_data)
            print(f"Write multiple registers result: {result}")

    async def send_packet(self, packet: ModbusPacket):
        """Add packet to queue for processing"""
        await self.queue.put(packet)

    async def stop(self):
        self.running = False
        if self.client:
            self.client.close()
