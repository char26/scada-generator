from pymodbus.client import AsyncModbusTcpClient, AsyncModbusUdpClient
import rpyc
import asyncio
import sys
from rpyc.utils.server import ThreadedServer


class ModbusProvider(rpyc.Service):
    """
    Wrapper for pymodbus clients to represent a Modbus connection between a single source and destination.

    Receives a ModbusPacket from the coordinator and sends it to the destination.

    Args:
        dest: Tuple of destination address and port.
        mode: Mode of the connection. Can be "tcp" or "udp".
    """

    def __init__(
        self,
        dest: tuple[str, int],
        mode: str = "tcp",
    ) -> None:
        self.dest_address = dest[0]
        self.dest_port = dest[1]
        self.mode = mode

        if mode == "tcp":
            self.client = AsyncModbusTcpClient(self.dest_address, port=self.dest_port)
        elif mode == "udp":
            self.client = AsyncModbusUdpClient(self.dest_address, port=self.dest_port)
        else:
            raise ValueError(f"Invalid mode: {mode}")

    def cleanup(self) -> None:
        self.client.close()

    @staticmethod
    async def create_and_connect(
        dest: tuple[str, int], mode: str = "tcp"
    ) -> "ModbusProvider":
        provider = ModbusProvider(dest, mode)
        await provider.client.connect()
        assert provider.client.connected

        ## Test
        await provider.client.write_coil(2, False)
        result = await provider.client.read_coils(2, count=1)
        print(result.bits[0])
        ##

        return provider


if __name__ == "__main__":
    asyncio.run(ModbusProvider.create_and_connect(("localhost", 8080), "tcp"))

    rpyc_port = 18861
    t = ThreadedServer(ModbusProvider, port=rpyc_port)
    t.start()
