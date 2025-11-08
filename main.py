import asyncio
from client.modbus_provider import ModbusProvider
from coordinator.coordinator import Coordinator
from modbus_packet import ModbusPacket, ModbusFunction


async def main():
    coordinator = Coordinator()

    # Create multiple providers
    provider1 = ModbusProvider(("localhost", 8080))
    # provider2 = ModbusProvider(("localhost", 8080))

    coordinator.add_provider("provider1", provider1)
    # coordinator.add_provider("provider2", provider2)

    # Start all providers in background
    asyncio.create_task(coordinator.start_all())

    # Send packets
    start_address = 0x0001
    count = 0x0002
    byte_count = 0x04
    write_data1 = 0xFFFF
    write_data2 = 0xFFFF
    await coordinator.send_to_provider(
        "provider1",
        ModbusPacket(
            ModbusFunction.WRITE_MULTIPLE_REGISTERS,
            [start_address, count, byte_count, write_data1, write_data2],
            None,
        ),
    )

    # await coordinator.send_to_provider(
    #     "provider2", ModbusPacket(1, bytes([3, 4]), None)
    # )

    # Keep running
    await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
