import asyncio
from client.modbus_provider import ModbusProvider
from coordinator.coordinator import Coordinator
from modbus_packet import ModbusPacket


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
    await coordinator.send_to_provider(
        "provider1", ModbusPacket(1, bytes([0, 8]), None)
    )
    # await coordinator.send_to_provider(
    #     "provider2", ModbusPacket(1, bytes([3, 4]), None)
    # )

    # Keep running
    await asyncio.sleep(10)


if __name__ == "__main__":
    asyncio.run(main())
