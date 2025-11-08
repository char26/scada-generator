from enum import IntEnum


class ModbusPacket:
    def __init__(self, func: bytes, data: list[bytes], checksum: bytes) -> None:
        """
        https://www.modbustools.com/modbus.html

        ignoring worker address within packet representation

        func: 1 byte, function code
        data: list of bytes (everything after func until checksum)
            https://www.modbustools.com/modbus.html#Function01
        checksum: 2 bytes

        example data bytes from above example:
            [0x000A, 0x000D]
            Starting Address Hi+Lo, Quantity Hi+Lo
        """
        self.func = func
        self.data = data
        self.checksum = checksum


class ModbusFunction(IntEnum):
    READ_COILS = 0x01
    READ_DISCRETE_INPUTS = 0x02
    READ_HOLDING_REGISTERS = 0x03
    READ_INPUT_REGISTERS = 0x04
    WRITE_SINGLE_COIL = 0x05
    WRITE_SINGLE_REGISTER = 0x06
    WRITE_MULTIPLE_COILS = 0x0F
    WRITE_MULTIPLE_REGISTERS = 0x10
