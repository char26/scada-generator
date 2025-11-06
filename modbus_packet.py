class ModbusPacket:
    def __init__(self, func: bytes, data: bytes, checksum: bytes) -> None:
        self.func = func
        self.data = data
        self.checksum = checksum
