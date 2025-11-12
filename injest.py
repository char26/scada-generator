import pyshark

cap = pyshark.FileCapture(
    "/Users/charliealders/SCADA_Data/Modbus/modbus_RTU_6h_1.pcap",
    display_filter="modbus",
)
cap.load_packets()
print(len(cap))
print(cap[3])

prev_ts = None
for packet in cap:
    modbus = packet.modbus

    timestamp = float(packet.sniff_time.timestamp())
    func_code = int(modbus.func_code)
    reference_num = int(modbus.reference_num) if hasattr(modbus, "reference_num") else 0
    word_cnt = int(modbus.word_cnt) if hasattr(modbus, "word_cnt") else 0

    print(timestamp)
    print(modbus.func_code)

    break
