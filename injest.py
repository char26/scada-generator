from collections import defaultdict
import pyshark


def get_all_fields(capture):
    """
    Get all fields in the modbus layer for each packet
    Returns a set of field names

    While it would be faster to hard code the fields for our data, this
    allows us to easily injest new datasets without changing this code.

    Args:
        capture: pyshark.FileCapture
            The capture should already be loaded with packets

    Returns:
        set: set of field names
    """
    all_fields = set()
    for packet in capture:
        modbus = packet.modbus
        all_fields.update(modbus.field_names)
    return all_fields


def load_matrix(capture):
    """
    Load the matrix of fields for each packet
    Returns a dictionary of field names and their values

    Args:
        capture: pyshark.FileCapture
            The capture should already be loaded with packets

    Returns:
        dict: dictionary of field names and their values
    """
    all_fields = get_all_fields(capture)
    dict_matrix = defaultdict(list)
    for packet in capture:
        modbus = packet.modbus
        for field in all_fields:
            if not hasattr(modbus, field):
                dict_matrix[field].append(None)
                continue
            dict_matrix[field].append(getattr(modbus, field))
    return dict_matrix


def main():
    capture = pyshark.FileCapture(
        "/Users/charliealders/SCADA_Data/Modbus/modbus_RTU_6h_1.pcap",
        display_filter="modbus",
    )
    capture.load_packets()

    matrix = load_matrix(capture)
    print(matrix)


if __name__ == "__main__":
    main()
