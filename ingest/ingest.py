from collections import defaultdict
import pyshark
import logging

logger = logging.getLogger(__name__)

logging.basicConfig(level=logging.INFO)


def get_all_fields(capture: pyshark.FileCapture, protocol: str = "modbus"):
    """
    Get all fields in the modbus layer for each packet
    Returns a set of field names

    While it would be faster to hard code the fields for our data, this
    allows us to easily ingest new datasets without changing this code.

    Args:
        capture: pyshark.FileCapture
            The capture should already be loaded with packets
        protocol: str
            The protocol to get the fields from

    Returns:
        set: set of field names
    """
    logger.info(f"Collecting fields for {protocol}...")
    all_fields = set()
    for packet in capture:
        protocol_layer = packet[protocol]
        all_fields.update(protocol_layer.field_names)
    all_fields.remove("")  # modbus has an empty field, for example
    return all_fields


def get_layer_field_values(packet, protocol: str, field: str):
    """
    Get the values from the layer field in the packet and return a list of default values.

    Layer fields are tricky to work with, so this is a helper to unwrap them.

    Args:
        packet:
            The packet from a pyshark.FileCapture to get the layer field values from
        protocol: str
            The protocol to get the layer field values from
        field: str
            The layer field to get the values from

    Returns:
        list: list of default values for the layer field

    This workaround was found here:
    https://osqa-ask.wireshark.org/questions/50063/getting-register-values-from-modbustcp-response/
    """

    if not hasattr(packet[protocol], field):
        return []
    protocol_layer = getattr(packet, protocol)

    if not hasattr(protocol_layer, field):
        return []
    unwrapped = getattr(protocol_layer, field)

    return [layer_field.get_default_value() for layer_field in unwrapped.all_fields]


def load_matrix(capture: pyshark.FileCapture, protocol: str = "modbus"):
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
    logger.info(f"Building matrix for {protocol}...")
    for packet in capture:
        protocol_layer = packet[protocol]
        for field in all_fields:
            if not hasattr(protocol_layer, field):
                dict_matrix[field].append(None)
                continue
            # These fields require some special processing
            if field in ["regval_uint16", "regnum16"]:
                dict_matrix[field].append(
                    get_layer_field_values(packet, protocol, field)
                )
            else:
                dict_matrix[field].append(getattr(protocol_layer, field))
    return dict_matrix


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Load Modbus packet matrix from PCAP file."
    )

    parser.add_argument(
        "--filepath",
        type=str,
        required=True,
        help="Path to pcap file containing Modbus packets",
    )
    parser.add_argument(
        "--display_filter",
        type=str,
        default="modbus",
        help="Pyshark display filter to use (default: 'modbus')",
    )
    args = parser.parse_args()

    capture = pyshark.FileCapture(
        args.filepath,
        display_filter=args.display_filter,
    )
    logger.info(f"Loading capture from {args.filepath}")
    capture.load_packets()

    matrix = load_matrix(capture, args.display_filter)
    print(matrix)


if __name__ == "__main__":
    main()
