"""
Run synthetic traffic against a Modbus server and analyze properties of queries and responses.

This script was written collaboratively with Opus 4.5. The LLM was primarily used to assist with
statistics collection and debugging, as these parts are quite tedious.

Run with:
python3 server/server_async.py --port 8080

sudo python3 test.py --filepath <path to pcap file>

sudo is required for scapy.
"""

from scapy.all import rdpcap, TCP
from scapy.contrib.modbus import ModbusADURequest, ModbusADUResponse
import socket
import argparse
import sys
from collections import defaultdict

HOST = "127.0.0.1"
PORT = 8080

stats = {
    "valid_queries": 0,
    "valid_responses": 0,
    "malformed_packets": 0,
    "response_errors": 0,
    "response_matches": 0,
    "response_mismatches": 0,
    "missing_synthetic": 0,
}

field_diffs = defaultdict(int)


def compare_modbus_fields(synthetic_layer, actual_layer):
    """
    Compare all fields between synthetic and actual Modbus responses.

    Returns:
        dict: {field_name: (synthetic_value, actual_value)} for differing fields
    """
    differences = {}

    mbap_fields = ["transId", "protoId", "len", "unitId"]

    for field in mbap_fields:
        synthetic_val = getattr(synthetic_layer, field, None)
        actual_val = getattr(actual_layer, field, None)
        if synthetic_val != actual_val:
            differences[field] = (synthetic_val, actual_val)

    synthetic_pdu = synthetic_layer.payload
    actual_pdu = actual_layer.payload

    synthetic_pdu_fields = (
        set(synthetic_pdu.fields.keys()) if hasattr(synthetic_pdu, "fields") else set()
    )
    actual_pdu_fields = (
        set(actual_pdu.fields.keys()) if hasattr(actual_pdu, "fields") else set()
    )
    all_pdu_fields = synthetic_pdu_fields | actual_pdu_fields

    for field in all_pdu_fields:
        synthetic_val = getattr(synthetic_pdu, field, None)
        actual_val = getattr(actual_pdu, field, None)

        if isinstance(synthetic_val, (list, bytes)) and isinstance(
            actual_val, (list, bytes)
        ):
            if list(synthetic_val) != list(actual_val):
                differences[field] = (synthetic_val, actual_val)
        elif synthetic_val != actual_val:
            differences[field] = (synthetic_val, actual_val)

    return differences


def load_modbus_transactions_from_pcap(pcap_file):
    """
    Load Modbus TCP packets from a pcap file and group by transaction ID.

    Returns:
        Dict mapping transId -> {"request": ..., "synthetic_response": ...}
    """
    print(f"Loading packets from: {pcap_file}")

    try:
        packets = rdpcap(pcap_file)
        print(f"Total packets in pcap: {len(packets)}")
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        sys.exit(1)

    transactions = defaultdict(lambda: {"request": None, "synthetic_response": None})

    for i, pkt in enumerate(packets):
        if "IP" not in pkt or TCP not in pkt:
            stats["malformed_packets"] += 1
            continue

        if ModbusADURequest in pkt:
            modbus_layer = pkt[ModbusADURequest]
            trans_id = modbus_layer.transId
            transactions[trans_id]["request"] = {
                "index": i,
                "payload": bytes(modbus_layer),
                "layer": modbus_layer,
                "src": f"{pkt['IP'].src}:{pkt[TCP].sport}",
                "dst": f"{pkt['IP'].dst}:{pkt[TCP].dport}",
            }

        elif ModbusADUResponse in pkt:
            modbus_layer = pkt[ModbusADUResponse]
            trans_id = modbus_layer.transId
            transactions[trans_id]["synthetic_response"] = {
                "index": i,
                "payload": bytes(modbus_layer),
                "layer": modbus_layer,
                "src": f"{pkt['IP'].src}:{pkt[TCP].sport}",
                "dst": f"{pkt['IP'].dst}:{pkt[TCP].dport}",
            }
        else:
            stats["malformed_packets"] += 1

    complete_transactions = {}
    for trans_id, data in transactions.items():
        if data["request"] is not None:
            complete_transactions[trans_id] = data
            if data["synthetic_response"] is None:
                stats["missing_synthetic"] += 1

    print(f"\nFound {len(complete_transactions)} Modbus transactions")
    print(
        f"  - With synthetic response: {len(complete_transactions) - stats['missing_synthetic']}"
    )
    print(f"  - Missing synthetic response: {stats['missing_synthetic']}")

    return complete_transactions


def send_and_compare(trans_id, request_data, synthetic_response_data):
    """Send a Modbus request and compare response to synthetic."""
    payload = request_data["payload"]

    print(f"\n[Transaction {trans_id}]")
    print(f"  Request: {request_data['layer'].summary()}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, PORT))

        sock.send(payload)
        actual_response = sock.recv(1024)
        sock.close()

        try:
            parsed_response = ModbusADUResponse(actual_response)
            print(f"  Actual Response: {parsed_response.summary()}")
            # Considering a response "valid" if scapy can parse it as a ModbusADUResponse
            stats["valid_responses"] += 1

            # Consider a request "valid" if scapy receives a valid response for it
            # This might require more thought.
            stats["valid_queries"] += 1
        except Exception as e:
            print(f"  Error parsing response: {e}")
            stats["response_errors"] += 1
            return False

        if synthetic_response_data is None:
            print(f"  ⚠ No synthetic response to compare")
            return None

        synthetic_payload = synthetic_response_data["payload"]

        if actual_response == synthetic_payload:
            print(f"  ✓ Response MATCHES synthetic")
            stats["response_matches"] += 1
            return True
        else:
            print(f"  ✗ Response MISMATCH")

            synthetic_layer = synthetic_response_data["layer"]
            differences = compare_modbus_fields(synthetic_layer, parsed_response)

            if differences:
                print(f"    Field differences:")
                for field, (synthetic_val, actual_val) in differences.items():
                    field_diffs[field] += 1

                    if isinstance(synthetic_val, bytes):
                        synthetic_str = synthetic_val.hex()
                        actual_str = (
                            actual_val.hex()
                            if isinstance(actual_val, bytes)
                            else str(actual_val)
                        )
                    elif isinstance(synthetic_val, list) and len(synthetic_val) > 10:
                        synthetic_str = f"[{len(synthetic_val)} items]"
                        actual_str = (
                            f"[{len(actual_val)} items]"
                            if isinstance(actual_val, list)
                            else str(actual_val)
                        )
                    else:
                        synthetic_str = str(synthetic_val)
                        actual_str = str(actual_val)

                    print(f"      {field}: synthetic {synthetic_str}, got {actual_str}")
            else:
                # Bytes differ but parsed fields are same - show raw comparison
                print(f"    Raw bytes differ (parsed fields match):")
                print(f"      Synthetic: {synthetic_payload.hex()}")
                print(f"      Actual:    {actual_response.hex()}")

            stats["response_mismatches"] += 1
            return False

    except socket.timeout:
        print("  Error: Connection timeout")
        stats["response_errors"] += 1
        return False
    except socket.error as e:
        print(f"  Socket error: {e}")
        stats["response_errors"] += 1
        return False
    except Exception as e:
        print(f"  Error: {e}")
        stats["response_errors"] += 1
        return False


def replay_transactions(transactions, limit=None):
    """Replay all Modbus transactions and compare responses."""
    print(f"\n{'='*60}")
    print(f"Replaying transactions to {HOST}:{PORT}")
    print("=" * 60)

    trans_ids = list(transactions.keys())
    if limit:
        trans_ids = trans_ids[:limit]

    for trans_id in trans_ids:
        data = transactions[trans_id]
        send_and_compare(trans_id, data["request"], data["synthetic_response"])


def main():
    global HOST, PORT
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--filepath", type=str, required=True, help="Path to the pcap file"
    )
    parser.add_argument("--host", default=HOST, help=f"Target host (default: {HOST})")
    parser.add_argument(
        "--port", type=int, default=PORT, help=f"Target port (default: {PORT})"
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="Limit number of transactions to replay"
    )

    args = parser.parse_args()

    HOST = args.host
    PORT = args.port

    transactions = load_modbus_transactions_from_pcap(args.filepath)

    if not transactions:
        print("No Modbus transactions found in pcap file")
        sys.exit(1)

    replay_transactions(transactions, limit=args.limit)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total transactions: {len(transactions)}")
    print(f"  Valid queries: {stats['valid_queries']}")
    print(f"  Valid responses: {stats['valid_responses']}")
    print(f"  Response mismatches:   {stats['response_mismatches']}")
    print(f"  Response errors:       {stats['response_errors']}")
    print(f"  Missing synthetic response: {stats['missing_synthetic']}")

    if field_diffs:
        print(f"\nField Difference Breakdown:")
        print("-" * 40)
        for field, count in sorted(field_diffs.items(), key=lambda x: -x[1]):
            print(f"  {field}: {count} mismatches")


if __name__ == "__main__":
    main()
