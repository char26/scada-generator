"""
This script is used to analyze the TCP streams in a PCAP file.
It extracts the TCP streams, analyzes the ASCII data of the streams,
and prints the summary statistics.

Sonnet 4.5 was used to generate the pretty print functions.
"""

from scapy.all import rdpcap, Raw, TCP, IP
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

SEL_KEYWORDS = [
    "QUIT",
    "ACCES",
    "ACCESS",
    "2ACCESS",
    "BREAKER",
    "DATE",
    "EVENT",
    "GROUP",
    "HISTORY",
    "IRIG",
    "METER",
    "SHOWSET",
    "STATUS",
    "TIME",
    "TRIGGER",
    "CLOSE",
    "OPEN",
    "COPY",
    "PASSWORD",
    "SET",
    "TARGET",
]


def bytes_to_readable_ascii(data: bytes) -> str:
    """Convert bytes to ASCII, keeping common control chars like \r \n \t"""
    result = []
    for b in data:
        if 32 <= b <= 126:  # printable ASCII
            result.append(chr(b))
        elif b == 13:  # \r
            result.append("\\r")
        elif b == 10:  # \n
            result.append("\\n")
        elif b == 9:  # \t
            result.append("\\t")
        else:
            result.append(".")
    return "".join(result)


def load_pcap(pcap_path: str):
    """Load a PCAP file into a list of packets"""
    logger.info(f"Loading PCAP from {pcap_path}")
    packets = rdpcap(pcap_path)
    logger.info(f"Loaded {len(packets)} packets")
    return packets


def extract_tcp_streams(packets):
    """
    Extract TCP streams from packets.
    A stream is defined by the 5-tuple: (src_ip, src_port, dst_ip, dst_port, protocol)
    We track each direction separately.

    Returns:
        dict: Dictionary of streams with their packets and data
    """
    streams = defaultdict(lambda: {"packets": [], "data": b""})

    for i, packet in enumerate(packets):
        if TCP in packet and IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

            stream_id = (src_ip, src_port, dst_ip, dst_port)

            # Get raw data if present
            raw_data = b""
            if Raw in packet:
                raw_data = bytes(packet[Raw].load)

            # Add to stream
            streams[stream_id]["packets"].append(
                {
                    "packet_num": i,
                    "seq": packet[TCP].seq,
                    "ack": packet[TCP].ack,
                    "flags": str(packet[TCP].flags),
                    "data": raw_data,
                    "data_len": len(raw_data),
                    "timestamp": packet.time,
                }
            )

            # Append data to stream
            if raw_data:
                streams[stream_id]["data"] += raw_data

    return streams


def print_tcp_streams(streams):
    """
    Print all TCP streams with their ASCII data
    """
    print("=" * 100)
    print(f"TCP STREAM ANALYSIS")
    print(f"Total streams found: {len(streams)}")
    print("=" * 100)

    # Sort streams by total data length (descending)
    sorted_streams = sorted(
        streams.items(), key=lambda x: len(x[1]["data"]), reverse=True
    )

    for stream_num, (stream_id, stream_data) in enumerate(sorted_streams, 1):
        src_ip, src_port, dst_ip, dst_port = stream_id
        packets = stream_data["packets"]
        data = stream_data["data"]

        # Skip empty streams
        if len(data) == 0:
            continue

        print(f"\n{'=' * 100}")
        print(f"Stream #{stream_num}")
        print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        print(f"  Packets: {len(packets)} | Total Data: {len(data)} bytes")

        if packets:
            print(
                f"  Packet Range: #{packets[0]['packet_num']} - #{packets[-1]['packet_num']}"
            )

        print(f"{'-' * 100}")

        # Show ASCII data
        ascii_data = bytes_to_readable_ascii(data)
        print(f"\nASCII Data:")
        print(f"  {ascii_data}")

        # Show hex for small streams
        if len(data) <= 100:
            print(f"\nHEX:")
            print(f"  {data.hex()}")

        # Show packet breakdown for small streams
        if len(packets) <= 20:
            print(f"\nPacket Breakdown:")
            for pkt in packets:
                if pkt["data_len"] > 0:
                    pkt_ascii = bytes_to_readable_ascii(pkt["data"])
                    print(
                        f"  Pkt #{pkt['packet_num']:6d} [{pkt['flags']:>4s}] ({pkt['data_len']:4d} bytes): {pkt_ascii[:80]}"
                    )

    print("\n" + "=" * 100)


def print_stream_summary(streams):
    """Print summary statistics"""
    total_streams = len(streams)
    streams_with_data = sum(1 for s in streams.values() if len(s["data"]) > 0)
    total_data = sum(len(s["data"]) for s in streams.values())

    print("\n" + "=" * 100)
    print("SUMMARY")
    print("=" * 100)
    print(f"  Total streams: {total_streams}")
    print(f"  Streams with data: {streams_with_data}")
    print(f"  Total data bytes: {total_data}")

    if streams_with_data > 0:
        avg_data = total_data / streams_with_data
        print(f"  Average data per stream: {avg_data:.1f} bytes")

    print("=" * 100)


def get_sel_streams(streams: dict):
    sel_streams = {}
    for stream in streams.keys():
        ascii_data = bytes_to_readable_ascii(streams[stream]["data"])
        if any(keyword in ascii_data for keyword in SEL_KEYWORDS):
            # Characterize a SEL stream if any of the keywords are present
            if ascii_data not in sel_streams:
                sel_streams[ascii_data] = {
                    "stream": stream,
                    "packets": [streams[stream]["packets"]],
                }
            else:
                sel_streams[ascii_data]["packets"].append(streams[stream]["packets"])
    return sel_streams


def analyze_sel(sel_streams: dict):
    """Analyze SEL ASCII data of the streams"""
    print(f"Unique SEL ASCII streams: {len(sel_streams.keys())}")
    for key in sel_streams.keys():
        # Each unique ASCII sequence is a key, and the
        # value is a list of a list of each stream's packets
        # Using this, we can aggregate the packets and analyze characteristics of each stream.
        all_stream_packets = sel_streams[key]["packets"]
        # Intervals are time since last packet
        packet_intervals = []
        packet_sizes = []
        for stream in all_stream_packets:
            packet_intervals.extend(get_packet_intervals(stream))
            packet_sizes.extend([packet["data_len"] for packet in stream])

        print(f"UNIQUE STREAM\n{key}\n")
        print(f"Number of streams with this sequence: {len(sel_streams[key])}")
        print(f"Average packet size: {sum(packet_sizes) / len(packet_sizes)}")
        print(
            f"Average packet interval: {sum(packet_intervals) / len(packet_intervals)}"
        )
        print(f"{'-' * 100}")


def get_packet_intervals(packets: list):
    """Get the intervals between packets"""
    return [
        packets[i + 1]["timestamp"] - packets[i]["timestamp"]
        for i in range(len(packets) - 1)
    ]


if __name__ == "__main__":
    packets = load_pcap(
        "/Users/charliealders/SCADA_Data/Modbus/substation_split_00001_20180828162856.pcap"
    )

    # Extract TCP streams
    print("\nExtracting TCP streams...")
    streams = extract_tcp_streams(packets)

    sel_streams = get_sel_streams(streams)
    analyze_sel(sel_streams)
