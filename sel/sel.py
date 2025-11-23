"""
This script is used to analyze the TCP streams in a PCAP file.
It extracts the TCP streams, analyzes the ASCII data of the streams,
and prints the summary statistics.

Sonnet 4.5 with code completion was used as a baseline to generate the original functions.
"""

from scapy.all import rdpcap, Raw, TCP, IP
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

OUTPUT_FILE = "sel_analysis.txt"

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

    Args:
        packets: list
            List of packets

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
                    "size": len(bytes(packet)),  # total size of the packet
                    "timestamp": packet.time,
                }
            )

            # Append data to stream
            if raw_data:
                streams[stream_id]["data"] += raw_data

    return streams


def get_sel_streams(streams: dict):
    """Get the SEL streams from the streams dictionary

    Args:
        streams: dict
            Dictionary of TCP streams with their packets

    Returns:
        dict: Dictionary of SEL streams with their packets
    """
    assert isinstance(streams, dict), "streams must be a dictionary"
    assert len(streams) > 0, "streams must not be empty"

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

    assert len(sel_streams) > 0, "No SEL streams found"
    return sel_streams


def analyze_sel(sel_streams: dict):
    """Analyze SEL ASCII data of the streams

    Args:
        sel_streams: dict
            Dictionary of SEL streams with their packets
    """
    assert isinstance(sel_streams, dict), "sel_streams must be a dictionary"
    assert len(sel_streams) > 0, "sel_streams must not be empty"

    logger.info(f"Writing SEL analysis to {OUTPUT_FILE}")

    with open(OUTPUT_FILE, "w") as f:
        f.write(f"Unique SEL ASCII streams: {len(sel_streams.keys())}\n")
        for key in sel_streams.keys():
            # sel_streams format is:
            # ascii_sequence: { "packets": [[stream_1 packets], [stream_2 packets], ...]}
            # Each unique ASCII sequence is a key, and the
            # value is a list of a list of each stream's packets
            # Using this, we can aggregate the packets and analyze characteristics of each stream.
            all_packet_streams = sel_streams[key]["packets"]

            avg_packet_iats: list[float] = []  # inter-arrival times
            unique_packet_sizes: set[int] = set()
            session_durations: list[float] = []
            for stream in all_packet_streams:
                # list of all iat's for this stream
                this_stream_iats = get_packet_iat(stream)
                avg_packet_iats.append(
                    round(sum(this_stream_iats) / len(this_stream_iats), 4)
                )
                unique_packet_sizes.update([packet["size"] for packet in stream])
                session_durations.extend(
                    [round(float(stream[-1]["timestamp"] - stream[0]["timestamp"]), 3)]
                )

            # number of streams with this sequence
            num_streams: int = len(all_packet_streams)
            num_packets: list[int] = [len(stream) for stream in all_packet_streams]

            f.write(f"== UNIQUE STREAM ==\n{key}\n")
            f.write(f"Number of streams with this sequence: {num_streams}\n")
            f.write(f"Number of packets in each stream: {num_packets}\n")
            f.write(f"Duration of each stream (seconds): {session_durations}\n")
            f.write(f"Unique packet sizes: {unique_packet_sizes}\n")
            f.write(
                f"Average packet inter-arrival times per stream: {avg_packet_iats}\n"
            )
            f.write(f"{'-' * 100}\n\n")

    logger.info(f"Finished writing SEL analysis to {OUTPUT_FILE}")


def get_packet_iat(packets: list):
    """Get the inter-arrival times between packets

    Args:
        packets: list
            List of packets

    Returns:
        list: List of inter-arrival times
    """
    return [
        float(packets[i + 1]["timestamp"] - packets[i]["timestamp"])
        for i in range(len(packets) - 1)
    ]


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python sel.py <pcap_file_path>")
        sys.exit(1)
    pcap_file_path = sys.argv[1]
    packets = load_pcap(pcap_file_path)

    # Extract TCP streams
    logger.info("Extracting TCP streams...")
    streams = extract_tcp_streams(packets)

    logger.info("Analyzing SEL streams...")
    sel_streams = get_sel_streams(streams)
    analyze_sel(sel_streams)


"""
TODO:
such as total size, direction, and type, convert packets into their bitwise representation,
and stack packets from the same flow. Additionally, we add extra derived information to the signature
that might be relevant in fingerprinting, such as number of packets in the signature, packet inter-arrival times
(shown in the IEC 104 example on the left) and a packet’s relative position in the flow (shown in the MODBUS example on
the right).
"""
