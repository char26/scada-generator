# Boilerplate validation code
import pandas as pd
import pyshark
import argparse
import logging
import scapy.all as send
import injest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

logger = logging.getLogger(__name__)
SERVER_IP = "1.1.1.1" # Placeholder IP
INTERFACE = "eth0"  # Placeholder interface
REAL_PCAP_PATH = "path/to/real_pcap"  # Placeholder path
FAKE_PCAP_PATH = "path/to/fake_pcap"  # Placeholder path

def send_and_receive(packet, timeout=2):
    raw = packet.get_raw_packet()
    scapy_packet = send.Ether(raw)

    # Force destination
    if "IP" in scapy_packet:
        scapy_packet[SERVER_IP].dst = SERVER_IP
        del scapy_packet[SERVER_IP].chksum  # Recalculate checksum
        # May also need to do the mac but gonna see how this goes for now

    answer = send.sr1(scapy_packet, iface=INTERFACE, timeout=timeout, verbose=False)

    if answer is None:
        logger.error("No response for packet with frame number %s", getattr(packet, "number", "unknown"))
    else:
        logger.info("Got response for frame %s", getattr(packet, "number", "unknown"))
    return answer

# This may need to be expanded for both modbus and mqtt
def validate_response(request_packet, response_packet):
    # Grab raw bytes for both
    req_raw = request_packet.get_raw_packet()
    if send.Raw not in response_packet:
        logger.error("Response has no application payload")
        return False

    resp_raw = bytes(response_packet[send.Raw].load)

    # Minimal Modbus/TCP checks
    # 1. Transaction ID (bytes 0–1)
    req_tid = int.from_bytes(req_raw[0:2], "big")
    resp_tid = int.from_bytes(resp_raw[0:2], "big")

    if req_tid != resp_tid:
        logger.error("Transaction ID mismatch: req=%d resp=%d", req_tid, resp_tid)
        return False

    # 2. Function code (after MBAP header: at offset 7)
    req_func = req_raw[7]
    resp_func = resp_raw[7]

    # Excaption response (exceptions always flip highest bit)
    if resp_func == req_func | 0x80:
        exception_code = resp_raw[8]
        logger.error(
            "Modbus exception for TID %d func %d: exception code %d",
            req_tid, req_func, exception_code
        )
        return False

    if resp_func != req_func:
        logger.error("Function code mismatch: req=%d resp=%d", req_func, resp_func)
        return False

    logger.info("Response for TID %d (func %d) looks OK", req_tid, req_func)
    return True


def pcap_to_dataframe(filepath, display_filter):
    df = pd.DataFrame()
    # Use ingest to get the specifed pcap and turn it into a dict
    data_injest = injest.main(["--filepath", filepath, "--display_filter", display_filter]) # Replace with actual filepath and filter as needed

    # Take the keys (field names) and values (lists of field values) and add them to the dataframe
    for name in data_injest.keys():
        df[name] = data_injest[name] # That's a list so hopefully it should just work
    return df

# The fake and real dataframes are hardcoded so using the fake_idx to set the labels
# is probably unnecessary but whatever
def merge_dataframes(df1, df2, fake_idx: int):
    # This also needs to be set up so it adds the labels correctly
    # I want to fill the label column with 0 for real packets and 1 for fake packets
    real_idx = fake_idx ^ 1  # Assuming binary labels 0 and 1
    df1 = df1.copy()
    df2 = df2.copy()
    df1['label'] = real_idx  # Real packets
    df2['label'] = fake_idx  # Fake packets

    # Concatenate dataframes
    merged_df = pd.concat([df1, df2], ignore_index=True)
    # Shuffle the merged dataframe
    merged_df = merged_df.sample(frac=1, random_state=1).reset_index(drop=True)  # Shuffle with fixed random state for reproducibility
    return merged_df

def normalize_dataframe(train_df, test_df):
    scaler = StandardScaler()
    train_scaled = scaler.fit_transform(train_df)
    test_scaled = scaler.transform(test_df)
    return train_scaled, test_scaled

def PCA_reduction(train_df, test_df, n_components=0.95):
    pca = PCA(n_components=0.95)  # Retain 95% of variance
    train_pca = pca.fit_transform(train_df)
    test_pca = pca.transform(test_df)
    return train_pca, test_pca

def train_svm(X_train, y_train, kernel='linear'):
    svm = SVC(kernel, random_state=1) # Kernel can be changed as needed, same with random_state
    return svm.fit(X_train, y_train)

def main():
    parser = argparse.ArgumentParser(
        description="Validate Modbus packet classification using SVM."
    )

    parser.add_argument(
        "--display_filter",
        type=str,
        default="modbus",
        help="Display filter for pyshark capture",
    )
    parser.add_argument(
        "--run_type",
        type=str,
        choices=["Full", "Partial"],
        default="Partial",
        help="Type of run: 'Full' for complete validation, 'Partial' for sending/receiving only",
    )

    args =  parser.parse_args()


    # Need to take the pcap, break it into packets via pyshark
    capture = pyshark.FileCapture(
        args.filepath,
        display_filter=args.display_filter,
    )
    logger.info(f"Loading capture from {args.filepath}")
    capture.load_packets()

    # Now we go through each packet and send it to the server using scapy
    for packet in capture:
        # Send packet to server
        # And collect response
        resp = send_and_receive(packet) # This already logs errors if no response
        
        # We also need to check the response to see if it makes sense for the query
        if resp:
            # Basic validation: check if response has Modbus layer
            if resp.haslayer("Modbus"):
                logger.info(f"Valid Modbus response for frame {getattr(packet, 'number', 'unknown')}")
            else:
                logger.warning(f"Invalid response for frame {getattr(packet, 'number', 'unknown')}: No Modbus layer")
            
            # More significant validation will probably be needed based on function codes, etc.
            ok = validate_response(packet, resp)
            if not ok:
                logger.warning(f"Response validation failed for frame {getattr(packet, 'number', 'unknown')}")

    if args.run_type == "Partial":
        exit(0)

    dfa = pcap_to_dataframe(REAL_PCAP_PATH, args.display_filter)  # Real packets
    dfb = pcap_to_dataframe(FAKE_PCAP_PATH, args.display_filter)  # Synthetic packets

    df = merge_dataframes(dfa, dfb, fake=1)  # Merge, label, and shuffle

    X = df.drop(columns=['label'])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1) # Can change split/state as needed

    X_train_scaled, X_test_scaled = normalize_dataframe(X_train, X_test)
    X_train_pca, X_test_pca = PCA_reduction(X_train_scaled, X_test_scaled, n_components=0.95)

    print(f'Original number of features: {X.shape[1]}')
    print(f'Number of features after PCA: {X_train_pca.shape[1]}') # Validate that PCA reduced dimensions, if it doesn't we can tweak or remove

    # SVM Classifier
    svm = train_svm(X_train_pca, y_train, kernel='linear')

    # Evaluation
    y_pred = svm.predict(X_test_pca)
    accuracy = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print(f'Accuracy: {accuracy:.4f}') # If accuracy is ~50% that means our model cannot distinguish between synthetic and real packets
    print('Confusion Matrix:\n', cm)
    print('Classification Report:\n', classification_report(y_test, y_pred))

if __name__ == "__main__":
    main()