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

'''
I really need to break this file up into a notebook or a multi function module
but for now this will do.
'''
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

def main():
    parser = argparse.ArgumentParser(
        description="Validate Modbus packet classification using SVM."
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
        help="Display filter for pyshark capture",
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

if __name__ == "__main__":
    main()

'''
Ignore everything past this point for now.
'''

# Create default empty dataframe df
df = pd.DataFrame()
# Call injest, which returns a default dictionary of field names and their values
data_injest = injest.main(["--filepath", "path/to/pcap", "--display_filter", "modbus"]) # Replace with actual filepath and filter as needed

for name in data_injest.keys():
    # Make the key the name of the column and the values the values of that column, the values are in the form of a list
    df[name] = data_injest[name] # That's a list so hopefully it should just work

# Will need to merge this data with the sythetic data, and add the labels, but I can do that later
# Assuming there's a label column named 'label', which has a binary classification for the synthetic/real packets.

X = df.drop(columns=['label'])
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=1) # Can change split/state as needed

# Data normalization
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# PCA for dimensionality/noise reduction
pca = PCA(n_components=0.95)  # Retain 95% of variance
X_train_pca = pca.fit_transform(X_train_scaled)
X_test_pca = pca.transform(X_test_scaled)

print(f'Original number of features: {X.shape[1]}')
print(f'Number of features after PCA: {X_train_pca.shape[1]}') # Validate that PCA reduced dimensions, if it doesn't we can tweak or remove

# SVM Classifier
svm = SVC(kernel='linear', random_state=1) # Kernel can be changed as needed, same with random_state
svm.fit(X_train_pca, y_train)

# Evaluation
y_pred = svm.predict(X_test_pca)
accuracy = accuracy_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)

print(f'Accuracy: {accuracy:.4f}') # If accuracy is ~50% that means our model cannot distinguish between synthetic and real packets
print('Confusion Matrix:\n', cm)
print('Classification Report:\n', classification_report(y_test, y_pred))