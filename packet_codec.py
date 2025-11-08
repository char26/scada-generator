# This module provides functionality for encoding and decoding network packets
# Specifically, Modbus and MQTT packets are handled here.

# No imports for now cuz idk what I need
# Ideally we'll be able to use the git repos we found for the actual packet handling and this will just be a wrapper around those 

# I'm going to just use a general use request function for now that performs logic to determine what path to take
def request(packet_data, protocol_type, request_type):
    if protocol_type == 'modbus':
        if request_type == 'encode':
            return encode_modbus(packet_data)
        elif request_type == 'decode':
            return decode_modbus(packet_data)
    elif protocol_type == 'mqtt':
        if request_type == 'encode':
            return encode_mqtt(packet_data)
        elif request_type == 'decode':
            return decode_mqtt(packet_data)
    else:
        raise ValueError("Unsupported protocol type")
    
def encode_modbus(packet_data):
    pass

def decode_modbus(packet_data):
    pass

def encode_mqtt(packet_data):
    pass

def decode_mqtt(packet_data):
    pass