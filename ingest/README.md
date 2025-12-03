# Data Ingest

## Usage

The example below pulls packets from the specified pcap file, filters for Modbus packets, then creates a matrix based on the Modbus fields.

```sh
cd ingest
python3 ingest.py --filename <filename> --display_filter modbus
```

## Datasets

### Modbus

- https://github.com/antoine-lemay/Modbus_dataset

  - https://github.com/antoine-lemay/Modbus_dataset/blob/master/Modbus_polling_only_6RTU(2).pcap
  - https://github.com/antoine-lemay/Modbus_dataset/blob/master/channel_5d_3s.zip

- https://github.com/tjcruz-dei/ICS_PCAPS/releases/tag/MODBUSTCP%231

### MQTT

- https://www.kaggle.com/datasets/cnrieiit/mqttset
