# scada-generator

This repository contains:

- Network traffic fingerprinting (Universal and SEL over Modbus)
- Network traffic generation with a custom ML model

Run modbus server with:

```sh
python3 server/server_async.py --port 8080
```

## Datasets

### Modbus

- https://github.com/antoine-lemay/Modbus_dataset

  - https://github.com/antoine-lemay/Modbus_dataset/blob/master/Modbus_polling_only_6RTU(2).pcap
  - https://github.com/antoine-lemay/Modbus_dataset/blob/master/channel_5d_3s.zip

- https://github.com/tjcruz-dei/ICS_PCAPS/releases/tag/MODBUSTCP%231

### MQTT

- https://www.kaggle.com/datasets/cnrieiit/mqttset
