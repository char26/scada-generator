# scada-generator

Coordinator: Diffusion model, determines the next packet to be sent.

Client: May have multiple, Modbus or MQTT client ready to send a packet from the coordinator.

Server: Not implemented by us (pymodbus server, etc), mostly used for verification and testing

```
python3 server/server_async.py --port 8080

python3 main.py
```

## Datasets

### Modbus

- https://github.com/antoine-lemay/Modbus_dataset

  - https://github.com/antoine-lemay/Modbus_dataset/blob/master/Modbus_polling_only_6RTU(2).pcap
  - https://github.com/antoine-lemay/Modbus_dataset/blob/master/channel_5d_3s.zip

- https://github.com/tjcruz-dei/ICS_PCAPS/releases/tag/MODBUSTCP%231

### MQTT

- https://www.kaggle.com/datasets/cnrieiit/mqttset
