# scada-generator

Coordinator: Diffusion model, determines the next packet to be sent.

Client: May have multiple, Modbus or MQTT client ready to send a packet from the coordinator.

Server: Not implemented by us (pymodbus server, etc), mostly used for verification and testing

```
python3 server/server_async.py --port 8080

python3 main.py
```
