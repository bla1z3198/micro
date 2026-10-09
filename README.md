# micro — secure high-speed tunnel over UDP

![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?style=flat-square&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux)
![iperf3 Test](https://img.shields.io/badge/iperf%20Test-500%20Mbps%20Ready-success?style=flat-square)

# What is micro?

**micro** is a simple, L3 UDP tunneling engine written in Go, micro uses TUN interfaces for read/write L3 traffic.

# Simple start

Create a valid configs for server and client. Default configs already created and placed if cfg folders. Firstly start a server, then a client (at the now version client and server can has connectivity problem - just restart server and client).

```
chmod +x server
sudo ./server
```

```
chmod +x client
sudo ./client
```

# iperf3 test (500 Mbps)

## Client side

![iperf3 500 Mbps Zero-Loss Test|553](test/client.png)

## Server side

![iperf3 500 Mbps Zero-Loss Test|551](test/server.png)