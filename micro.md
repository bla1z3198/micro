# micro — secure super-speed tunnel over UDP

![Status](https://img.shields.io/badge/Status-Pre--Release%20%2F%20WIP-orange?style=flat-square)
![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat-square&logo=go)
![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=flat-square&logo=linux)
![Race Detector](https://img.shields.io/badge/Race%20Detector-Passing-success?style=flat-square)

> **Early Development Notice:** This repository currently holds an active, raw development build of **Micro**. APIs, packet header layouts, and internal pipeline structures are changing rapidly as we finalize the pre-release architecture.

**Micro** is an experimental, low-latency Layer 3 UDP tunneling engine written in Go, designed to push hundreds of Mbps across virtual TUN interfaces with zero heap allocations on the hot path.

---

### Current State (Working in Dev)

- [x] **Multi-Queue Ingestion:** Concurrent UDP workers utilizing Linux `SO_REUSEPORT` (`2 MB` socket buffers per descriptor).
- [x] **Zero-Allocation Memory Pools:** Pre-allocated `RXPool` and `TXPool` byte rings.
- [x] **Lock-Free Routing:** Thread-safe NAT and client session lookups via `sync.Map`.
- [x] **Concurrency Verified:** Zero data races under `go run -race`.
- [ ] **In Progress:** Stateless per-flow packet reordering (`collector` refactor).
- [ ] **In Progress:** Configuration cleanup & CLI flags for pre-release v0.1.0.

---
