# Metrics Guardian

## 1. Leverages COM & WMI for Deep System-Level Metrics

**Uses Microsoft’s COM (Component Object Model) technology to interface with WMI (Windows Management Instrumentation).**

* **Why it matters:** This provides native access to hardware and OS-level metrics (CPU load, disk usage, network stats) directly from the Windows kernel—the same method used by enterprise-grade monitoring systems.

* **Technical Strength:** Uses IWbemLocator and IEnumWbemClassObject COM interfaces for querying Win32 classes, ensuring accurate, real-time hardware information.

* **Result:** Not dependent on third-party monitoring tools; uses Windows’ official, low-level APIs for reliability.

---

## 2. High-Performance Networking Using Boost.Asio (TCP/IP)

**Implements raw TCP socket communication using Boost.Asio, one of the most powerful and portable C++ networking libraries.**

* **Why it matters:** Boost.Asio allows direct control over TCP communication without abstraction overhead, ensuring low-latency, high-throughput transmission of monitoring data.

* **Technical Strength:** JSON payloads are serialized and streamed over synchronous socket connections, making it easy to integrate with existing network analysis pipelines or backend services.

* **Result:** The design is production-ready for secure LAN/WAN monitoring, extensible to cloud infrastructure.

---

## 3. Multithreaded Architecture for Efficient Data Gathering

**Built using C++ Standard Library Threads (std::thread) for concurrent execution of resource collection.**

* **Why it matters:** Modern systems require asynchronous, parallel processing to gather multi-metric system data in real time without blocking or delays.

* **Technical Strength:** Separation of concerns—each resource (CPU, Disk, Network) is gathered independently and concurrently, optimizing response time and system utilization.

* **Result:** Low overhead, scalable, and extensible. Can easily add more resource monitors or parallelize further for distributed systems.

---

## Technologies Used:

* **COM + WMI** → Hardware & OS Information
* **Boost.Asio (TCP/IP)** → Network communication layer
* **nlohmann/json** → JSON serialization
* **C++17 STL** → Multithreading, memory management, efficient data structures
