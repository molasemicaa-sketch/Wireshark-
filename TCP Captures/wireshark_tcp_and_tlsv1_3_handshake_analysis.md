# Wireshark Packet Capture Analysis: TCP 3-Way Handshake & TLSv1.3 Connection

This document provides a line-by-line breakdown of a network capture showing a secure HTTPS connection (`TLSv1.3`) being established between a local client (`192.168.254.122`) and a Pinterest image server (`146.75.20.84` / `s.pinimg.com`).

---

## 📋 Connection Overview

* **Client IP:** `192.168.254.122` (Ephemeral Port: `54486`)
* **Server IP:** `146.75.20.84` (HTTPS Port: `443`)
* **Target Domain (SNI):** `s.pinimg.com`
* **Protocols:** TCP, TLSv1.3

---

## 🔍 Line-by-Line Packet Breakdown

### Phase 1: TCP 3-Way Handshake
Before any encrypted data can be exchanged, the client and server must establish a reliable TCP connection.

* **Packet 1 (`0.000000000s`) — TCP `[SYN]`**
  * **Direction:** Client (`54486`) $\rightarrow$ Server (`443`)
  * **Process:** The client initiates the connection by sending a Synchronize (`SYN`) packet (`Seq=0`). It advertises its Maximum Segment Size (`MSS=1460` bytes), Window Scale (`WS=256`), and Selective Acknowledgment support (`SACK_PERM`).
* **Packet 2 (`0.021632500s`) — TCP `[SYN, ACK]`**
  * **Direction:** Server (`443`) $\rightarrow$ Client (`54486`)
  * **Process:** Roughly 21.6 ms later, the server responds, acknowledging the client's request (`Ack=1`) and sending its own synchronization request (`Seq=0`) along with its network capabilities (`MSS=1412`, `WS=512`).
* **Packet 3 (`0.021702100s`) — TCP `[ACK]`**
  * **Direction:** Client (`54486`) $\rightarrow$ Server (`443`)
  * **Process:** The client acknowledges the server's `SYN` (`Ack=1`), completing the **TCP 3-Way Handshake**. The transport layer is now open.

---

### Phase 2: TLSv1.3 Handshake & Certificate Exchange
With TCP established, the client and server immediately negotiate encryption parameters using TLSv1.3.

* **Packet 4 & 5 (`0.022200300s`) — TLSv1.3 `Client Hello`**
  * **Direction:** Client (`54486`) $\rightarrow$ Server (`443`)
  * **Process:** The client initiates the TLS handshake. Because the `Client Hello` message is larger than a single standard segment (totaling 1,984 bytes across the two frames), Packet 4 carries the first 1,412 bytes of payload (`[TCP PDU reassembled in 5]`), and Packet 5 completes the message. It includes the **Server Name Indication (`SNI=s.pinimg.com`)** so the server knows which SSL certificate to present, along with supported cipher suites and key shares.
* **Packet 6 (`0.045928500s`) — TCP `[ACK]`**
  * **Direction:** Server (`443`) $\rightarrow$ Client (`54486`)
  * **Process:** The server acknowledges receipt of all 1,984 bytes (`Ack=1985`) of the `Client Hello`.
* **Packet 7 (`0.045933100s`) — TLSv1.3 `Server Hello, Change Cipher Spec, Application Data`**
  * **Direction:** Server (`443`) $\rightarrow$ Client (`54486`)
  * **Process:** The server selects the cipher suite (`Server Hello`), sends a compatibility `Change Cipher Spec` record, and immediately begins sending encrypted handshake messages (`Application Data`), such as its encrypted extensions and SSL/TLS certificate.
* **Packets 8, 9, 10, & 11 (`0.047312000s` – `0.047315200s`) — Server Certificate & Encrypted Handshake Data**
  * **Direction:** Server (`443`) $\rightarrow$ Client (`54486`)
  * **Process:** Because the server's certificate chain exceeds the `MSS` of 1,412 bytes, the server fragments the TLS record across multiple TCP segments:
    * **Packets 8–10:** Carry consecutive 1,412-byte chunks of encrypted handshake data (`Seq=1413`, `Seq=2825`, `Seq=4237`), flagged as `[TCP PDU reassembled in 11]`.
    * **Packet 11:** Delivers the final piece of the flight, allowing Wireshark to reassemble and display the combined `Application Data` records (Encrypted Extensions, Certificate, Certificate Verify, and Server Finished).
* **Packet 12 (`0.047347100s`) — TCP `[ACK]`**
  * **Direction:** Client (`54486`) $\rightarrow$ Server (`443`)
  * **Process:** The client confirms receipt of the entire server handshake flight (`Ack=6879`).
* **Packet 13 (`0.048998400s`) — TLSv1.3 `Change Cipher Spec, Application Data`**
  * **Direction:** Client (`54486`) $\rightarrow$ Server (`443`)
  * **Process:** After verifying the server's certificate, the client sends its own `Change Cipher Spec` and encrypted `Client Finished` message (`Application Data`), officially completing the **TLSv1.3 Handshake**.

---

### Phase 3: Encrypted Application Data Exchange (HTTPS)
Now that both sides share symmetric session keys, actual HTTP requests and responses are transmitted securely inside TLS `Application Data` wrappers.

* **Packets 14, 15, & 16 (`0.049123300s` – `0.049252500s`) — Client HTTP Request**
  * **Direction:** Client (`54486`) $\rightarrow$ Server (`443`)
  * **Process:** The client transmits its encrypted HTTP request(s) (e.g., `GET` requests for assets on `s.pinimg.com`) split across three TLS `Application Data` packets (Lengths: `146`, `534`, and `144` bytes).
* **Packets 17 & 18 (`0.069972800s` – `0.069973500s`) — TCP `[ACK]`**
  * **Direction:** Server (`443`) $\rightarrow$ Client (`54486`)
  * **Process:** The server acknowledges the incoming client data in two increments (`Ack=2049` and `Ack=2141`).
* **Packet 19 (`0.070022800s`) — TLSv1.3 `Application Data`**
  * **Direction:** Server (`443`) $\rightarrow$ Client (`54486`)
  * **Process:** The server sends a `125`-byte encrypted payload (likely a TLSv1.3 `NewSessionTicket` for future session resumption).
* **Packet 20 (`0.070147800s`) — TLSv1.3 `Application Data`**
  * **Direction:** Client (`54486`) $\rightarrow$ Server (`443`)
  * **Process:** The client sends an additional `85`-byte encrypted message to the server.
* **Packets 21 & 22 (`0.073084400s` – `0.073084700s`) — TCP `[ACK]`**
  * **Direction:** Server (`443`) $\rightarrow$ Client (`54486`)
  * **Process:** The server acknowledges the latest client bytes (`Ack=2621` and `Ack=2711`).
* **Packets 23 & 24 (`0.073087100s` – `0.073087700s`) — Server HTTP Response**
  * **Direction:** Server (`443`) $\rightarrow$ Client (`54486`)
  * **Process:** The server responds with the requested encrypted application data (`458` bytes and `157` bytes).
* **Packet 25 (`0.073126400s`) — TCP `[ACK]`**
  * **Direction:** Client (`54486`) $\rightarrow$ Server (`443`)
  * **Process:** The client acknowledges receiving all server data up to byte `7457` (`Ack=7457`).
* **Packet 26 (`0.091313300s`) — TCP `[ACK]`**
  * **Direction:** Server (`443`) $\rightarrow$ Client (`54486`)
  * **Process:** Final visible acknowledgment from the server confirming receipt of all client data up to sequence `2742` (`Ack=2742`).

---

## 💡 Key Takeaways
1. **Zero Round-Trip Overhead on Handshake:** Unlike older TLS versions (TLS 1.2) that require two full round trips after TCP connects, **TLSv1.3** completes its handshake in a single round trip (`1-RTT`), allowing encrypted HTTP data to flow in just **49 milliseconds** from the initial `SYN`.
2. **TCP Segmentation & Reassembly:** Large TLS records (such as the `Client Hello` and server certificate chain) are automatically split at the TCP layer based on the negotiated `MSS` (`1412` bytes) and reassembled by the receiving stack.