
# PacketSniffer

PacketSniffer is a simple Python-based packet sniffing tool designed for network analysis and debugging. This tool captures and logs packets transmitted over a network interface, providing detailed information about the Ethernet, IP, TCP, UDP, and ICMP headers.

## Features

- Captures Ethernet frames, IP packets, and common protocols (TCP, UDP, ICMP).
- Logs packet data to timestamped files.
- Provides detailed header information for each captured packet.
- Simple and intuitive command-line interface.

## Prerequisites

- Python 3.x
- Root or administrator privileges (required to create raw sockets)

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/drewmayberry11/Network_Packet_Sniffer.git
    cd PacketSniffer
    ```

## Usage

1. Run the PacketSniffer:
    ```sh
    sudo python3 packet_sniffer.py
    ```

2. Enter the network interface you want to sniff on (e.g., `eth0`, `wlan0`):
    ```sh
    Enter interface: eth0
    ```

3. The sniffer will start capturing packets on the specified interface. Press `Ctrl+C` to stop the sniffer and save the captured packets to a log file.

### Example

```sh
$ sudo python3 packet_sniffer.py
Enter interface: eth0
Sniffing packets on eth0...

Ethernet Frame:
Destination MAC: XX:XX:XX:XX:XX:XX | Source MAC: XX:XX:XX:XX:XX:XX | Protocol: 2048
IP Header:
Version: 4 | IP Header Length: 20 | TTL: 64
Protocol: 6 | Source Address: 192.168.1.2 | Destination Address: 192.168.1.1
TCP Header:
Source Port: 12345 | Destination Port: 80
Sequence Number: 1234567890 | Acknowledgement: 1234567890
TCP Header Length: 20
Data:
    Hello World
```

## Directory Structure

```
PacketSniffer/
├── packet_sniffer.py     # Main packet sniffer script
├── requirements.txt      # List of Python dependencies
└── logs/                 # Directory to store packet logs
```

## Code Overview

### packet_sniffer.py

The main script that contains the `PacketSniffer` class responsible for:

- Creating a raw socket to capture packets.
- Parsing and displaying Ethernet, IP, TCP, UDP, and ICMP headers.
- Logging captured packets to timestamped files.
- Handling user interruption and saving logs upon exit.

### Logging Packets

Captured packets are saved in the `logs` directory with filenames based on the timestamp when the program was terminated.

### Parsing Headers

The script parses the following headers:

- **Ethernet Header**: MAC addresses and protocol type.
- **IP Header**: IP addresses, protocol, and other metadata.
- **TCP Header**: Ports, sequence numbers, and data.
- **UDP Header**: Ports, length, and checksum.
- **ICMP Header**: Type, code, and checksum.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Contact

For any questions or suggestions, please contact [your-email@example.com](mailto:your-email@example.com).

---

Happy Sniffing!
