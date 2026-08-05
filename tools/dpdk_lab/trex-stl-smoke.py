#!/usr/bin/env python3
import time

from trex.stl.api import Ether, IP, Raw, STLClient, STLPktBuilder, STLStream, STLTXCont, UDP


def main():
    client = STLClient(server="127.0.0.1")
    try:
        client.connect()
        client.reset(ports=[0])

        packet = Ether() / IP(src="198.18.2.10", dst="198.18.2.3") / UDP(
            sport=12345, dport=80
        ) / Raw(load="x" * 18)
        stream = STLStream(packet=STLPktBuilder(pkt=packet), mode=STLTXCont(pps=10000))

        client.add_streams(stream, ports=[0])
        client.clear_stats(ports=[0])
        client.start(ports=[0], duration=10)
        client.wait_on_traffic(ports=[0])
        time.sleep(2)

        port = client.get_stats(ports=[0])[0]
        tx_packets = int(port["opackets"])
        rx_packets = int(port["ipackets"])
        tx_errors = int(port["oerrors"])
        rx_errors = int(port["ierrors"])
        loss = tx_packets - rx_packets

        print(f"tx_packets={tx_packets}")
        print(f"rx_packets={rx_packets}")
        print(f"loss_packets={loss}")
        print(f"tx_errors={tx_errors}")
        print(f"rx_errors={rx_errors}")

        if tx_packets == 0 or rx_packets < tx_packets * 0.99 or tx_errors or rx_errors:
            raise SystemExit(1)
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
