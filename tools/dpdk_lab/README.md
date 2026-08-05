# DPDK Lab Operations

The deployment reserves 4 GiB of 2 MiB hugepages and loads VFIO at boot. NICs
are deliberately not bound at boot, so an interface can be repurposed safely.

The default validation ports on both lab hosts are:

- `0000:03:00.0`: Intel I210, 1 GbE, Linux name `enp3s0`
- `0000:07:00.0`: Intel I226-V, 2.5 GbE, Linux name `enp7s0`

The management port `0000:06:00.0` / `enp6s0` is protected by the binding
script whenever it carries the default route.

```bash
sudo dpdk-bind-lab
sudo /opt/dpdk/bin/dpdk-devbind.py --status-dev net
sudo dpdk-unbind-lab
```

Pass explicit PCI addresses to select another pair, for example:

```bash
sudo dpdk-bind-lab 0000:03:00.0 0000:04:00.0
sudo dpdk-bind-lab 0000:07:00.0 0000:08:00.0
```

## Router test topology

For dperf, use two hosts and one DPDK port on each side of the DUT:

```text
10.66.0.57 test port -> DUT LAN -> DUT WAN -> 10.66.0.67 test port
```

Start the server on `10.66.0.67` before the client on `10.66.0.57`. The sample
configs use the RFC 2544 benchmarking ranges `198.18.0.0/24` on the LAN side and
`198.19.0.0/24` on the WAN side. Adjust both gateways to match the DUT. For NAT
tests, also adjust the server-side client range to the addresses emitted by the
DUT.

```bash
sudo dperf -c /opt/dpdk-lab/config/dperf-server-cps.conf
sudo dperf -c /opt/dpdk-lab/config/dperf-client-cps.conf
sudo dperf -c /opt/dpdk-lab/config/dperf-server-cc.conf
sudo dperf -c /opt/dpdk-lab/config/dperf-client-cc.conf
```

After dperf exits, release any persistent DPDK mapping files before starting a
different DPDK application. The cleanup command refuses to run while a known
DPDK process or open hugepage file exists.

```bash
sudo dpdk-hugepage-clean
```

For TRex, use two equal-speed ports on one host. Connect one port to DUT LAN and
the other to DUT WAN. Use `03:00.0` plus `04:00.0` for 1 GbE, or `07:00.0` plus
`08:00.0` for 2.5 GbE.

```bash
sudo dpdk-bind-lab 0000:03:00.0 0000:04:00.0
cd /opt/trex
sudo ./t-rex-64 -i --cfg /opt/dpdk-lab/config/trex-1g.yaml
```

Use dperf CPS for new connections per second and dperf CC for concurrent TCP
connections. Use TRex STL for packet forwarding rate and RFC 2544 NDR/PDR, and
TRex ASTF when a stateful traffic profile is required.
