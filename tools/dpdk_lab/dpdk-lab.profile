export RTE_SDK=/opt/dpdk
export PATH="/opt/dpdk/bin:/opt/trex:${PATH}"
export PKG_CONFIG_PATH="/opt/dpdk/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
export LD_LIBRARY_PATH="/opt/dpdk/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
