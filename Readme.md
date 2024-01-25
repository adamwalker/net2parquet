# Net2Parquet

Extracts network headers from pcap files and dumps them in the Parquet file format for later analysis. 

Supports xz compression, and processes multiple pcap files in parallel.

Extracts Ethernet, VLAN, IP, UDP and TCP headers. 

Usage:

```
$ net2parquet input.pcap.xz -o parquet-out-dir
```
