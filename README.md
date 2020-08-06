# TLS-Malware-Detection-with-Machine-Learning

Repository containing code for cleaning of TLS flows extracted from Cisco Joy telemetry tool. Cleaned TLS flows are extracted and written to .csv file before machine learning classifiers 
are applied. Based on the research of Olivier Roques (https://github.com/ojroques/tls-malware-detection) and Cisco (https://blogs.cisco.com/security/detecting-encrypted-malware-traffic-without-decryption)

### Usage
Cisco joy is utilized to extract network telemetry data from .pcap files. Run cisco joy using the parameters specified below:

```
bin/joy tls=1 bidir=1 dist=1 num_pkts=50 zeros=0 retrans=0 entropy=1 $file | gunzip | ./sleuth --where "tls=*" > filename.json
```

.json files are run through tls_flow_filter.py to produce .csv files

### Websites to obtain .pcaps for training and validation
Link to magestic millions csv file:
https://majestic.com/reports/majestic-million

Link to websites which contain large .pcap files:
https://www.netresec.com/?page=PcapFiles
