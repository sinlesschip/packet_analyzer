## Simple packet analyzer

just for fun

- requires libpcap

compile with `gcc analyzer.c -o analyzer -lpcap`

- you can capture to pcap file with `-f filename.pcap`
- you can set how many packet to capture with `-i`

#### Example uses
`sudo analyzer` - default infinite capture and print to stdout, no file to save
`sudo analyzer -f capture.pcap -p 100` - all arguments specified