# detect-ethereum-nmap
Nmap script for detecting jsonrpc etherum nodes and retriving the ChainID.

## Installation
```bash
wget -O /usr/share/nmap/scripts/http-eth.nse https://raw.githubusercontent.com/dzmitry-savitski/detect-ethereum-nmap/main/http-eth.nse
nmap --script-updatedb
```

## Running
```bash
nmap --script http-eth -p 443 bsc-dataseed.binance.org
```

Result:
```
PORT    STATE SERVICE
443/tcp open  https
|_http-eth: ChainID 56 detected
```

Mass scan:
```bash
nmap -v --script http-eth -p 443,8545 -Pn -n -oA results -iL hosts.txt
```
