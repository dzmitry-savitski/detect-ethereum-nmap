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
|_http-eth: 76.223.50.140:443 ChainID 56 detected
```

Mass scan:
```bash
nmap -v --script http-eth -Pn -n --min-rate 1000 --max-retries 0 --min-hostgroup 2048 --host-timeout 30s --script-timeout 30s --open -p 443,8545 -iL hosts.txt -oA results
```
