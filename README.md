# wsfuzz
Websocket proxy and fuzzer

# Usage

## Path Fuzzing
- `python3 wsfuzz.py path --ws "ws://ws.qreader.htb:5789/" --lhost 127.0.0.1 --lport 6060`
- `wfuzz -u http://127.0.0.1:6060/?param=FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 404`

## Param Fuzzing
- `python3 wsfuzz.py param --ws "ws://ws.qreader.htb:5789/endpoint" --lhost 127.0.0.1 --lport 6060`
- `wfuzz -u http://127.0.0.1:6060/?param=FUZZ -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt --hc 404`

## SQLMap Proxy
- `python3 wsfuzz.py sqlmap --ws "ws://ws.qreader.htb:5789/endpoint" --pname version --lhost 127.0.0.1 --lport 6060`
- `sqlmap -u http://127.0.0.1:6060/?param=test --level 5 --risk 3`
