local http = require "http"
local io = require "io"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects ethereum node and receives the chain id.
]]

---
-- @usage
-- nmap -p 443 <ip> --script http-eth
--
-- @output
-- PORT     STATE SERVICE
-- PORT   STATE SERVICE
-- 443/tcp open  https
-- |_http-eth: 76.223.50.140:443 ChainID 56 detected
--
-- @xmloutput
-- <elem key="result">76.223.50.140:443 ChainID 56 detected</elem>
--
-- Version 0.1
-- Updated 09/05/2021 - v0.1 - host and port information added to the output
-- Created 09/03/2021 - v0.1 - created by Dzmitry Savitski <dmitry.savitski@gmail.com>
--

author = "Dzmitry Savitski"
license = "MIT License"
categories = {"discovery"}

portrule = shortport.http

action = function( host, port )
  local output = stdnse.output_table()
  local data = '{"jsonrpc":"2.0","method":"net_version","params":[],"id":67}'
  local response = http.post(host, port, '/', {header = {["Content-Type"] = "application/json"}}, nil, data )
  if (response.status==200) and (response['body']:match('{"jsonrpc":"2.0","id":67,"result":"%d+"}')) then
    chain_id = response['body']:match('{"jsonrpc":"2.0","id":67,"result":"(%d+)"}')
    output.result=("%s:%s ChainID %s detected"):format(host.ip, port.number, chain_id)
    return output, output.result
  end
end
