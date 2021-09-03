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
-- |_http-eth: ChainID 56 detected
--
-- @xmloutput
-- <elem key="result">ChainID 56 detected</elem>
--
-- Version 0.1
-- Created 09/03/2021 - v0.1 - created by Dzmitry Savitski <dmitry.savitski@gmail.com>
--

author = "Dzmitry Savitski"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery"}

portrule = shortport.http

action = function( host, port )
  local output = stdnse.output_table()
  local data = '{"jsonrpc":"2.0","method":"net_version","params":[],"id":67}'
  local response = http.post(host, port, '/', {header = {["Content-Type"] = "application/json"}}, nil, data )
  if (response.status==200) and (response['body']:match('{"jsonrpc":"2.0","id":67,"result":"%d+"}')) then
    chain_id = response['body']:match('{"jsonrpc":"2.0","id":67,"result":"(%d+)"}')
    output.result=("ChainID %s detected"):format(chain_id)
    return output, output.result
  end
end
