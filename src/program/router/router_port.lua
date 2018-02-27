-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local S      = require("syscall")
local bit    = require("syscall.bit")
local ffi    = require("ffi")
local C      = ffi.C
local c, t   = S.c, S.types.t

local link   = require("core.link")

local ethernet = require("lib.protocol.ethernet")

local constants = require("apps.lwaftr.constants")
local lwutil = require("apps.lwaftr.lwutil")


local function get_ethertype(pkt)
   return lwutil.rd16(pkt.data + (constants.ethernet_header_size - 2))
end
local function get_ethernet_payload(pkt)
   return pkt.data + constants.ethernet_header_size
end
local function get_ipv4_dst_address(ptr)
   return lwutil.rd32(ptr + constants.o_ipv4_dst_addr)
end
local function get_ipv6_dst_address(ptr)
   return ptr + constants.o_ipv6_dst_addr
end

RouterPort = {}

function RouterPort:new(conf)
	return setmetatable(conf, {__index=RouterPort})
end

function RouterPort:push()
	local i = self.input.input
	for _ = 1, link.nreadable(i) do
		local pkt = link.receive(i)
        local output = nil

        local route = nil
        local hdr = get_ethernet_payload(pkt)
        local ethertype = get_ethertype(pkt)
        if ethertype == constants.n_ethertype_ipv4 then
            route = self.nls:route_for(c.AF.INET, get_ipv4_dst_address(hdr))
        elseif ethertype == constants.n_ethertype_ipv6 then
            route = self.nls:route_for(c.AF.INET6, get_ipv6_dst_address(hdr))
        end

        -- NOTE(sileht): output selection logic
        -- * no bypass route (example: arp, ...) -> kernel space
        -- * route for the router interface where the pkt come in -> kernel space
        -- * route for another router interface -> kernel bypass
        if route ~= nil then
            local src_mac = self.nls:get_if_mac("router" .. route.port)
            if route.port ~= self.port and self.output["nic_" .. route.port] ~= nil and src_mac ~= nil then
                -- Yah! kernel bypass
                ffi.copy(pkt.data, route.mac.mac_addr, 6)
                ffi.copy(pkt.data + 6, src_mac, 6)
                output =  self.output["nic_" .. route.port]
            end
        end
        link.transmit(output or self.output.tap, pkt)
	end
end


