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
local function get_ipv4_src_ptr(ptr)
   return ptr + constants.o_ipv4_src_addr
end
local function get_ipv4_src_address(ptr)
   return lwutil.rd32(get_ipv4_src_ptr(ptr))
end
local function get_ipv6_dst_address(ptr)
   return ptr + constants.o_ipv6_dst_addr
end
local function get_ipv6_next_header(ptr)
   return ptr[constants.o_ipv6_next_header]
end
local function get_ether_dhost_ptr (pkt)
   return pkt.data
end

local function ether_equals (dst, src)
   return C.memcmp(dst, src, 6) == 0
end
local function get_ipv6_src_address(ptr)
   return ptr + constants.o_ipv6_src_addr
end

local function copy_ether(dst, src)
end

local function to_ipv4_string(uint32)
   return ("%i.%i.%i.%i"):format(
      bit.band(uint32, 0xff),
      bit.rshift(bit.band(uint32, 0xff00), 8),
      bit.rshift(bit.band(uint32, 0xff0000), 16),
      bit.rshift(uint32, 24))
end

local function debug(msg)
    io.write(msg)
end

RouterPort = {}

function RouterPort:new(conf)
	return setmetatable(conf, {__index=RouterPort})
end

function RouterPort:output_for(pkt)
	local ip_dest = nil
    local route = nil
	local dst_mac = nil
    local hdr = get_ethernet_payload(pkt)
    local ethertype = get_ethertype(pkt)
	if ethertype == constants.n_ethertype_ipv4 then
		ip = get_ipv4_dst_address(hdr)
        -- debug(" dest: " .. to_ipv4_string(ip))
        route = self.nls:route_for(c.AF.INET, ip)
	elseif ethertype == constants.n_ethertype_ipv6 then
		ip = get_ipv6_dst_address(hdr)
        route = self.nls:route_for(c.AF.INET6, ip)
    end

    -- NOTE(sileht): output selection logic
    -- * no bypass route -> kernel space
    -- * route for the router interface where the pkt come in -> kernel space
    -- * route for another router interface -> kernel bypass
	if route == nil then
        -- debug(" to kernel")
		return self.output.tap, nil, nil
	else 
        local src_mac = self.nls:get_if_mac("router" .. route.port)
        local output =  self.output["nic_" .. route.port]
        if route.port == self.port or output == nil or src_mac == nil then
            -- debug(" to kernel")
            return self.output.tap, nil, nil
        else
            -- Yah! kernel bypass
            -- debug(" bypass to nic_" .. route.port)
            return self.output["nic_" .. route.port], route.mac, src_mac
        end
	end
	
end

function RouterPort:push()
	local i = self.input.input
	for _ = 1, link.nreadable(i) do
        -- debug("Port" .. self.port .. ":")
		local pkt = link.front(i)
		local output, dst_mac, src_mac = self:output_for(pkt)
		if not link.full(output) then
            -- Override the mac addresses in the packet
			if dst_mac then
                ffi.copy(pkt.data, dst_mac.mac_addr, 6)
            end
			if src_mac then
                ffi.copy(pkt.data + 6, src_mac, 6)
			end
			link.transmit(output, pkt)
			link.receive(i) -- pop it from the ring
		else
			-- That sucks an output is full so we can't read the ring 
            -- of this input even if other pkts are for another output
            -- Let's try the next input, we may be luckier
            break
		end
        -- debug("\n")
	end
end


