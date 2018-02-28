-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local S      = require("syscall")
local bit    = require("syscall.bit")
local const  = require("syscall.linux.constants")
local ffi    = require("ffi")
local c, t   = S.c, S.types.t

local lib    = require("core.lib")
local ipv4   = require("lib.protocol.ipv4")
local ctable = require('lib.ctable')



local function to_ipv4_u32(ip)
    assert(type(ip) == "string")
    ip = ipv4:pton(ip)
    print(type(ip))
    print(ip)
    return ip[3] * 2^24 + ip[2] * 2^16 + ip[1] * 2^8 + ip[0]
end

local function prefix2maskv4(prefix)
    return lib.htonl(bit.bnot(bit.lshift(1, (32 - prefix)) - 1));
end


local n_key_t = ffi.typeof([[
    struct {
        unsigned char family;
        int           ifindex;
        uint32_t      dst;
    }
]])

local r4_key_t = ffi.typeof([[
    struct {
        int           oif;
        uint32_t      net;
        uint32_t      mask;
    }
]])

local r4_value_t = ffi.typeof([[
    struct {
        int           port;
        uint32_t      gw;
    }
]])

NetlinkSyncer = {}

function NetlinkSyncer:new(conf)
	return setmetatable({
        sock=nil,
        port=conf.port,
        ifs={},
        ifs_indexmap={},
        neighs=ctable.new({
            key_type = n_key_t,
            value_type = t.macaddr,
        }),
        routes4=ctable.new({
            key_type = r4_key_t,
            value_type = r4_value_t,
        }),
        -- routes6=ctable.new(r6_params),
        fastpath={},
    }, {__index=NetlinkSyncer})
end

function NetlinkSyncer:route_for(family, ip)
    -- FIXME(sileht): This is far from been optimal we browse the whole table on each packet
    -- We should use snabb.lib.ctable but how to share the table between worker ?
    if self.fastpath[ip] == nil then
        local bestmatch = nil
        local bestmask = -1
        if family == c.AF.INET then
            for entry in self.routes4:iterate() do
                if entry.key.mask > bestmask then
                    -- print("PREFIX: " .. entry.key.mask .. " > " .. bestmask)
                    local ip_net = bit.band(ip, entry.key.mask)
                    -- print("NET: " .. entry.key.net .. " == " .. ip_net)
                    if entry.key.net == ip_net then
                        -- print("GW: " .. entry.value.gw)
                        bestmatch = {
                            gw=entry.value.gw,
                            port=entry.value.port,
                            oif=entry.key.oif,
                            mac=nil,
                        }
                        bestmask = entry.key.mask
                    end
                end
            end
        end

        if bestmatch then
            local key = ffi.new(n_key_t)
            key.family = family
            key.ifindex = bestmatch.oif
            if bestmatch.gw ~= 0 then
                key.dst = bestmatch.gw
            else
                key.dst = ip
            end
            local ptr = self.neighs:lookup_ptr(key)
            if ptr then
                bestmatch.mac = ptr.value
                self.fastpath[ip] = bestmatch
            else
                -- We don't have neighbord yet, pass to the kernel it will do
                -- arp request and then we will bypass it
            end
        end
    end
    return self.fastpath[ip]
end

function NetlinkSyncer:get_if_mac(name)
    for i, interface in ipairs(self.ifs) do
        if interface.name == name then
            return interface.macaddr
        end
    end
end

function NetlinkSyncer:debug(msg)
    print("Port" .. self.port .. ": " .. msg)
end

function NetlinkSyncer:get_route4_key(r)
    local net = 0
    local mask = prefix2maskv4(r.dst_len)
    if r.dst then
        net = bit.band(r.dst.s_addr, mask)
        -- net = bit.band(r.dst.s6_addr, r.mask)
    end
    local key = ffi.new(r4_key_t)
    key.oif = r.oif
    key.net = net
    key.mask = mask
    return key
end

function NetlinkSyncer:add_route(r, iface)
    -- FIXME(sileht): IPV6
    if r.family == c.AF.INET6 then
        return
    end
    local value = ffi.new(r4_value_t)
    value.port = tonumber(string.sub(iface, 7))
    value.gw = r.gw.s_addr
    self.routes4:add(self:get_route4_key(r), value, true)
    -- self:debug("route " .. tostring(r) .. " added.")
end

function NetlinkSyncer:del_route(r)
    self.routes4:remove(self:get_route4_key(r), true)
    -- self:debug("route " .. key .. " deleted")
end

function NetlinkSyncer:get_neigh_key(n)
    local key = ffi.new(n_key_t)
    key.family = n.family
    key.dst = n.dst.s_addr
    key.ifindex = n.ifindex
    return key
end

function NetlinkSyncer:add_neigh(n)
    -- FIXME(sileht): When we received a ipv6 neighbor n.dst is a boolean set to false, WTF?
    if n.family == c.AF.INET6 then
        return
    end
    if n.dst == nil or n.lladdr == nil then
        return
    end
    self.neighs:add(self:get_neigh_key(n), n.lladdr, true)
    -- self:debug("neighbor '" .. tostring(n) .. "' added")
end

function NetlinkSyncer:del_neigh(n)
    if n.dst == nil then
        return
    end
    self.neighs:remove(self:get_neigh_key(key), true)
    -- self:debug("neighbor '" .. tostring(n) .. "' deleted")
end

function NetlinkSyncer:preload()
    local ifs, err = S.nl.getlink()
    if not ifs then
        -- self:debug("fail to retrieve links")
        return
    end

    self.ifs = ifs

    for i, v in pairs(self.ifs) do
      v.inet, v.inet6 = {}, {}
      self.ifs_indexmap[v.index] = i
    end

    for i, n in ipairs(S.nl.getneigh(nil, {})) do
        local iface = self.ifs[self.ifs_indexmap[n.ifindex]].name
        if string.sub(iface, 0, 6) == "router" then
            self:add_neigh(n)
        end
    end
    -- self:debug("Neighbords loaded.")

    for i, r in ipairs(S.nl.routes("inet")) do
        -- Take only route of our tap interfaces routerX 
        if string.sub(r.output, 0, 6) == "router" then
            self:add_route(r, r.output)
        end
    end
    -- self:debug("Routes v4 loaded.")
end

function NetlinkSyncer:sync()
    if self.sock == nil then
        self:preload()
        local k = t.sockaddr_nl()
        self.sock = S.nl.socket("route", {nl_family=c.AF.NETLINK, nl_pig = S.getpid(), nl_groups=-1})
        self.sock:nonblock()
    end
    -- self:debug("reading last netlink events")
    local msg, err = S.nl.read(self.sock, nil, 65535, false)
    if not msg then
        if err.errno ~= const.E.AGAIN then
            -- self:debug("error reading netlink events: " .. tostring(err))
            self.sock:close()
            self.sock = nil
        else
            -- self:debug("Got 0 messages")
        end
        return
    else
        -- self:debug("Got " .. #msg .. " messages")
    end
    for i, obj in ipairs(msg) do
        -- NOTE(sileht): 'obj' here is the raw nlmsg and not the lua object, so we don't have
        -- helper for some attributes like 'output', ...
        
        -- -- self:debug(obj.op .. ": " .. tostring(obj))
        if obj.nl == c.RTM.NEWLINK then
            self.ifs_indexmap[obj.index] = #self.ifs
            self.ifs[#self.ifs] = obj
        elseif obj.nl == c.RTM.DELLINK then
            self.ifs[self.ifs_indexmap[obj.index]] = nil
            self.ifs_indexmap[obj.index] = nil
        elseif obj.nl == c.RTM.GETLINK then
            self.ifs[self.ifs_indexmap[obj.index]] = obj
        elseif obj.nl == c.RTM.NEWNEIGH or obj.nl == c.RTM.DELNEIGH or obj.nl == c.RTM.GETNEIGH then
            iface = self.ifs[self.ifs_indexmap[obj.ifindex]].name
            if string.sub(iface, 0, 6) == "router" then
                if obj.nl == c.RTM.NEWNEIGH then
                    self:add_neigh(obj)
                elseif obj.nl == c.RTM.GETNEIGH then
                    self:del_neigh(obj)
                    self:add_neigh(obj)
                elseif obj.nl == c.RTM.DELNEIGH then
                    self:del_neigh(obj)
                end
            end
        elseif obj.nl == c.RTM.NEWROUTE or obj.nl == c.RTM.DELROUTE or obj.nl == c.RTM.GETROUTE then
            local iface = ifs[ifs_indexmap[obj.oif]].name
            if string.sub(iface, 0, 6) == "router" then
                if obj.nl == c.RTM.NEWROUTE then
                    add_route(shared, obj, iface)
                elseif obj.nl == c.RTM.DELROUTE then
                    del_route(shared, obj)
                elseif obj.nl == c.RTM.GETROUTE then
                    del_route(shared, obj)
                    add_route(shared, obj, iface)
                end
            end
        end
    end
end
