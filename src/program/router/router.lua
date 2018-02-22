-- Use of this source code is governed by the Apache 2.0 license; see COPYING.

module(..., package.seeall)

local ffi    = require("ffi")

-- local now    = require("core.app").now
local worker = require("core.worker")
local timer  = require("core.timer")

local numa   = require("lib.numa")

local intel  = require("apps.intel_mp.intel_mp")
local tap    = require("apps.tap.tap")

local router_port    = require("program.router.router_port")
local netlink_syncer = require("program.router.netlink_syncer")

function process_port(main_device, port, devices)
    numa.bind_to_cpu(port)

    local nls = netlink_syncer.NetlinkSyncer:new{port=port}
    local s_freq = 10
    nls:sync()
    timer.activate(timer.new("netlink", function () nls:sync() end , timer.ns_per_tick * 1000 * s_freq, 'repeating'))

    -- NOTE(sileht): This table sucks as we can't make routing algo smart due
    -- to this thread-safe table. I will see later if I can find something better
    local c = config.new()
	config.app(c, "router", router_port.RouterPort, {port = port, nls=nls})
    config.app(c, "tap", tap.Tap, {name = "router" .. port})
    config.app(c, "main_nic", intel.Intel, {
        pciaddr = main_device,
    })
    config.link(c, "tap.output -> main_nic.input")
    config.link(c, "main_nic.output -> router.input")
    config.link(c, "router.nic_" .. port .. " -> main_nic.input")
    config.link(c, "router.tap -> tap.input")

    for i, device in ipairs(devices) do
        if device ~= main_device then
            config.app(c, "nic_" .. i, intel.Intel, {
                pciaddr = device,
                rxq = false,
                -- We have 16 queues max per nic, so we can scale to 16 nics without vmdk
                txq = port,
            })
            config.link(c, "router.nic_" .. i .. " -> nic_" .. i .. ".input")
        end
    end
    engine.configure(c)
    engine.busywait = false

    timer.activate(timer.new("report", function () engine.report() end, 1e9, 'repeating'))

    engine.main({
        measure_latency = true,
        no_report = false,
        report = {{showapps=true, showlinks=true}},
    })
end


function run(args)
    print("Router starting...")
	print("pci list:")
	table.foreach(args, function(k, v) print(k .. ": " .. tostring(v)) end)

    local nics_params = "{\"" .. table.concat(args, "\", \"") .. "\"}"
	for i, device in ipairs(args) do
        worker.start("port_" .. i, string.format([[
            require("program.router.router").process_port("%s", %d, %s)
        ]], device, i, nics_params))
    end

    print("Router started!")
    while true do
        for w, s in pairs(worker.status()) do
            print(("  worker %s: pid=%s alive=%s"):format(w, s.pid, s.alive))
        end
        ffi.C.usleep(60*1000*1000)
    end
end
