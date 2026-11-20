-- GhostMesh Wireshark dissector (Lua). Opens .pcap files written by security/gm_pcap.py.
--
-- Install: copy this file into Wireshark's personal Lua plugins folder
--   Windows: %APPDATA%\Wireshark\plugins\        macOS/Linux: ~/.local/lib/wireshark/plugins/
-- or run once with:  wireshark -X lua_script:security/ghostmesh.lua capture.pcap
--
-- Packets use link type DLT_USER0 (147): a 16-byte capture header (watchtower metadata, not on the
-- air) followed by the 240-byte frame (PROTOCOL.md §9.4 offsets). Only cleartext is decoded: no
-- keys are loaded, so DATA bodies stay ciphertext. That is the point of the demo.
--
-- Display filters: ghostmesh.type == 4, ghostmesh.cap.node == "X", ghostmesh.src_pseudo == 0x23c91361,
-- ghostmesh.flags.sos, !ghostmesh.cap.link_ok, ghostmesh.ctrl.subtype == 2, ...

local gm = Proto("ghostmesh", "GhostMesh")

local TYPES   = { [1] = "DATA", [2] = "HELLO", [3] = "CTRL", [4] = "KEYS" }
local SUBTYPE = { [1] = "TIME", [2] = "BLOCK" }
local REASON  = { [0] = "manual/other", [1] = "flood", [2] = "replay", [3] = "spoof", [4] = "routing" }
local MODE    = { [0] = "normal", [1] = "resync" }

local F = {
  -- capture header (watchtower metadata)
  cap        = ProtoField.none("ghostmesh.cap", "Capture info (watchtower metadata, not on air)"),
  cap_magic  = ProtoField.string("ghostmesh.cap.magic", "Magic"),
  cap_ver    = ProtoField.uint8("ghostmesh.cap.version", "Version"),
  cap_len    = ProtoField.uint8("ghostmesh.cap.hdr_len", "Header length"),
  cap_flags  = ProtoField.uint8("ghostmesh.cap.flags", "Flags", base.HEX),
  cap_link   = ProtoField.bool("ghostmesh.cap.link_ok", "link_tag valid (checked by watchtower)", 8, nil, 0x01),
  cap_id     = ProtoField.bool("ghostmesh.cap.id_ok", "MAC matches pseudonym (id_ok)", 8, nil, 0x02),
  cap_hasnode= ProtoField.bool("ghostmesh.cap.has_node", "Node field present", 8, nil, 0x04),
  cap_hasrx  = ProtoField.bool("ghostmesh.cap.has_rx_us", "rx_us present", 8, nil, 0x08),
  cap_rssi   = ProtoField.int8("ghostmesh.cap.rssi", "RSSI (dBm)"),
  cap_node   = ProtoField.string("ghostmesh.cap.node", "Node (watchtower's identity lookup)"),
  cap_rate   = ProtoField.uint8("ghostmesh.cap.rate", "Rate"),
  cap_sig    = ProtoField.uint8("ghostmesh.cap.sig_mode", "sig_mode"),
  cap_mcs    = ProtoField.uint8("ghostmesh.cap.mcs", "MCS"),
  cap_rx     = ProtoField.uint32("ghostmesh.cap.rx_us", "Radio rx time (µs since boot)"),

  -- on-air frame
  frame      = ProtoField.none("ghostmesh.frame", "GhostMesh frame (240 bytes on air)"),
  type       = ProtoField.uint8("ghostmesh.type", "Type (ver_type)", base.DEC, TYPES),
  flags      = ProtoField.uint8("ghostmesh.flags", "Flags", base.HEX),
  sos        = ProtoField.bool("ghostmesh.flags.sos", "SOS", 8, nil, 0x01),
  flags_rsv  = ProtoField.uint8("ghostmesh.flags.reserved", "Reserved (must be 0)", base.HEX, nil, 0xFE),
  msg_id     = ProtoField.bytes("ghostmesh.msg_id", "msg_id"),
  ttl        = ProtoField.uint8("ghostmesh.ttl", "TTL"),
  hop        = ProtoField.uint8("ghostmesh.hop", "Hop count"),
  src        = ProtoField.uint32("ghostmesh.src_pseudo", "Transmitter pseudonym (src_pseudo)", base.HEX),
  next_hop   = ProtoField.uint32("ghostmesh.next_hop", "next_hop (0 = flood)", base.HEX),
  epoch      = ProtoField.uint16("ghostmesh.epoch", "Epoch"),
  link_tag   = ProtoField.bytes("ghostmesh.link_tag", "link_tag"),
  nonce      = ProtoField.bytes("ghostmesh.nonce", "Nonce"),
  ct         = ProtoField.bytes("ghostmesh.ciphertext", "Ciphertext (inner header + body, encrypted)"),
  aead       = ProtoField.bytes("ghostmesh.aead_tag", "Poly1305 tag"),
  body       = ProtoField.bytes("ghostmesh.body", "Body"),
  filler     = ProtoField.bytes("ghostmesh.filler", "Random filler"),

  -- CTRL (signed by the watchtower)
  ctrl       = ProtoField.none("ghostmesh.ctrl", "CTRL (signed by the watchtower)"),
  c_sub      = ProtoField.uint8("ghostmesh.ctrl.subtype", "Subtype", base.DEC, SUBTYPE),
  c_issued   = ProtoField.absolute_time("ghostmesh.ctrl.issued_at", "Issued at (mesh clock)", base.UTC),
  c_sig      = ProtoField.bytes("ghostmesh.ctrl.sig", "Ed25519 signature"),
  b_id       = ProtoField.uint32("ghostmesh.block.id", "block_id"),
  b_until    = ProtoField.absolute_time("ghostmesh.block.until", "Until (mesh clock)", base.UTC),
  b_reason   = ProtoField.uint8("ghostmesh.block.reason", "Reason", base.DEC, REASON),
  b_target   = ProtoField.none("ghostmesh.block.target", "Target"),
  b_pseudo   = ProtoField.uint32("ghostmesh.block.pseudo", "Pseudonym", base.HEX),
  b_mac      = ProtoField.ether("ghostmesh.block.mac", "MAC (all zero = any)"),
  b_epoch    = ProtoField.uint16("ghostmesh.block.epoch", "Epoch"),

  -- KEYS (epoch ratchet announcement)
  keys       = ProtoField.none("ghostmesh.keys", "KEYS (next-epoch key announcement)"),
  k_target   = ProtoField.uint16("ghostmesh.keys.target_epoch", "Target epoch"),
  k_mode     = ProtoField.uint8("ghostmesh.keys.mode", "Mode", base.DEC, MODE),
  k_pk       = ProtoField.bytes("ghostmesh.keys.next_pk", "next_pk (X25519 public key)"),
  k_nonce    = ProtoField.bytes("ghostmesh.keys.resync_nonce", "RESYNC nonce"),
  k_slot     = ProtoField.none("ghostmesh.keys.slot", "Slot"),
  k_tag      = ProtoField.bytes("ghostmesh.keys.tag", "Pair tag"),
  k_conf     = ProtoField.bytes("ghostmesh.keys.conf", "Confirmation hash"),
}
local list = {}
for _, f in pairs(F) do list[#list + 1] = f end
gm.fields = list

local E = {
  link_bad = ProtoExpert.new("ghostmesh.expert.link_bad", "link_tag failed at the watchtower (outsider or corrupted frame)",
                             expert.group.SECURITY, expert.severity.WARN),
  id_bad   = ProtoExpert.new("ghostmesh.expert.id_bad", "MAC doesn't match the pseudonym (spoof, replay, or unknown radio)",
                             expert.group.SECURITY, expert.severity.NOTE),
  unknown  = ProtoExpert.new("ghostmesh.expert.unknown", "Transmitter matches no known node (\"?\")",
                             expert.group.SECURITY, expert.severity.NOTE),
  rsv      = ProtoExpert.new("ghostmesh.expert.flags_rsv", "Reserved flag bits set",
                             expert.group.MALFORMED, expert.severity.WARN),
  short    = ProtoExpert.new("ghostmesh.expert.short", "Packet too short for a 240-byte GhostMesh frame",
                             expert.group.MALFORMED, expert.severity.ERROR),
}
gm.experts = { E.link_bad, E.id_bad, E.unknown, E.rsv, E.short }

-- UInt64 milliseconds -> NSTime
local function ms_time(range)
  local ms = range:uint64()
  local secs = (ms / 1000):tonumber()
  local nsecs = (ms % 1000):tonumber() * 1000000
  return NSTime.new(secs, nsecs)
end

local function ms_text(range)
  return os.date("!%H:%M:%S", math.floor((range:uint64() / 1000):tonumber())) .. " UTC"
end

local function dissect_ctrl(buf, pinfo, tree, o)
  local t = tree:add(F.ctrl, buf(o, 170))
  local sub = buf(o, 1):uint()
  t:add(F.c_sub, buf(o, 1))
  t:add(F.c_issued, buf(o + 1, 8), ms_time(buf(o + 1, 8)))
  local info = "CTRL " .. (SUBTYPE[sub] or ("subtype " .. sub)) .. " issued " .. ms_text(buf(o + 1, 8))
  local sig_at = o + 9
  if sub == 2 then
    local p = o + 9
    t:add(F.b_id, buf(p, 4))
    t:add(F.b_until, buf(p + 4, 8), ms_time(buf(p + 4, 8)))
    t:add(F.b_reason, buf(p + 12, 1))
    for k = 0, 1 do
      local e = p + 13 + 12 * k
      local tt = t:add(F.b_target, buf(e, 12))
      tt:set_text(string.format("Target %d: pseudo %08x, epoch %d", k + 1, buf(e, 4):uint(), buf(e + 10, 2):uint()))
      tt:add(F.b_pseudo, buf(e, 4))
      tt:add(F.b_mac, buf(e + 4, 6))
      tt:add(F.b_epoch, buf(e + 10, 2))
    end
    info = string.format("CTRL BLOCK id=%d reason=%s target %08x until %s", buf(p, 4):uint(),
                         REASON[buf(p + 12, 1):uint()] or "?", buf(p + 13, 4):uint(), ms_text(buf(p + 4, 8)))
    sig_at = p + 37
  end
  t:add(F.c_sig, buf(sig_at, 64))
  local rest = o + 170 - (sig_at + 64)
  if rest > 0 then t:add(F.filler, buf(sig_at + 64, rest)) end
  return info
end

local function dissect_keys(buf, pinfo, tree, o)
  local t = tree:add(F.keys, buf(o, 170))
  local mode = buf(o + 2, 1):uint()
  t:add(F.k_target, buf(o, 2))
  t:add(F.k_mode, buf(o + 2, 1))
  t:add(F.k_pk, buf(o + 3, 32))
  local slots = o + 35
  if mode == 1 then
    t:add(F.k_nonce, buf(o + 35, 8))
    slots = o + 43
  end
  for s = 0, 7 do
    local so = slots + 12 * s
    local st = t:add(F.k_slot, buf(so, 12))
    st:set_text("Slot " .. (s + 1) .. " (a real pair's tag, or random if unused)")
    st:add(F.k_tag, buf(so, 8))
    st:add(F.k_conf, buf(so + 8, 4))
  end
  local rest = o + 170 - (slots + 96)
  if rest > 0 then t:add(F.filler, buf(slots + 96, rest)) end
  return string.format("KEYS %s -> epoch %d", MODE[mode] or ("mode " .. mode), buf(o, 2):uint())
end

function gm.dissector(buf, pinfo, root)
  pinfo.cols.protocol = "GhostMesh"
  local tree = root:add(gm, buf())
  if buf:len() < 4 then tree:add_proto_expert_info(E.short); return end

  -- capture header
  local h = buf(3, 1):uint()
  local ct = tree:add(F.cap, buf(0, h))
  ct:add(F.cap_magic, buf(0, 2))
  ct:add(F.cap_ver, buf(2, 1))
  ct:add(F.cap_len, buf(3, 1))
  local fl = ct:add(F.cap_flags, buf(4, 1))
  fl:add(F.cap_link, buf(4, 1)); fl:add(F.cap_id, buf(4, 1))
  fl:add(F.cap_hasnode, buf(4, 1)); fl:add(F.cap_hasrx, buf(4, 1))
  ct:add(F.cap_rssi, buf(5, 1))
  local flags = buf(4, 1):uint()
  local node = "-"
  if (flags & 0x04) ~= 0 then                -- Lua 5.3+ bit operators (Wireshark 4.x)
    node = buf(6, 1):string()
    ct:add(F.cap_node, buf(6, 1))
  end
  ct:add(F.cap_rate, buf(7, 1)); ct:add(F.cap_sig, buf(8, 1)); ct:add(F.cap_mcs, buf(9, 1))
  ct:add(F.cap_rx, buf(10, 4))
  local link_ok = (flags & 0x01) ~= 0
  local id_ok = (flags & 0x02) ~= 0
  ct:append_text(string.format(": node %s, %d dBm, link_tag %s", node, buf(5, 1):int(), link_ok and "ok" or "FAILED"))

  if buf:len() < h + 240 then tree:add_proto_expert_info(E.short); return end
  local o = h
  local t = tree:add(F.frame, buf(o, 240))
  local ty = buf(o, 1):uint()
  t:add(F.type, buf(o, 1))
  local ft = t:add(F.flags, buf(o + 1, 1))
  ft:add(F.sos, buf(o + 1, 1)); ft:add(F.flags_rsv, buf(o + 1, 1))
  if (buf(o + 1, 1):uint() & 0xFE) ~= 0 then ft:add_proto_expert_info(E.rsv) end
  t:add(F.msg_id, buf(o + 2, 8))
  t:add(F.ttl, buf(o + 10, 1))
  t:add(F.hop, buf(o + 11, 1))
  t:add(F.src, buf(o + 12, 4))
  t:add(F.next_hop, buf(o + 16, 4))
  t:add(F.epoch, buf(o + 20, 2))
  t:add(F.link_tag, buf(o + 22, 8))

  local src = string.format("%08x", buf(o + 12, 4):uint())
  local nh = buf(o + 16, 4):uint()
  pinfo.cols.src = src
  pinfo.cols.dst = (nh == 0) and "flood" or string.format("%08x", nh)

  local info
  if ty == 3 then
    t:add(F.filler, buf(o + 30, 24)):set_text("Random filler (nonce field, unused by CTRL)")
    info = dissect_ctrl(buf, pinfo, t, o + 54)
    t:add(F.filler, buf(o + 224, 16)):set_text("Random filler (tag field, unused by CTRL)")
  elseif ty == 4 then
    t:add(F.filler, buf(o + 30, 24)):set_text("Random filler (nonce field, unused by KEYS)")
    info = dissect_keys(buf, pinfo, t, o + 54)
    t:add(F.filler, buf(o + 224, 16)):set_text("Random filler (tag field, unused by KEYS)")
  else
    t:add(F.nonce, buf(o + 30, 24))
    if ty == 1 then
      t:add(F.ct, buf(o + 54, 170))
      info = "DATA (message or ACK: encrypted)"
    else
      t:add(F.body, buf(o + 54, 170))
      info = TYPES[ty] or ("type " .. ty)
    end
    t:add(F.aead, buf(o + 224, 16))
  end

  local sos = ((buf(o + 1, 1):uint() & 0x01) ~= 0) and " SOS" or ""
  pinfo.cols.info = string.format("%s%s  hop %d ttl %d  epoch %d  [%s, %d dBm%s]", info, sos,
                                  buf(o + 11, 1):uint(), buf(o + 10, 1):uint(), buf(o + 20, 2):uint(),
                                  node, buf(5, 1):int(), link_ok and "" or ", BAD link_tag")
  if not link_ok then tree:add_proto_expert_info(E.link_bad) end
  if node == "?" then tree:add_proto_expert_info(E.unknown)
  elseif not id_ok then tree:add_proto_expert_info(E.id_bad) end
end

local encaps = wtap_encaps or wtap
DissectorTable.get("wtap_encap"):add(encaps.USER0, gm)
