-- sfos-dissect.lua
--
-- A wireshark dissector for STAS and SATC packets
--
-- Dissection of STAS may be incomplete!	
--
-- To use, find or create your local Wireshark plugin folder and put it there.
-- For Unix/Mac, it's 
--          ~/.local/lib/wireshark/plugins/
-- For Windows, it's 
--          %APPDATA%\Wireshark\plugins
--
-- You may need to create the directory if you've never used plugins before


-- stas_protocol = Proto("STAS", "Sophos Transparent Authentication Service")

stas_type = ProtoField.uint8("sfos.stas.type", "STAS message type", base.DEC)
stas_tlv_len = ProtoField.string("sfos.stas.tlv_len", "STAS TLV data length", base.NONE)
stas_poll_ip = ProtoField.string("sfos.stas.poll_ip", "STAS poll request target IP", base.NONE)
stas_use_port = ProtoField.string("sfos.stas.use_port", "STAS port on agent for firewall to use", base.NONE)
stas_encrypted = ProtoField.string("sfos.stas.encrypted", "STAS Encrypted data block", base.NONE)
stas_logout_message = ProtoField.string("sfos.stas.logout_msg", "STAS logout message from firewall", base.NONE)
stas_logout_message_len = ProtoField.uint8("sfos.stas.logout_msg_len", "STAS logout message length", base.DEC)
sfos_protocol_type = ProtoField.string("sfos.protocol", "SFOS protocol", base.NONE)

-- ßsatc_protocol = Proto("SATC", "Sophos Thin Client Authentication Protocol")

sfos_protocol = Proto("SFOS", "Sophos Firewall Authentication")

satc_type = ProtoField.uint8("sfos.satc.type", "SATC message type", base.DEC)
satc_session_id = ProtoField.uint16("sfos.satc.session_id", "Session ID", base.DEC)
satc_srcport = ProtoField.uint16("sfos.satc.srcport", "Connection src port", base.DEC)
satc_dstport = ProtoField.uint16("sfos.satc.dstport", "Connection dest port", base.DEC)
satc_ipaddr = ProtoField.ipv4("sfos.satc.ipaddr", "Connection dest IP", base.DEC)
satc_user = ProtoField.string("sfos.satc.username", "Login user name", base.NONE)
satc_domain = ProtoField.string("sfos.satc.domain", "Login user domain", base.NONE)

sfos_protocol.fields = {satc_type,
						satc_session_id,
						satc_srcport,
						satc_dstport,
						satc_ipaddr,
						satc_user,
						satc_domain ,
						stas_type,
						stas_tlv_len,
						stas_poll_ip,
						stas_use_port,
						stas_encrypted,
						stas_logout_message,
						stas_logout_message_len,
						sfos_protocol_type
					}


function get_type_name(msg)
	local type_name = "Unknown"

	    if msg == 11 then type_name = "STAS_WORKSTATION_POLLING"
	elseif msg == 12 then type_name = "STAS_GET_ALL_USERS"
	elseif msg == 13 then type_name = "STAS_LOGOUT_USERS"
	elseif msg == 102 then type_name = "STAS_ACTIVE_COLLECTOR_QRY"
	elseif msg == 104 then type_name = "STAS_LIVE_NACK"
	elseif msg == 105 then type_name = "STAS_LIVE_OFF"
	elseif msg == 2 then type_name = "STAS_CONN_RESPONSE"
	elseif msg == 3 then type_name = "STAS_AUTH_NACK_NA_SSO"
	elseif msg == 107 then type_name = "STAS_CONN_CHECK"
	elseif msg == 81 then type_name = "STAS_LOGON_USER"
	elseif msg == 82 then type_name = "STAS_LOGOUT_USER"
	elseif msg == 103 then type_name = "STAS_HEARTBEAT"
	elseif msg == 106 then type_name = "STAS_ACTIVE_COLLECTOR_ACK"

	elseif msg == 96 then type_name = "SATC_LOGIN"
	elseif msg == 97 then type_name = "SATC_LOGOUT"
	elseif msg == 98 then type_name = "SATC_FLUSH"
	elseif msg == 8  then type_name = "SATC_LOGOUT_ACK" end

	return type_name
end


function is_satc_type(msg)
	return (msg == 96) or (msg == 97) or (msg == 98) or (msg == 8)
end

function sfos_protocol.dissector(buffer, pinfo, tree)
	length=buffer:len()
	if length == 0 then return end
	local this_msg_type = buffer(0,1):uint()
	local this_msg_name = get_type_name(this_msg_type)
	if not (string.find(this_msg_name, "SATC_")==nil) then 
		dissect_satc(buffer, pinfo, tree, this_msg_type, this_msg_name) 
	elseif not (string.find(this_msg_name,"STAS_")==nil) then
		dissect_stas(buffer, pinfo, tree, this_msg_type, this_msg_name)
	end

end

function dissect_satc(buffer, pinfo, tree, this_msg_type, this_msg_name)
	pinfo.cols.protocol = "SFOS.SATC"

	local subtree = tree:add(sfos_protocol, buffer(), "SFOS authentication"):add(sfos_protocol_type, buffer(), "SATC")
	local this_satc_type = buffer(0,1):uint()
	local infostring = string.format("%s(%d)", this_msg_name, this_msg_type)

	subtree:add(satc_type, buffer(0,1)):append_text(" (" .. this_msg_type  .. ")")
	
	if (this_msg_type == 96) or (this_msg_type == 97) then
		subtree:add(satc_session_id, buffer(1,2))
		infostring = string.format("%s Session %d", infostring, buffer(1,2):uint())
	end
	if (this_msg_type == 96) then
		subtree:add(satc_srcport, buffer(3,2))
		subtree:add(satc_dstport, buffer(5,2))
		subtree:add(satc_ipaddr, buffer(7,4))
		subtree:add(satc_user, buffer(11,64))
		subtree:add(satc_domain, buffer(75,64))
		infostring = string.format("%s, Src port: %d, Dest: %s:%d, User: %s", infostring, buffer(3,2):uint(), buffer(7,4):ipv4(), buffer(5,2):uint(), buffer(11,64):string())
	end

	pinfo.cols.info = infostring
end

function dissect_stas(buffer, pinfo, tree, this_msg_type, this_msg_name)

	pinfo.cols.protocol = "SFOS.STAS"

	local subtree = tree:add(sfos_protocol, buffer(), "SFOS authentication"):add(sfos_protocol_type, buffer(), "STAS")
	local infostring = string.format("%s(%d)", get_type_name(this_msg_type), this_msg_type)

	subtree:add(stas_type, buffer(0,1)):append_text(" (" .. get_type_name(this_msg_type) .. ")")

	if (this_msg_type == 8) then
		-- SATC_LOGOUT_ACK actually sent in response to STAS logout too, but inconsistent format
		-- Byte 1: 08 
		-- Byte 2: 00
		-- Byte 3: Length of text message
		-- Byte 4: 00
		-- Zero terminated ascii text message
		subtree:add(stas_logout_message_len, buffer(2,1):uint())
		subtree:add(stas_logout_message, buffer(4,(buffer(2,1):uint()-4)))
		infostring = infostring .. " - " .. buffer(4,(buffer(2,1):uint()-4)):stringz()
	else

		subtree:add(stas_tlv_len, buffer(1,4))
		local tlv_len_s = buffer(1,4):stringz()
		local tlv_len = tonumber(tlv_len_s)
		local buff_len = buffer:len()

		if not (tlv_len == buff_len) then
	--		infostring = string.format("%s Length mismatch (TLV: %d Actual: %d)", infostring, tlv_len, 172)
			infostring = string.format("%s Length mismatch (%s %d)", infostring, tlv_len_s, buff_len)
		end
		pinfo.cols.info = infostring

		if this_msg_type == 81 or this_msg_type == 82 then
			-- LOGON_USER and LOGOUT_USER just has a big old block of encrypted data
			subtree:add(stas_encrypted, buffer(15, tlv_len-15))
			infostring = infostring .. "  Encrypted"
		end

		if (tlv_len > 9) then
			next_chunk=5
			repeat
				local tlv_code=buffer(next_chunk,1):uint()
				local tlv_elen=buffer(next_chunk+1,1):uint()
				if tlv_code == 7 then -- Response port
					subtree:add(stas_use_port, buffer(next_chunk+2,tlv_elen))
					infostring = string.format("%s Agent port %s", infostring, buffer(next_chunk+2,tlv_elen):string())
				elseif tlv_code == 1 then
					subtree:add(stas_poll_ip, buffer(next_chunk+2,tlv_elen))
					infostring = string.format("%s Poll IP %s", infostring, buffer(next_chunk+2,tlv_elen):string())
				end
				next_chunk = next_chunk + (tlv_elen+2)
			until next_chunk>=tlv_len
		end
	end

--	if (this_msg_type == 96) or (this_msg_type == 97) then
--		subtree:add(satc_session_id, buffer(1,2))
--		infostring = string.format("%s Session %d", infostring, buffer(1,2):uint())
--	end
--	if (this_satc_type == 96) then
--		subtree:add(satc_srcport, buffer(3,2))
--		subtree:add(satc_dstport, buffer(5,2))
--		subtree:add(satc_ipaddr, buffer(7,4))
--		subtree:add(satc_user, buffer(11,64))
--		subtree:add(satc_domain, buffer(75,64))
--		infostring = string.format("%s, Src port: %d, Dest: %s:%d", infostring, buffer(3,2):uint(), buffer(7,4):ipv4(), buffer(5,2):uint())
--	end

	pinfo.cols.info = infostring
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(6677, sfos_protocol)
udp_port:add(5566, sfos_protocol)
udp_port:add(6060, sfos_protocol)
