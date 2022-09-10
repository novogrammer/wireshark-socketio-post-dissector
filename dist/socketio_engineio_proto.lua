--[[ Generated with https://github.com/TypeScriptToLua/TypeScriptToLua ]]
do
    local function separate_tvb_range(original, separator)
        local result = {}
        local i = 0
        local start = 0
        do
            while i < original:len() do
                if original:raw(i, 1) == separator then
                    result[#result + 1] = original:range(start, i - start)
                    start = i + 1
                end
                i = i + 1
            end
        end
        result[#result + 1] = original:range(start, i - start)
        return result
    end
    local function is_socket_io_polling_uri(uri)
        local found1 = string.find(uri, "/socket.io/", 1, true)
        local found2 = string.find(uri, "transport=polling", 1, true)
        return not not found1 and not not found2
    end
    local SOCKET_IO_TYPE_CONNECT = "0"
    local SOCKET_IO_TYPE_DISCONNECT = "1"
    local SOCKET_IO_TYPE_EVENT = "2"
    local SOCKET_IO_TYPE_ACK = "3"
    local SOCKET_IO_TYPE_CONNECT_ERROR = "4"
    local SOCKET_IO_TYPE_BINARY_EVENT = "5"
    local SOCKET_IO_TYPE_BINARY_ACK = "6"
    local SOCKET_IO_END_OF_BINARY_ATTACHMENT = "-"
    local SOCKET_IO_BEGIN_OF_NAMESPACE = "/"
    local SOCKET_IO_NAMESPACE_MAIN = "/"
    local SOCKET_IO_END_OF_NAMESPACE = ","
    local SOCKET_IO_TYPE_MAP = {}
    SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_CONNECT] = "CONNECT"
    SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_DISCONNECT] = "DISCONNECT"
    SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_EVENT] = "EVENT"
    SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_ACK] = "ACK"
    SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_CONNECT_ERROR] = "CONNECT ERROR"
    SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_BINARY_EVENT] = "BINARY EVENT"
    SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_BINARY_ACK] = "BINARY ACK"
    local socketio_field = ProtoField.none("socketio_engineio.socketio", "Socket.IO")
    local socketio_binary_data_field = ProtoField.bytes("socketio_engineio.socketio.binary_data", "binary data")
    local socketio_type_field = ProtoField.string("socketio_engineio.socketio.type", "type", base.UNICODE)
    local socketio_attachments_field = ProtoField.string("socketio_engineio.socketio.attachments", "attachments", base.UNICODE)
    local socketio_nsp_field = ProtoField.string("socketio_engineio.socketio.nsp", "nsp", base.UNICODE)
    local socketio_id_field = ProtoField.string("socketio_engineio.socketio.id", "id", base.UNICODE)
    local socketio_data_field = ProtoField.string("socketio_engineio.socketio.data", "data", base.UNICODE)
    local function process_socket_io_packet(tree, socket_io_packet, is_binary)
        local socket_io_tree = tree:add(socketio_field, socket_io_packet)
        if is_binary then
            socket_io_tree:add(socketio_binary_data_field, socket_io_packet)
            return
        end
        local i = 0
        local packet = {}
        packet.type = socket_io_packet:range(0, 1)
        if not (SOCKET_IO_TYPE_MAP[packet.type:raw()] ~= nil) then
            error("unknown packet type", 0)
        end
        if packet.type:raw() == SOCKET_IO_TYPE_BINARY_EVENT or packet.type:raw() == SOCKET_IO_TYPE_BINARY_ACK then
            i = i + 1
            local start = i
            while socket_io_packet:raw(i, 1) ~= SOCKET_IO_END_OF_BINARY_ATTACHMENT and i < socket_io_packet:len() do
                i = i + 1
            end
            local buf = socket_io_packet:range(start, i - start)
            if socket_io_packet:raw(i, 1) ~= SOCKET_IO_END_OF_BINARY_ATTACHMENT then
                error("SOCKET_IO_END_OF_BINARY_ATTACHMENT not found", 0)
            end
            packet.attachments = buf
        end
        if socket_io_packet:raw(i + 1, 1) == SOCKET_IO_BEGIN_OF_NAMESPACE then
            local start = i + 1
            while true do
                i = i + 1
                local c = socket_io_packet:raw(i, 1)
                if c == SOCKET_IO_END_OF_NAMESPACE then
                    break
                end
                if i == socket_io_packet:len() then
                    break
                end
            end
            packet.nsp = socket_io_packet:range(start, i - start)
        end
        if i + 1 ~= socket_io_packet:len() then
            local next = socket_io_packet:raw(i + 1, 1)
            if next == tostring(tonumber(next)) then
                local start = i + 1
                while true do
                    i = i + 1
                    if i == socket_io_packet:len() then
                        break
                    end
                    local c = socket_io_packet:raw(i, 1)
                    if c ~= tostring(tonumber(c)) then
                        i = i - 1
                        break
                    end
                end
                packet.id = socket_io_packet:range(start, i - start + 1)
            end
        end
        if i + 1 ~= socket_io_packet:len() then
            i = i + 1
            packet.data = socket_io_packet:range(
                i,
                socket_io_packet:len() - i
            )
        end
        socket_io_tree:add(
            socketio_type_field,
            packet.type,
            SOCKET_IO_TYPE_MAP[packet.type:raw()]
        )
        if packet.attachments ~= nil then
            socket_io_tree:add(socketio_attachments_field, packet.attachments)
        end
        if packet.nsp ~= nil then
            socket_io_tree:add(socketio_nsp_field, packet.nsp)
        else
            socket_io_tree:add(socketio_nsp_field, SOCKET_IO_NAMESPACE_MAIN)
        end
        if packet.id ~= nil then
            socket_io_tree:add(socketio_id_field, packet.id)
        end
        if packet.data ~= nil then
            socket_io_tree:add(
                socketio_data_field,
                packet.data,
                packet.data:raw()
            )
        end
    end
    local ENGINE_IO_PAYLOAD_SEPARATOR = string.char(30)
    local ENGINE_IO_TYPE_OPEN = "0"
    local ENGINE_IO_TYPE_CLOSE = "1"
    local ENGINE_IO_TYPE_PING = "2"
    local ENGINE_IO_TYPE_PONG = "3"
    local ENGINE_IO_TYPE_MESSAGE = "4"
    local ENGINE_IO_TYPE_UPGRADE = "5"
    local ENGINE_IO_TYPE_NOOP = "6"
    local ENGINE_IO_TYPE_BINARY_MESSAGE = "b"
    local ENGINE_IO_TYPE_MAP = {}
    ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_OPEN] = "open"
    ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_CLOSE] = "close"
    ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_PING] = "ping"
    ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_PONG] = "pong"
    ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_MESSAGE] = "message"
    ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_UPGRADE] = "upgrade"
    ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_NOOP] = "noop"
    ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_BINARY_MESSAGE] = "binary message"
    local engineio_field = ProtoField.none("socketio_engineio.engineio", "Engine.IO")
    local engineio_binary_message_field = ProtoField.bytes("socketio_engineio.engineio.binary_message", "binary message")
    local engineio_type_field = ProtoField.string("socketio_engineio.engineio.type", "type", base.UNICODE)
    local engineio_data_field = ProtoField.string("socketio_engineio.engineio.data", "data", base.UNICODE)
    local engineio_decoded_data_field = ProtoField.bytes("socketio_engineio.engineio.decoded_data", "decoded data")
    local function process_engine_io_packet(tree, engine_io_packet, is_binary, process_payload)
        local engine_io_tree = tree:add(engineio_field, engine_io_packet)
        if is_binary then
            engine_io_tree:add(engineio_binary_message_field, engine_io_packet)
            process_payload(tree, engine_io_packet, true)
            return
        end
        local packet = {}
        packet.type = engine_io_packet:range(0, 1)
        if 1 < engine_io_packet:len() then
            packet.data = engine_io_packet:range(
                1,
                engine_io_packet:len() - 1
            )
        end
        if not (ENGINE_IO_TYPE_MAP[packet.type:raw()] ~= nil) then
            error("unknown packet type", 0)
        end
        if packet.type:raw() == ENGINE_IO_TYPE_BINARY_MESSAGE then
            packet.decoded_data = packet.data:bytes():base64_decode():tvb("decoded_data"):range()
        end
        engine_io_tree:add(
            engineio_type_field,
            packet.type,
            ENGINE_IO_TYPE_MAP[packet.type:raw()]
        )
        if packet.data ~= nil then
            engine_io_tree:add(engineio_data_field, packet.data)
        end
        if packet.decoded_data ~= nil then
            engine_io_tree:add(engineio_decoded_data_field, packet.decoded_data)
        end
        if packet.type:raw() == ENGINE_IO_TYPE_MESSAGE then
            process_payload(tree, packet.data, false)
        end
        if packet.type:raw() == ENGINE_IO_TYPE_BINARY_MESSAGE then
            process_payload(tree, packet.decoded_data, true)
        end
    end
    local http = Field.new("http")
    local http_request_uri = Field.new("http.request.uri")
    local http_request_method = Field.new("http.request.method")
    local http_response_for_uri = Field.new("http.response_for.uri")
    local http_response_line = Field.new("http.response.line")
    local websocket = Field.new("websocket")
    local field_data_text_lines = Field.new("data-text-lines")
    local field_data = Field.new("data")
    local socketio_engineio_proto = Proto.new("socketio_engineio", "Socket.IO and Engine.IO PostDissector")
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = engineio_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = engineio_binary_message_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = engineio_type_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = engineio_data_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = engineio_decoded_data_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = socketio_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = socketio_binary_data_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = socketio_type_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = socketio_attachments_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = socketio_nsp_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = socketio_id_field
    socketio_engineio_proto.fields[#socketio_engineio_proto.fields + 1] = socketio_data_field
    socketio_engineio_proto.init = function()
    end
    socketio_engineio_proto.dissector = function(buffer, pinfo, tree)
        local info_http = http()
        local info_http_request_uri = http_request_uri()
        local info_http_request_method = http_request_method()
        local info_http_response_for_uri = http_response_for_uri()
        local info_http_response_line = http_response_line()
        local info_websocket = websocket()
        if not info_http and not info_websocket then
            return 0
        end
        if info_http_request_uri ~= nil then
            if not is_socket_io_polling_uri(info_http_request_uri.value) then
                return 0
            elseif info_http_request_method.value == "GET" then
                return 0
            end
        end
        if info_http_response_for_uri ~= nil then
            if not is_socket_io_polling_uri(info_http_response_for_uri.value) then
                return 0
            else
                local s = info_http_response_line.value
                local found = string.find(s, "Content-Type: text/html", 1, true)
                if not not found then
                    return 0
                end
            end
        end
        local binary_payload = nil
        local text_payload = nil
        local payload = nil
        local info_field_data = field_data()
        if info_field_data ~= nil then
            binary_payload = info_field_data.value:tvb("binary_payload"):range()
            payload = binary_payload
        end
        local info_field_data_text_lines = field_data_text_lines()
        if info_field_data_text_lines ~= nil then
            text_payload = info_field_data_text_lines.value:tvb("text_payload"):range()
            payload = text_payload
        end
        if payload == nil then
            return 0
        end
        local proto_tree = tree:add(socketio_engineio_proto, payload)
        if text_payload ~= nil then
            local engine_io_packet_list = separate_tvb_range(text_payload, ENGINE_IO_PAYLOAD_SEPARATOR)
            do
                local i = 1
                while i <= #engine_io_packet_list do
                    local engine_io_packet = engine_io_packet_list[i]
                    process_engine_io_packet(proto_tree, engine_io_packet, false, process_socket_io_packet)
                    i = i + 1
                end
            end
        elseif binary_payload ~= nil then
            local engine_io_packet = binary_payload
            process_engine_io_packet(proto_tree, engine_io_packet, true, process_socket_io_packet)
        end
        return 0
    end
    register_postdissector(socketio_engineio_proto)
end
