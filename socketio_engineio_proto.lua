-- https://github.com/novogrammer/wireshark-socketio-post-dissector

-- see
-- https://github.com/socketio/engine.io-protocol/
-- https://github.com/socketio/socket.io-protocol/



local function separate_tvb_range(original, separator)
    local result = {}
    do
        local i = 0
        local start = 0
        while i < original:len() do
            if original:raw(i,1) == separator then
                result[#result + 1] = original:range(start, i - start);
                start = i + 1
            end
            i = i + 1
        end
        result[#result + 1] = original:range(start, i - start);
    end
return result
end

local function is_socket_io_polling_uri(uri)
    return GRegex.match(uri,"\\/socket\\.io\\/.+transport\\=polling")
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

SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_CONNECT]="CONNECT"
SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_DISCONNECT]="DISCONNECT"
SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_EVENT]="EVENT"
SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_ACK]="ACK"
SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_CONNECT_ERROR]="CONNECT ERROR"
SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_BINARY_EVENT]="BINARY EVENT"
SOCKET_IO_TYPE_MAP[SOCKET_IO_TYPE_BINARY_ACK]="BINARY ACK"

local function process_socket_io_packet(tree, socket_io_packet, is_binary)
    local socket_io_tree=tree:add(socketio_field,socket_io_packet)
    if is_binary then
        socket_io_tree:add(socketio_binary_data_field,socket_io_packet)
        return
    end
    local i = 0
    local packet = {
        type = socket_io_packet:range(0, 1),
        data = nil
    }
    if not SOCKET_IO_TYPE_MAP[packet.type:raw()] then
        error("unknown packet type")
    end

    if packet.type:raw() == SOCKET_IO_TYPE_BINARY_EVENT or packet.type:raw() == SOCKET_IO_TYPE_BINARY_ACK then
        i = i + 1
        local start = i
        while socket_io_packet:raw(i, 1) ~= SOCKET_IO_END_OF_BINARY_ATTACHMENT and i < socket_io_packet:len() do
            i = i + 1
        end
        local buf = socket_io_packet:range(start, i - start)
        if socket_io_packet:raw(i, 1) ~= SOCKET_IO_END_OF_BINARY_ATTACHMENT then
            error("SOCKET_IO_END_OF_BINARY_ATTACHMENT not found")
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
    socket_io_tree:add(socketio_type_field,packet.type, SOCKET_IO_TYPE_MAP[packet.type:raw()])
    if packet.attachments ~= nil then
        socket_io_tree:add(socketio_attachments_field,packet.attachments)
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
        socket_io_tree:add(socketio_data_field,packet.data, packet.data:raw())
    end
end

local ENGINE_IO_PAYLOAD_SEPARATOR = "\x1e"
local ENGINE_IO_TYPE_OPEN = "0"
local ENGINE_IO_TYPE_CLOSE = "1"
local ENGINE_IO_TYPE_PING = "2"
local ENGINE_IO_TYPE_PONG = "3"
local ENGINE_IO_TYPE_MESSAGE = "4"
local ENGINE_IO_TYPE_UPGRADE = "5"
local ENGINE_IO_TYPE_NOOP = "6"
local ENGINE_IO_TYPE_BINARY_MESSAGE = "b"
local ENGINE_IO_TYPE_MAP = {}
ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_OPEN]="open"
ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_CLOSE]="close"
ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_PING]="ping"
ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_PONG]="pong"
ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_MESSAGE]="message"
ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_UPGRADE]="upgrade"
ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_NOOP]="noop"
ENGINE_IO_TYPE_MAP[ENGINE_IO_TYPE_BINARY_MESSAGE]="binary message"


local function process_engine_io_packet(tree, engine_io_packet,is_binary ,process_payload)
    local engine_io_tree=tree:add(engineio_field,engine_io_packet)
    if is_binary then
        engine_io_tree:add(engineio_binary_message_field,engine_io_packet)
        process_payload(tree, engine_io_packet, true)
        return
    end
    local packet = {
        type = engine_io_packet:range(0, 1),
    }
    if 1 < engine_io_packet:len() then
        packet.data=engine_io_packet:range(
            1,
            engine_io_packet:len() - 1
        )
    end
    if not ENGINE_IO_TYPE_MAP[packet.type:raw()] then
        error("unknown packet type")
    end
    if packet.type:raw() == ENGINE_IO_TYPE_BINARY_MESSAGE then
        packet.decoded_data = packet.data:bytes():base64_decode():tvb("decoded_data"):range()
    end

    engine_io_tree:add(engineio_type_field,packet.type,ENGINE_IO_TYPE_MAP[packet.type:raw()])
    if packet.data ~= nil then
        engine_io_tree:add(engineio_data_field,packet.data)
    end
    if packet.decoded_data ~= nil then
        engine_io_tree:add(engineio_decoded_data_field,packet.decoded_data)
    end

    if packet.type:raw() == ENGINE_IO_TYPE_MESSAGE then
        process_payload(tree, packet.data, false)
    end
    if packet.type:raw() == ENGINE_IO_TYPE_BINARY_MESSAGE then
        process_payload(tree, packet.decoded_data, true)
    end
    
end



http = Field.new("http")
http_request_uri = Field.new("http.request.uri")
http_request_method = Field.new("http.request.method")
http_response_for_uri = Field.new("http.response_for.uri")
http_response_line = Field.new("http.response.line")

websocket = Field.new("websocket")

field_data_text_lines = Field.new("data-text-lines")
field_data = Field.new("data")

socketio_engineio_proto = Proto("socketio_engineio", "Socket.IO and Engine.IO PostDissector")

engineio_field = ProtoField.none("socketio_engineio.engineio","Engine.IO")
engineio_binary_message_field = ProtoField.bytes("socketio_engineio.engineio.binary_message","binary message")
engineio_type_field = ProtoField.string("socketio_engineio.engineio.type","type",base.UNICODE)
engineio_data_field = ProtoField.string("socketio_engineio.engineio.data","data",base.UNICODE)
engineio_decoded_data_field = ProtoField.bytes("socketio_engineio.engineio.decoded_data","decoded data")

socketio_field = ProtoField.none("socketio_engineio.socketio","Socket.IO")
socketio_binary_data_field = ProtoField.bytes("socketio_engineio.socketio.binary_data","binary data")
socketio_type_field = ProtoField.string("socketio_engineio.socketio.type","type",base.UNICODE)
socketio_attachments_field = ProtoField.string("socketio_engineio.socketio.attachments","attachments",base.UNICODE)
socketio_nsp_field = ProtoField.string("socketio_engineio.socketio.nsp","nsp",base.UNICODE)
socketio_id_field = ProtoField.string("socketio_engineio.socketio.id","id",base.UNICODE)
socketio_data_field = ProtoField.string("socketio_engineio.socketio.data","data",base.UNICODE)


socketio_engineio_proto.fields={
    engineio_field,
    engineio_binary_message_field,
    engineio_type_field,
    engineio_data_field,
    engineio_decoded_data_field,

    socketio_field,
    socketio_binary_data_field,
    socketio_type_field,
    socketio_attachments_field,
    socketio_nsp_field,
    socketio_id_field,
    socketio_data_field,
}



function socketio_engineio_proto.init()
end

function socketio_engineio_proto.dissector(buffer, pinfo, tree)

    local http = http()
    local http_request_uri = http_request_uri()
    local http_request_method = http_request_method()
    local http_response_for_uri = http_response_for_uri()
    local http_response_line = http_response_line()
    local websocket = websocket()

    
    if not http and not websocket then
        -- other protocol
        return
    end
    if http_request_uri then
        if not is_socket_io_polling_uri(http_request_uri.value) then
            -- other http request
            return
        elseif http_request_method.value =="GET" then
            -- skip http get request
            return
        end
    end

    if http_response_for_uri then
        if not is_socket_io_polling_uri(http_response_for_uri.value) then
            -- other http response
            return
        elseif GRegex.match(http_response_line(),"Content-Type: text\\/html") then
            -- skip post response
            return
        end
    end


    local binary_payload
    local text_payload
    local payload

    if field_data() then
        binary_payload = field_data().value:tvb("binary_payload"):range();
        payload=binary_payload
    end
    if field_data_text_lines() then
        text_payload = field_data_text_lines().value:tvb("text_payload"):range()
        payload=text_payload
    end

    if not text_payload and not binary_payload then
        return
    end
    local proto_tree=tree:add(socketio_engineio_proto,payload);
    
    if text_payload then
        local engine_io_packet_list=separate_tvb_range(text_payload,ENGINE_IO_PAYLOAD_SEPARATOR);
        do
            local i
            for i = 1,#engine_io_packet_list do
                local engine_io_packet=engine_io_packet_list[i]
                process_engine_io_packet(proto_tree, engine_io_packet,false,process_socket_io_packet)

            end
        end
    elseif binary_payload then
        local engine_io_packet=binary_payload
        process_engine_io_packet(proto_tree, engine_io_packet,true,process_socket_io_packet)
    end
end

register_postdissector(socketio_engineio_proto)
