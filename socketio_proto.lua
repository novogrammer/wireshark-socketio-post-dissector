-- https://github.com/novogrammer/wireshark-socketio-post-dissector

-- see
-- https://github.com/socketio/engine.io-protocol/
-- https://github.com/socketio/socket.io-protocol/



local function separate_byte_array(original, separator)
    local result = {}
    do
        local i = 0
        local start = 0
        while i < original:len() do
            if original:subset(i,1):raw() == separator then
                result[#result + 1] = original:subset(start, i - start);
                start = i + 1
            end
            i = i + 1
        end
        result[#result + 1] = original:subset(start, i - start);
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
    local socket_io_tree=tree:add("Socket.IO")
    if is_binary then
        socket_io_tree:add("binary packet:",socket_io_packet:tohex())
        return
    end
    local i = 0
    local packet = {
        type = socket_io_packet:subset(0, 1):raw(),
        data = nil
    }
    if not SOCKET_IO_TYPE_MAP[packet.type] then
        error("unknown packet type")
    end

    if packet.type == SOCKET_IO_TYPE_BINARY_EVENT or packet.type == SOCKET_IO_TYPE_BINARY_ACK then
        local start = i
        while socket_io_packet:subset(i, 1):raw() ~= SOCKET_IO_END_OF_BINARY_ATTACHMENT and i < socket_io_packet:len() do
            i = i + 1
        end
        local buf = socket_io_packet:subset(start, i - start):raw()
        if socket_io_packet:subset(i, 1):raw() ~= SOCKET_IO_END_OF_BINARY_ATTACHMENT then
            error("SOCKET_IO_END_OF_BINARY_ATTACHMENT not found")
        end
        packet.attachments = tonumber(buf)
    end
    if socket_io_packet:subset(i + 1, 1):raw() == SOCKET_IO_BEGIN_OF_NAMESPACE then
        local start = i + 1
        while true do
            i = i + 1
            local c = socket_io_packet:subset(i, 1):raw()
            if c == SOCKET_IO_END_OF_NAMESPACE then
                break
            end
            if i == socket_io_packet:len() then
                break
            end
        end
        packet.nsp = socket_io_packet:subset(start, i - start):raw()
    else
        packet.nsp = SOCKET_IO_BEGIN_OF_NAMESPACE
    end
    if i + 1 ~= socket_io_packet:len() then
        local next = socket_io_packet:subset(i + 1, 1):raw()
        if next == tostring(tonumber(next)) then
            local start = i + 1
            while true do
                i = i + 1
                if i == socket_io_packet:len() then
                    break
                end
                local c = socket_io_packet:subset(i, 1):raw()
                if c ~= tostring(tonumber(c)) then
                    i = i - 1
                    break
                end
            end
            packet.id = tonumber(socket_io_packet:subset(start, i - start + 1):raw())
        end
    end
    if i + 1 ~= socket_io_packet:len() then
        i = i + 1
        packet.data = socket_io_packet:subset(
            i,
            socket_io_packet:len() - i
        )
    end
    socket_io_tree:add("type:", SOCKET_IO_TYPE_MAP[packet.type])
    if packet.attachments ~= nil then
        socket_io_tree:add("attachments:",packet.attachments)
    end
    if packet.nsp ~= nil then
        socket_io_tree:add("nsp:", packet.nsp)
    end
    if packet.id ~= nil then
        socket_io_tree:add("id:", packet.id)
    end
    if packet.data ~= nil then
        socket_io_tree:add("data:", packet.data:raw())
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
    local engine_io_tree=tree:add("Engine.IO")
    if is_binary then
        engine_io_tree:add("binary message:",engine_io_packet:tohex())
        process_payload(tree, engine_io_packet, true)
        return
    end
    local packet = {
        type = engine_io_packet:subset(0, 1):raw(),
    }
    if 1 < engine_io_packet:len() then
        packet.data=engine_io_packet:subset(
            1,
            engine_io_packet:len() - 1
        )
    end
    if not ENGINE_IO_TYPE_MAP[packet.type] then
        error("unknown packet type")
    end
    if packet.type == ENGINE_IO_TYPE_BINARY_MESSAGE then
        packet.decoded_data = packet.data:base64_decode()
    end

    engine_io_tree:add("type:",ENGINE_IO_TYPE_MAP[packet.type])
    if packet.data ~= nil then
        engine_io_tree:add("data:",packet.data:raw())
    end
    if packet.decoded_data ~= nil then
        engine_io_tree:add("decoded data:",packet.decoded_data:tohex())
    end

    if packet.type == ENGINE_IO_TYPE_MESSAGE then
        process_payload(tree, packet.data, false)
    end
    if packet.type == ENGINE_IO_TYPE_BINARY_MESSAGE then
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

socketio_proto = Proto("socketio", "Socket.IO and Engine.IO PostDissector")


function socketio_proto.init()
end

function socketio_proto.dissector(buffer, pinfo, tree)

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

    if field_data() then
        binary_payload = field_data().value;
    end
    if field_data_text_lines() then
        text_payload = field_data_text_lines().value
    end

    if not text_payload and not binary_payload then
        return
    end
    local proto_tree=tree:add(socketio_proto);
    
    if text_payload then
        local engine_io_packet_list=separate_byte_array(text_payload,ENGINE_IO_PAYLOAD_SEPARATOR);
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

register_postdissector(socketio_proto)
