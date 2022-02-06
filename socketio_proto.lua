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
            if original:get_index(i) == separator then
                result[#result + 1] = original:subset(start, i - start);
                start = i + 1
            end
            i = i + 1
        end
        result[#result + 1] = original:subset(start, i - start);
    end
return result
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
    i = i + 1
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
    if i ~= socket_io_packet:len() then
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
            packet.id = tonumber(socket_io_packet:subset(start, i - start):raw())
        end
    end
    if i ~= socket_io_packet:len() then
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


local function process_engine_io_packet(tree, engine_io_packet, process_payload)
    local engine_io_tree=tree:add("Engine.IO")
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
        engine_io_tree:add("decoded data:",packet.data:hex())
    end

    if packet.type == ENGINE_IO_TYPE_MESSAGE then
        process_payload(tree, packet.data, false)
    end
    if packet.type == ENGINE_IO_TYPE_BINARY_MESSAGE then
        process_payload(tree, packet.decoded_data, true)
    end
    
end



websocket = Field.new("websocket")
websocket_payload = Field.new("data-text-lines")

socketio_proto = Proto("socketio", "Socket.IO and Engine.IO PostDissector")


function socketio_proto.init()
end

function socketio_proto.dissector(buffer, pinfo, tree)

    if not websocket() then
        return
    end

    local websocket_payload = websocket_payload()
    if not websocket_payload then
        return
    end
    local proto_tree=tree:add(socketio_proto);
    
    local engine_io_packet_list=separate_byte_array(websocket_payload.value,ENGINE_IO_PAYLOAD_SEPARATOR);
    do
        local i
        for i = 1,#engine_io_packet_list do
            local engine_io_packet=engine_io_packet_list[i]
            process_engine_io_packet(proto_tree, engine_io_packet,process_socket_io_packet)

        end
    end
end

register_postdissector(socketio_proto)