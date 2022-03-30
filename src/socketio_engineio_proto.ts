// https://github.com/novogrammer/wireshark-socketio-post-dissector

// see
// https://github.com/socketio/engine.io-protocol/
// https://github.com/socketio/socket.io-protocol/
{

  function separate_tvb_range(this: void, original: TvbRange, separator: string): LuaTable<number, TvbRange> {
    const result = new LuaTable<number, TvbRange>();
    let i = 0;
    let start = 0;
    for (; i < original.len(); i++) {
      if (original.raw(i, 1) === separator) {
        result.set(result.length() + 1, original.range(start, i - start));
        start = i + 1;
      }
    }
    result.set(result.length() + 1, original.range(start, i - start));
    return result;
  }
  function is_socket_io_polling_uri(this: void, uri: string): boolean {
    const [matched] = GRegex.match(uri, "\\/socket\\.io\\/.+transport\\=polling");
    return !!matched;
  }
  const SOCKET_IO_TYPE_CONNECT = "0"
  const SOCKET_IO_TYPE_DISCONNECT = "1"
  const SOCKET_IO_TYPE_EVENT = "2"
  const SOCKET_IO_TYPE_ACK = "3"
  const SOCKET_IO_TYPE_CONNECT_ERROR = "4"
  const SOCKET_IO_TYPE_BINARY_EVENT = "5"
  const SOCKET_IO_TYPE_BINARY_ACK = "6"
  const SOCKET_IO_END_OF_BINARY_ATTACHMENT = "-"
  const SOCKET_IO_BEGIN_OF_NAMESPACE = "/"
  const SOCKET_IO_NAMESPACE_MAIN = "/"
  const SOCKET_IO_END_OF_NAMESPACE = ","
  const SOCKET_IO_TYPE_MAP = new LuaTable<string, string>();

  SOCKET_IO_TYPE_MAP.set(SOCKET_IO_TYPE_CONNECT, "CONNECT");
  SOCKET_IO_TYPE_MAP.set(SOCKET_IO_TYPE_DISCONNECT, "DISCONNECT");
  SOCKET_IO_TYPE_MAP.set(SOCKET_IO_TYPE_EVENT, "EVENT");
  SOCKET_IO_TYPE_MAP.set(SOCKET_IO_TYPE_ACK, "ACK");
  SOCKET_IO_TYPE_MAP.set(SOCKET_IO_TYPE_CONNECT_ERROR, "CONNECT ERROR");
  SOCKET_IO_TYPE_MAP.set(SOCKET_IO_TYPE_BINARY_EVENT, "BINARY EVENT");
  SOCKET_IO_TYPE_MAP.set(SOCKET_IO_TYPE_BINARY_ACK, "BINARY ACK");


  const socketio_field = ProtoField.none("socketio_engineio.socketio", "Socket.IO")
  const socketio_binary_data_field = ProtoField.bytes("socketio_engineio.socketio.binary_data", "binary data")
  const socketio_type_field = ProtoField.string("socketio_engineio.socketio.type", "type", base.UNICODE)
  const socketio_attachments_field = ProtoField.string("socketio_engineio.socketio.attachments", "attachments", base.UNICODE)
  const socketio_nsp_field = ProtoField.string("socketio_engineio.socketio.nsp", "nsp", base.UNICODE)
  const socketio_id_field = ProtoField.string("socketio_engineio.socketio.id", "id", base.UNICODE)
  const socketio_data_field = ProtoField.string("socketio_engineio.socketio.data", "data", base.UNICODE)


  function process_socket_io_packet(this: void, tree: TreeItem, socket_io_packet: TvbRange, is_binary: boolean): void {
    const socket_io_tree = tree.add(
      socketio_field,
      socket_io_packet
    );
    if (is_binary) {
      socket_io_tree.add(
        socketio_binary_data_field,
        socket_io_packet
      );
      return;
    }
    let i = 0;
    const packet = new LuaTable<string, TvbRange>();
    packet.set("type", socket_io_packet.range(0, 1));
    // packet.set("data",null);

    if (!SOCKET_IO_TYPE_MAP.has(packet.get("type").raw())) {
      throw "unknown packet type";
    }
    if (packet.get("type").raw() == SOCKET_IO_TYPE_BINARY_EVENT || packet.get("type").raw() == SOCKET_IO_TYPE_BINARY_ACK) {
      i = i + 1;
      const start = i;
      while (socket_io_packet.raw(i, 1) != SOCKET_IO_END_OF_BINARY_ATTACHMENT && i < socket_io_packet.len()) {
        i = i + 1;

      }
      const buf = socket_io_packet.range(start, i - start);
      if (socket_io_packet.raw(i, 1) != SOCKET_IO_END_OF_BINARY_ATTACHMENT) {
        throw "SOCKET_IO_END_OF_BINARY_ATTACHMENT not found";
      }
      packet.set("attachments", buf);
    }
    if (socket_io_packet.raw(i + 1, 1) == SOCKET_IO_BEGIN_OF_NAMESPACE) {
      const start = i + 1;
      while (true) {
        i = i + 1;
        const c = socket_io_packet.raw(i, 1);
        if (c == SOCKET_IO_END_OF_NAMESPACE) {
          break;
        }
        if (i == socket_io_packet.len()) {
          break;
        }
      }
      packet.set("nsp", socket_io_packet.range(start, i - start));
    }
    if (i + 1 != socket_io_packet.len()) {
      const next = socket_io_packet.raw(i + 1, 1);
      if (next === tostring(tonumber(next))) {
        const start = i + 1;
        while (true) {
          i = i + 1;
          if (i == socket_io_packet.len()) {
            break;
          }
          const c = socket_io_packet.raw(i, 1);
          if (c !== tostring(tonumber(c))) {
            i = i - 1;
            break;
          }
        }
        packet.set("id", socket_io_packet.range(start, i - start + 1));
      }
    }
    if (i + 1 !== socket_io_packet.len()) {
      i = i + 1;
      packet.set(
        "data",
        socket_io_packet.range(
          i,
          socket_io_packet.len() - i
        )
      );
    }
    socket_io_tree.add(
      socketio_type_field,
      packet.get("type"),
      SOCKET_IO_TYPE_MAP.get(packet.get("type").raw())
    );
    if (packet.has("attachments")) {
      socket_io_tree.add(
        socketio_attachments_field,
        packet.get("attachments")
      );
    }
    if (packet.has("nsp")) {
      socket_io_tree.add(
        socketio_nsp_field,
        packet.get("nsp")
      );
    } else {
      socket_io_tree.add(
        socketio_nsp_field,
        SOCKET_IO_NAMESPACE_MAIN
      );
    }
    if (packet.has("id")) {
      socket_io_tree.add(
        socketio_id_field,
        packet.get("id")
      );
    }
    if (packet.has("data")) {
      socket_io_tree.add(
        socketio_data_field,
        packet.get("data"),
        packet.get("data").raw()
      );
    }
  }


  const ENGINE_IO_PAYLOAD_SEPARATOR = "\x1e"
  const ENGINE_IO_TYPE_OPEN = "0"
  const ENGINE_IO_TYPE_CLOSE = "1"
  const ENGINE_IO_TYPE_PING = "2"
  const ENGINE_IO_TYPE_PONG = "3"
  const ENGINE_IO_TYPE_MESSAGE = "4"
  const ENGINE_IO_TYPE_UPGRADE = "5"
  const ENGINE_IO_TYPE_NOOP = "6"
  const ENGINE_IO_TYPE_BINARY_MESSAGE = "b"
  const ENGINE_IO_TYPE_MAP = new LuaTable<string, string>();
  ENGINE_IO_TYPE_MAP.set(ENGINE_IO_TYPE_OPEN, "open");
  ENGINE_IO_TYPE_MAP.set(ENGINE_IO_TYPE_CLOSE, "close");
  ENGINE_IO_TYPE_MAP.set(ENGINE_IO_TYPE_PING, "ping");
  ENGINE_IO_TYPE_MAP.set(ENGINE_IO_TYPE_PONG, "pong");
  ENGINE_IO_TYPE_MAP.set(ENGINE_IO_TYPE_MESSAGE, "message");
  ENGINE_IO_TYPE_MAP.set(ENGINE_IO_TYPE_UPGRADE, "upgrade");
  ENGINE_IO_TYPE_MAP.set(ENGINE_IO_TYPE_NOOP, "noop");
  ENGINE_IO_TYPE_MAP.set(ENGINE_IO_TYPE_BINARY_MESSAGE, "binary message");

  const engineio_field = ProtoField.none("socketio_engineio.engineio", "Engine.IO");
  const engineio_binary_message_field = ProtoField.bytes("socketio_engineio.engineio.binary_message", "binary message");
  const engineio_type_field = ProtoField.string("socketio_engineio.engineio.type", "type", base.UNICODE);
  const engineio_data_field = ProtoField.string("socketio_engineio.engineio.data", "data", base.UNICODE);
  const engineio_decoded_data_field = ProtoField.bytes("socketio_engineio.engineio.decoded_data", "decoded data");


  function process_engine_io_packet(this: void, tree: TreeItem, engine_io_packet: TvbRange, is_binary: boolean, process_payload: typeof process_socket_io_packet): void {
    const engine_io_tree = tree.add(
      engineio_field,
      engine_io_packet
    );
    if (is_binary) {
      engine_io_tree.add(
        engineio_binary_message_field,
        engine_io_packet
      );
      process_payload(tree, engine_io_packet, true);
      return;
    }
    const packet = new LuaTable<string, TvbRange>();
    packet.set("type", engine_io_packet.range(0, 1));

    if (1 < engine_io_packet.len()) {
      packet.set(
        "data",
        engine_io_packet.range(
          1,
          engine_io_packet.len() - 1
        )
      );
    }
    if (!ENGINE_IO_TYPE_MAP.has(packet.get("type").raw())) {
      throw "unknown packet type";
    }
    if (packet.get("type").raw() == ENGINE_IO_TYPE_BINARY_MESSAGE) {
      packet.set(
        "decoded_data",
        packet.get("data").bytes().base64_decode().tvb("decoded_data").range()
      );
    }

    engine_io_tree.add(
      engineio_type_field,
      packet.get("type"),
      ENGINE_IO_TYPE_MAP.get(packet.get("type").raw())
    );
    if (packet.has("data")) {
      engine_io_tree.add(
        engineio_data_field,
        packet.get("data")
      );
    }
    if (packet.has("decoded_data")) {
      engine_io_tree.add(
        engineio_decoded_data_field,
        packet.get("decoded_data")
      );
    }
    if (packet.get("type").raw() == ENGINE_IO_TYPE_MESSAGE) {
      process_payload(
        tree,
        packet.get("data"),
        false
      )

    }
    if (packet.get("type").raw() == ENGINE_IO_TYPE_BINARY_MESSAGE) {
      process_payload(
        tree,
        packet.get("decoded_data"),
        true
      );
    }
  }
  const http = Field.new("http");
  const http_request_uri = Field.new("http.request.uri");
  const http_request_method = Field.new("http.request.method");
  const http_response_for_uri = Field.new("http.response_for.uri");
  const http_response_line = Field.new("http.response.line");

  const websocket = Field.new("websocket")

  const field_data_text_lines = Field.new("data-text-lines");
  const field_data = Field.new("data");

  const socketio_engineio_proto = Proto.new("socketio_engineio", "Socket.IO and Engine.IO PostDissector");

  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    engineio_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    engineio_binary_message_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    engineio_type_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    engineio_data_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    engineio_decoded_data_field
  );

  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    socketio_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    socketio_binary_data_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    socketio_type_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    socketio_attachments_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    socketio_nsp_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    socketio_id_field
  );
  socketio_engineio_proto.fields.set(
    socketio_engineio_proto.fields.length() + 1,
    socketio_data_field
  );

  socketio_engineio_proto.init = function () {

  }
  socketio_engineio_proto.dissector = function (this: void, buffer: Tvb, pinfo: Pinfo, tree: TreeItem): number {
    const [info_http] = http();
    const [info_http_request_uri] = http_request_uri();
    const [info_http_request_method] = http_request_method();
    const [info_http_response_for_uri] = http_response_for_uri();
    const [info_http_response_line] = http_response_line();
    const [info_websocket] = websocket();

    if (!info_http && !info_websocket) {
      // other protocol
      return 0;
    }
    if (info_http_request_uri != null) {
      if (!is_socket_io_polling_uri(info_http_request_uri.value as any as string)) {
        // other http request
        return 0;
      } else if (info_http_request_method.value == "GET") {
        // skip http get request
        return 0;
      }
    }
    if (info_http_response_for_uri != null) {
      if (!is_socket_io_polling_uri(info_http_response_for_uri.value as any as string)) {
        // other http response
        return 0;
      } else if (GRegex.match(info_http_response_line.value as any as string, "Content-Type: text\\/html")) {
        // skip post response
        return 0;
      }

    }

    let binary_payload: TvbRange | null = null;
    let text_payload: TvbRange | null = null;
    let payload: TvbRange | null = null;

    const [info_field_data] = field_data();
    if (info_field_data != null) {
      binary_payload = (info_field_data.value as any as ByteArray).tvb("binary_payload").range();
      payload = binary_payload;
    }

    const [info_field_data_text_lines] = field_data_text_lines();
    if (info_field_data_text_lines != null) {
      text_payload = (info_field_data_text_lines.value as any as ByteArray).tvb("text_payload").range();
      payload = text_payload;
    }

    if (payload == null) {
      return 0;
    }
    const proto_tree = tree.add(
      socketio_engineio_proto,
      payload
    );
    if (text_payload != null) {
      const engine_io_packet_list = separate_tvb_range(text_payload, ENGINE_IO_PAYLOAD_SEPARATOR);
      for (let i = 1; i <= engine_io_packet_list.length(); i++) {
        const engine_io_packet = engine_io_packet_list.get(i);
        process_engine_io_packet(proto_tree, engine_io_packet, false, process_socket_io_packet)
      }
    } else if (binary_payload != null) {
      const engine_io_packet = binary_payload
      process_engine_io_packet(proto_tree, engine_io_packet, true, process_socket_io_packet)
    }


    return 0;
  }
  register_postdissector(socketio_engineio_proto);

}
