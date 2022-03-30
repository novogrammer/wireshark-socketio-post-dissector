

# Wireshark Socket.IO and Engine.IO PostDissector

for Mac<br>
put `dist/socketio_engineio_proto.lua` in `~/.config/wireshark/plugins`

see also<br>
https://github.com/socketio/engine.io-protocol/<br>
https://github.com/socketio/socket.io-protocol/


inspired by https://github.com/ksmyth/wireshark-socket.io

## Run Test Scenario
see `tools/test-scenario-socketio.ts`

### Setup
```
$ npm install
```

### Run
```
$ npm run test-scenario-socketio
```