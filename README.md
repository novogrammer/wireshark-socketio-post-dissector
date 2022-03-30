

# Wireshark Socket.IO and Engine.IO PostDissector

see also<br>
https://github.com/socketio/engine.io-protocol/<br>
https://github.com/socketio/socket.io-protocol/


inspired by https://github.com/ksmyth/wireshark-socket.io

## Install
for Mac<br>
put `dist/socketio_engineio_proto.lua` in `~/.config/wireshark/plugins`

## GPL license
I have chosen the GPL license to use the Wireshark Lua API.

see<br>
https://osqa-ask.wireshark.org/questions/12371/wireshark-plugin-and-gpl-license/<br>
https://wiki.wireshark.org/Lua/


## Setup for Developer

```
$ npm install
```

### Transpile Typescript To Lua
```
$ npm run build
```

### Run Test Scenario for Wireshark
```
$ npm run test-scenario-socketio
```