import { Server, Socket, Namespace } from "socket.io";
import { createServer } from "http";
import { io as ioc, Socket as ClientSocket } from "socket.io-client";

const PORT = 3000;
const NSP_CHAT = "/chat"


async function mainAsync() {
  console.log("initialize");
  const httpServer = createServer();
  const sio = new Server(httpServer);

  await new Promise<void>((resolve,reject)=>{
    httpServer.listen(PORT,resolve);
  });
  console.log("listening");
  sio.of(NSP_CHAT);
  const url = `ws://localhost:${PORT}${NSP_CHAT}`;
  const clientSocket = ioc(url, { forceNew: true });
  await new Promise<void>((resolve,reject)=>{
    clientSocket.on("connect",()=>{
      console.log("connect");
      setTimeout(resolve,500);
    })
  });
  clientSocket.close();
  sio.close();

}
mainAsync();