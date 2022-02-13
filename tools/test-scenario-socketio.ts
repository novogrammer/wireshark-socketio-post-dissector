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
  const namespaceChat = sio.of(NSP_CHAT);
  namespaceChat.on("connection",(socket:Socket)=>{
    console.log("send hello to new client");
    socket.emit("hello");
    socket.on("callback me", (data: string, ack: (data: string) => void) => {
      ack(data);
    });
  })


  const url = `ws://localhost:${PORT}${NSP_CHAT}`;
  const clientSocket = ioc(url, { forceNew: true });
  await new Promise<void>((resolve,reject)=>{
    clientSocket.on("connect",()=>{
      console.log("connect");
      resolve();
    })
  });
  await new Promise<void>((resolve,reject)=>{
    console.log("waiting for upgrade");
    setTimeout(resolve,0);
  });

  console.log("callback me hello");
  clientSocket.emit("callback me","hello",(data:string)=>{
    console.log(`callbacked: ${data}`);
  });
  console.log("callback me world");
  clientSocket.emit("callback me","world",(data:string)=>{
    console.log(`callbacked: ${data}`);
  });
  console.log("sending some binary");
  const sendingData=Uint8Array.from([0,1,2]);
  clientSocket.emit("some binary",{
    sendingData,
  });
  await new Promise<void>((resolve,reject)=>{
    console.log("waiting some events");
    setTimeout(resolve,1000);
  });

  clientSocket.close();
  sio.close();

}
mainAsync();