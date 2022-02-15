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
    console.log("send welcome to new client");
    socket.emit("welcome");
    socket.on("callback me", (data: string, ack: (data: string) => void) => {
      ack(data);
    });
  });

  for(let transport of ["polling","websocket"]){
    console.log(`new socket transport: ${transport}`);
    const url = `ws://localhost:${PORT}${NSP_CHAT}`;
    const clientSocket = ioc(url, {
      forceNew: true,
      transports: [transport],
    });
    await new Promise<void>((resolve,reject)=>{
      clientSocket.on("connect",()=>{
        console.log("connect");
        resolve();
      })
    });

    await new Promise<void>((resolve,reject)=>{
      console.log("waiting for upgrade");
      setTimeout(resolve,100);
    });

    console.log("callback me hello");
    clientSocket.emit("callback me","hello",(data:string)=>{
      console.log(`callbacked: ${data}`);
    });
    console.log("callback me binary 010203");
    const sendingData=Uint8Array.from([1,2,3]);
    clientSocket.emit("callback me",{
      sendingData,
    },(data:Object)=>{
      console.log(`callbacked: ${JSON.stringify(data)}`);
    });

    await new Promise<void>((resolve,reject)=>{
      console.log("waiting some events");
      setTimeout(resolve,100);
    });
    clientSocket.close();
  }


  sio.close();

}
mainAsync();