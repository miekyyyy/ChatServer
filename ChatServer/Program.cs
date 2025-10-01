using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using ChatServer;


    Server server = new Server();
    server.EncryptionBootUp();
    server.StartListening();
 
