#include "SocketUtils.h"    // Socket, ServerSocket, and SocketException
#include <iostream>         // cerr and cout
#include <cstdlib>          // atoi()

using namespace std;

// initial receive buffer size
const unsigned int RCVBUFSIZE = 32;

// TCP client
void HandleTCPClient(TCPSocket *sock);

int main(int argc, char *argv[])
{
    if (argc != 2)
    { // call arity
        cerr << "Usage: " << argv[0] << " <Server Port>" << endl;
        exit(1);
    }

    unsigned short echoServPort = atoi(argv[1]); // argv[1] == local port

    try
    {
        TCPSocketServer servSock(echoServPort); // socket server object

        // run forever
        for (;;)
        {                                      
            // Wait for client connection 
            HandleTCPClient(servSock.accept());
        }
    }
    catch (SocketException &e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    // dead

    return 0;
}

// TCP client
void HandleTCPClient(TCPSocket *sock)
{
    cout << "Handling client ";
    try
    {
        cout << sock->getRemoteAddress() << ":";
    }
    catch (SocketException e)
    {
        cerr << "Unable to get foreign address" << endl;
    }
    try
    {
        cout << sock->getRemotePort();
    }
    catch (SocketException e)
    {
        cerr << "Unable to get foreign port" << endl;
    }
    cout << endl;

    // send inbound string and receive again until transmission ends
    char echoBuffer[RCVBUFSIZE];
    int recvMsgSize;
    while ((recvMsgSize = sock->receive(echoBuffer, RCVBUFSIZE)) > 0)
    {   // 0 == end of transmission
        // echo message to client
        sock->send(echoBuffer, recvMsgSize);
    }
    // clean up
    delete sock;
}