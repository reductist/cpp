/*
 * C++ socket utilities
 *  
 * References:
 *      https://cs.baylor.edu/~donahoo/practical/CSockets/practical/
 *      https://cs.baylor.edu/~donahoo/practical/CSockets/practical/PracticalSocket.cpp
 */

#include "SocketUtils.h"
#include <string.h>

// TODO: test on a Windows machine
#ifdef WIN32
    #include <winsock.h>
    typedef int socklen_t;
    typedef char raw_type;
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netinet/in.h>
    typedef void raw_type;
#endif

#include <errno.h>

using namespace std;

// TODO: test on a Windows machine
#ifdef WIN32
static bool initialized = false;
#endif


// SocketException
SocketException::SocketException(const string &message, bool sysMsg) throw() : userMessage(message)
{
    if (sysMsg)
    {
        userMessage.append(": ");
        userMessage.append(strerror(errno));
    }
}

SocketException::~SocketException() throw()
{
}

const char *SocketException::what() const throw()
{
    return userMessage.c_str();
}


// Full address from address & port
static void generateFullAddress(
    const std::string &address,
    unsigned short port,
    sockaddr_in &addr
)
{
    
    memset(&addr, 0, sizeof(addr)); // zero fill addr struct
    addr.sin_family = AF_INET;      // Internet address

    hostent *host;                  // resolve name

    if ((host = gethostbyname(address.c_str())) == NULL)
    {
        //strerror() doesn't work for gethostbyname()
        throw SocketException("Failed to resolve (gethostbyname())");
    }
    addr.sin_addr.s_addr = *((unsigned long *) host->h_addr_list[0]);

    // assign port in net byte order
    addr.sin_port = htons(port);
}


// Socket
Socket::Socket(int type, int protocol) throw(SocketException)
{
    // TODO: test on Windows machine
    #ifdef WIN32
        if (!initialized)
        {
            WORD wVersionRequested;
            WSADATA wsaData;

            wVersionRequested = MAKEWORD(2, 0);                 // Winsock v2.0
            if (WSAStartup(wVersionRequested, &wsaData) != 0)   // Load DLL
            {
                throw SocketException("Unable to load WinSock DLL");
            }
            initialized = true;
        }
    #endif

    // New socket
    if ((socketDescriptor = socket(PF_INET, type, protocol)) < 0)
    {
        throw SocketException("Failed to create socket (socket())", true);
    }
}

Socket::Socket(int socketDescriptor)
{
    this->socketDescriptor = socketDescriptor;
}

Socket::~Socket()
{
    // TODO: test on Windows machine
    #ifdef WIN32
        ::closesocket(socketDescriptor);
    #else
        ::close(socketDescriptor);
    #endif
    socketDescriptor = -1;
}

string Socket::getAddress() throw(SocketException)
{
    sockaddr_in address;
    unsigned int address_len = sizeof(address);

    if (getsockname(socketDescriptor, (sockaddr *) &address, (socklen_t *) &address_len) < 0)
    {
        throw SocketException("Failed to retrieve address (getsockname())", true);
    }
    return inet_ntoa(address.sin_addr);
}

void Socket::setPort(unsigned short port) throw(SocketException)
{
    sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = htons(port);

    if (bind(socketDescriptor, (sockaddr *) &address, sizeof(sockaddr_in)) < 0)
    {
        throw SocketException("Failed to set port (bind())", true);
    }
}

void Socket::setAddressAndPort(
    const std::string &address,
    unsigned short port
) throw(SocketException)
{
    sockaddr_in addr;
    generateFullAddress(address, port, addr);

    if (bind(socketDescriptor, (sockaddr *) &addr, sizeof(sockaddr_in)) < 0)
    {
        throw SocketException("Failed to set address and port (bind())", true);
    }
}

// TODO: test on Windows machine
void Socket::cleanUp() throw(SocketException)
{
    #ifdef WIN32
        if (WSACleanup() != 0)
        {
            throw SocketException("WSACleanup() failed");
        }
    #endif
}

unsigned short Socket::resolveService(
    const std::string &service,
    const std::string &protocol
)
{
    struct servent *serv;

    if ((serv = getservbyname(service.c_str(), protocol.c_str())) == NULL)
    {
        return atoi(service.c_str());   // service == port
    }
    else
    {
        return ntohs(serv->s_port);     // port by name, network byte order
    }
}

ConnectedSocket::ConnectedSocket(
    int type,
    int protocol
) throw(SocketException) : Socket(type, protocol)
{
}

ConnectedSocket::ConnectedSocket(
    int newConnSD
) : Socket(newConnSD)
{
}

void ConnectedSocket::connect(
    const std::string &remoteAddress,
    unsigned short remotePort
)
{
    sockaddr_in destAddr;
    generateFullAddress(remoteAddress, remotePort, destAddr);

    // attempt remote port connection
    if (::connect(socketDescriptor, (sockaddr *) &destAddr, sizeof(destAddr)) < 0)
    {
        throw SocketException("Failed to connect (connect())", true);
    }
}

void ConnectedSocket::send(
    const void *buffer,
    int bufferLen
) throw(SocketException)
{
    if (::send(
        socketDescriptor,
        (raw_type *) buffer,
        bufferLen,
         0
        ) < 0
    )
    {
        throw SocketException("Failed to send (send())", true);
    }
}

int ConnectedSocket::receive(void *buffer, int bufferLen) throw(SocketException)
{
    int rtn;
    if ((rtn = ::recv(socketDescriptor, (raw_type *) buffer, bufferLen, 0)) < 0)
    {
        throw SocketException("Failed to receive (receive())", true);
    }
}

std::string ConnectedSocket::getRemoteAddress() throw(SocketException)
{
    sockaddr_in address;
    unsigned int address_len = sizeof(address);

    if (getpeername(socketDescriptor, (sockaddr *) &address, (socklen_t *) &address_len) < 0)
    {
        throw SocketException("Failed to retrieve remote address (getpeername())", true);
    }
    return inet_ntoa(address.sin_addr);
}

unsigned short ConnectedSocket::getRemotePort() throw(SocketException)
{
    sockaddr_in address;
    unsigned int address_len = sizeof(address);

    if (getpeername(socketDescriptor, (sockaddr *) &address, (socklen_t *) &address_len) < 0)
    {
        throw SocketException("Failed to retrieve remote port (getpeername())", true);
    }
    return ntohs(address.sin_port);
}


// TCPSocket
TCPSocket::TCPSocket() throw(
    SocketException
) : ConnectedSocket(
    SOCK_STREAM,
    IPPROTO_TCP
)
{
}

TCPSocket::TCPSocket(
    const std::string &remoteAddress,
    unsigned short remotePort
) throw(SocketException) : ConnectedSocket(
    SOCK_STREAM,
    IPPROTO_TCP
)
{
    connect(remoteAddress, remotePort);
}

TCPSocket::TCPSocket(int newConnSD) : ConnectedSocket(newConnSD)
{
}


// TCPSocketServer
TCPSocketServer::TCPSocketServer(
    unsigned short port,
    int queueLen
) throw(SocketException) : Socket(SOCK_STREAM, IPPROTO_TCP)
{
    setPort(port);
    setListen(queueLen);
}

TCPSocketServer::TCPSocketServer(
    const std::string &address,
    unsigned short port,
    int queueLen
) throw(SocketException) : Socket(SOCK_STREAM, IPPROTO_TCP)
{
    setAddressAndPort(address, port);
    setListen(queueLen);
}

TCPSocket *TCPSocketServer::accept() throw(SocketException)
{
    int newConnSD;
    if ((newConnSD = ::accept(socketDescriptor, NULL, 0)) < 0)
    {
        throw SocketException("Failed to accept inbound request (accept())", true);
    }
}

void TCPSocketServer::setListen(int queueLen) throw(SocketException)
{
    if (listen(socketDescriptor, queueLen) < 0)
    {
        throw SocketException("Failed to set listening socket (listen())", true);
    }
}


// UDPSocket
UDPSocket::UDPSocket() throw(SocketException) : ConnectedSocket(
    SOCK_DGRAM,
    IPPROTO_UDP
)
{
    setBroadcast();
}

UDPSocket::UDPSocket(unsigned short port) throw(SocketException) : ConnectedSocket(
    SOCK_DGRAM,
    IPPROTO_UDP
)
{
    setPort(port);
    setBroadcast();
}

UDPSocket::UDPSocket(
    const std::string &address,
    unsigned short port
) throw(SocketException) : ConnectedSocket(
    SOCK_DGRAM,
    IPPROTO_UDP
)
{
    setAddressAndPort(address, port);
    setBroadcast;
}

void UDPSocket::setBroadcast()
{
    // Failure will throw on send to allow system continuation
    int broadcastPermission = 1;
    setsockopt(
        socketDescriptor,
        SOL_SOCKET,
        SO_BROADCAST,
        (raw_type *) &broadcastPermission,
        sizeof(broadcastPermission)
    );
}

void UDPSocket::disconnect() throw(SocketException)
{
    sockaddr_in nullAddress;
    memset(&nullAddress, 0, sizeof(nullAddress));
    nullAddress.sin_family = AF_UNSPEC;

    // attempt disconnect
    if (::connect(
        socketDescriptor,
        (sockaddr *) &nullAddress,
        sizeof(nullAddress)
    ) < 0)
{
    #ifdef WIN32
        if (errno != WSAEAFNOSUPPORT) {
    #else
        if (errno != EAFNOSUPPORT) {
    #endif
        throw SocketException("Disconnect failed (connect())", true);
    }}
}

void UDPSocket::sendDatagram(
    const void *buffer,
    int bufferLen,
    const std::string &remoteAddress,
    unsigned short remotePort
) throw(SocketException)
{
    sockaddr_in destinationAddress;
    generateFullAddress(remoteAddress, remotePort, destinationAddress);

    // buffer as message
    if (
        sendto(
            socketDescriptor,
            (raw_type *) buffer,
            bufferLen,
            0,
            (sockaddr *) &destinationAddress,
            sizeof(destinationAddress)
        ) != bufferLen
    )
    {
        throw SocketException("Failed to send (sendto())", true);
    }
}


int UDPSocket::receiveDatagram(
    void *buffer,
    int bufferLen,
    string &sourceAddress,
    unsigned short &sourcePort
) throw(SocketException)
{
    sockaddr_in clntAddr;
    socklen_t addrLen = sizeof(clntAddr);
    int rtn;
    if (
        (
            rtn = recvfrom(
                socketDescriptor,
                (raw_type *) buffer,
                bufferLen,
                0, 
                (sockaddr *) &clntAddr,
                (socklen_t *) &addrLen
            )
        ) < 0
    )
    {
        throw SocketException("Failed to receive datagram (recvfrom())", true);
    }
    sourceAddress = inet_ntoa(clntAddr.sin_addr);
    sourcePort = ntohs(clntAddr.sin_port);

    return rtn;
}

void UDPSocket::setMulticastTTL(
    unsigned char multicastTTL
) throw(SocketException)
{
    if (
        setsockopt(
            socketDescriptor,
            IPPROTO_IP,
            IP_MULTICAST_TTL, 
            (raw_type *) &multicastTTL,
            sizeof(multicastTTL)
        ) < 0
    )
    {
        throw SocketException("Failed to set multicast TTL (setsockopt())", true);
    }
}

void UDPSocket::joinMulticastGroup(
    const std::string &multicastGroup
) throw(SocketException)
{
    struct ip_mreq multicastRequest;

    multicastRequest.imr_multiaddr.s_addr = inet_addr(multicastGroup.c_str());
    multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);
    if (
        setsockopt(
            socketDescriptor,
            IPPROTO_IP,
            IP_ADD_MEMBERSHIP, 
            (raw_type *) &multicastRequest, 
            sizeof(multicastRequest)
        ) < 0
    )
    {
        throw SocketException("Failed to join multicast group (setsockopt())", true);
    }
}

void UDPSocket::leaveMulticastGroup(
    const std::string &multicastGroup
) throw(SocketException)
{
    struct ip_mreq multicastRequest;

    multicastRequest.imr_multiaddr.s_addr = inet_addr(multicastGroup.c_str());
    multicastRequest.imr_interface.s_addr = htonl(INADDR_ANY);
    if (
        setsockopt(
            socketDescriptor,
            IPPROTO_IP,
            IP_DROP_MEMBERSHIP, 
            (raw_type *) &multicastRequest, 
            sizeof(multicastRequest)
        ) < 0
    )
    {
        throw SocketException("Multicast group leave failed (setsockopt())", true);
    }
}