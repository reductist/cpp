/**
 * C++ socket utilities
 * Reference: https://cs.baylor.edu/~donahoo/practical/CSockets/practical/PracticalSocket.h
*/

#ifndef __SOCKETUTILS_INCLUDED__
#define __SOCKETUTILS_INCLUDED__

#include <string>
#include <exception>

using namespace std;

class SocketException : public std::exception
{
public:
    /**
     * Custom SocketException message constructor.
     * @param message   exception message
     * @param sysMsg    true to postfix strerror(errno) after custom message
     */
    SocketException(const std::string &message, bool sysMsg = false) throw();

    //  Ensure that no exceptions throw.
    ~SocketException() throw();

    /**
     *   Get exception.
     *   @return exception message
     */
    const char *what() const throw();

private:
    std::string userMessage;
};


/**
 * Socket base class
*/
class Socket
{
public:
    /**
     * Close and deallocate socket.
     */
    ~Socket();

    /**
     * Address getter.
     * @return socket current address
     * @exception SocketException on failure
     */
    std::string getAddress() throw(SocketException);

    /**
     * Port getter.
     * @return assigned current port
     * @exception SocketException on failure
     */
    unsigned short getPort() throw(SocketException);

    /**
     * Set port only.
     * @param port local port
     * @exception SocketException on failure
     */
    void setPort(unsigned short port) throw(SocketException);

    /**
     * Set both port and address, using random port if not provided.
     * @param address local address
     * @param port local port
     * @exception SocketException on failure
     */
    void setAddressAndPort(
      const std::string &address,
      unsigned short port = 0
    ) throw(SocketException);

    /**
     *   Unload Windows WinSock DLLs, empty function on other platforms.
     *   @param buffer buffer to receive the data
     *   @param bufferLen maximum number of buffer bytes to read
     *   @return number of bytes read; 0 on EOF | -1 on error
     *   @exception SocketException thrown on failure
     */
    static void cleanUp() throw(SocketException);

    /**
     *   Resolve protocol service to corresponding port number.
     *   @param service service to resolve (ex: "http")
     *   @param protocol protocol of service to resolve (default = "tcp")
     */
    static unsigned short resolveService(
        const std::string &service,
        const std::string &protocol = "tcp"
    );

private:
    // Prohibit user value semantics
    Socket(const Socket &sock);
    void operator=(const Socket &sock);

protected:
    // Socket descriptor
    int socketDescriptor;
    Socket(int type, int protocol) throw(SocketException);
    Socket(int socketDescriptor);
};


/**
 * Socket capable of connecting, sending, and receiving.
 */
class ConnectedSocket : public Socket
{
public:
    /**
     * Connect to provided remote address and port.
     * @param remoteAddress remote address (IP or FQDN)
     * @param remotePort remote port
     * @exception SocketException thrown on connection failure
     */
    void connect(
        const std::string &remoteAddress,
        unsigned short remotePort
    ) throw(SocketException);
    
    /**
     * Write provided buffer to this socket. Call after connect(...).
     * @param buffer buffer to write
     * @param bufferLen number of bytes to write from buffer
     * @exception SocketException thrown on failure to send
     */
    void send(const void *buffer, int bufferLen) throw(SocketException);
    
    /**
     * Read bufferLen bytes into provided buffer from this socket.
     * @param buffer buffer to write
     * @param bufferLen max bytes to read into buffer
     * @return number of bytes read; 0 on EOF | -1 on error
     * @exception SocketException thrown on failure to read
     */
    int receive(void *buffer, int bufferLen) throw(SocketException);
    
    /**
     * Get remote address.
     * @return foreign address
     * @exception SocketException thrown on failure
     */
    std::string getRemoteAddress() throw(SocketException);

    /**
     * Get remote port.
     * @return remote port
     * @exception SocketException thrown on failure
     */
    unsigned short getRemotePort() throw(SocketException);

protected:
    ConnectedSocket(int type, int protocol) throw(SocketException);
    ConnectedSocket(int newConnSD);
};


/**
 * TCP socket.
 */
class TCPSocket : public ConnectedSocket
{
public:
    /**
     * Unconnected TCP socket constructor.
     * @exception SocketException thrown on constructor failure
     */
    TCPSocket() throw(SocketException);

    /**
     * Connected TCP socket constructor.
     * @param remoteAddress remote address (IP or FQDN)
     * @param remotePort remote port
     * @exception SocketException thrown on constructor failure
     */
    TCPSocket(
        const std::string &remoteAddress,
        unsigned short remotePort
    ) throw(SocketException);

private:
    /**
     * TCPSocketServer::accept() to establish TCPSocketServer connection.
     */
    friend class TCPSocketServer;
    TCPSocket(int newConnSD);
};


/**
 * TCP socket server.
 */
class TCPSocketServer : public Socket
{
public:
    /**
     * TCP socket server constructor by specifying port only.
     * Accepts connections over any interface/address.
     * @param port      server port; 0 to use port from system
     * @param queueLen  max outstanding connection request
     *                  queue length (default = 5)
     * @exception SocketException thrown on TCP socket server creation failure
     */
    TCPSocketServer(unsigned short port, int queueLen = 5)
        throw(SocketException);
    
    /**
     * TCP socket server constructor accepting inbound
     * connections by specifying port and address.
     * @param address server interface/address
     * @param port server port
     * @param queueLen  max outstanding connection request
     *                  queue length (default = 5)
     * @exception SocketException thrown on TCP socket server creation failure
     */
    TCPSocketServer(
        const std::string &address,
        unsigned short port,
        int queueLen = 5
    ) throw(SocketException);

    /**
     * Block until connection is established on this socket.
     * @return new connection socket
     * @exception SocketException thrown on new connection failure
     */
    TCPSocket *accept() throw(SocketException);

private:
    void setListen(int queueLen) throw(SocketException);
};


/**
 * UDP socket.
 */
class UDPSocket : public ConnectedSocket
{
public:
    /**
     * Unconnected UDP socket constructor.
     * @exception SocketException thrown on failure to create UDP socket
     */
    UDPSocket() throw(SocketException);

    /**
     * UDP socket constructor using specified port.
     * @param port local port
     * @exception SocketException thrown on failure to create UDP socket
     */
    UDPSocket(unsigned short port) throw(SocketException);

    /**
     * UDP socket constructor
     * @param address local address
     * @param port local port
     * @exception SocketException thrown on failure to create UDP socket
     */
    UDPSocket(
        const std::string &address,
        unsigned short port
    ) throw(SocketException);

    /**
     * Unset remote address and port.
     * @return true upon success
     * @exception SocketException thrown on failure to disconnect
     */
    void disconnect() throw(SocketException);

    /**
     * Send buffer via UDP datagram to remote address/port.
     * @param buffer buffer to write
     * @param bufferLen number of bytes to write
     * @param remoteAddress remote address (IP or FQDN)
     * @param remotePort remote port
     * @return true if UDP shipment succeeds
     * @exception SocketException thrown on failure to send
     */
    void sendDatagram(
        const void *buffer,
        int bufferLen,
        const std::string &destinationAddress,
        unsigned short destinationPort
    ) throw(SocketException);

    /**
     * Read bufferLen bytes from socket into buffer via UDP datagram.
     * @param buffer buffer to receive
     * @param bufferLen max bytes to receive
     * @param address datagram source address
     * @param port datagram source port
     * @exception SocketException thrown on failure to receive
     * @return number of bytes received; -1 on error
     */
     int receiveDatagram(
         void *buffer,
         int bufferLen,
         std::string &sourceAddress,
         unsigned short &sourcePort
    ) throw(SocketException);

    /**
     * Set multicast TTL.
     * @param multicastTTL multicast TTL
     * @exception SocketException thrown on failure to set TTL
     */
    void setMulticastTTL(unsigned char multicastTTL) throw(SocketException);

    /**
     * Join provided multicast group.
     * @param multicastGroup multicast group address
     * @exception SocketException thrown on failure to join
     */
    void joinMulticastGroup(const std::string &multicastGroup) throw(SocketException);

    /**
     * Leave provided multicast group.
     * @param multicastGroup multicast group address
     * @exception SocketException thrown on failure to leave group
     */
    void leaveMulticastGroup(const string &multicastGroup) throw(SocketException);

private:
    void setBroadcast();
};

#endif