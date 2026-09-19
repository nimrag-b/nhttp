#include "nhttp.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <ws2tcpip.h>
#define SECURITY_WIN32
#include <security.h>
#include <schannel.h>
#include <shlwapi.h>


#include <fstream>
#include <sstream>

#include <algorithm>


#pragma comment (lib, "Ws2_32.lib")
//#pragma comment (lib, "Mswsock.lib")
//#pragma comment (lib, "AdvApi32.lib")
#pragma comment (lib, "secur32.lib")

#define TLS_MAX_PACKET_SIZE (16384+512)


namespace nhttp {


bool connection::connect(const char* url, short port, bool nonblocking) {


    _hostname = url;

    _nonblocking = nonblocking;

    addrinfo* ptr;
    addrinfo* result;
    addrinfo hints;



    ZeroMemory(&hints, sizeof(hints));
    hints.ai_flags = AI_CANONNAME;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portstr[64];
    snprintf(portstr, 64, "%d", port);

    int iresult = getaddrinfo(url, portstr, &hints, &result);

    if (iresult != 0) {

        std::stringstream err;
        err << "getaddrinfo failed with error: " << gai_strerrorA(iresult) << std::endl;
        std::cout << err.str();

        return false;
    }


    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        sock = ::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock == INVALID_SOCKET) {
            std::stringstream err;
            err << "socket failed to connect with error: " << WSAGetLastError() << std::endl;
            std::cout << err.str();

            return false;
        }

        iresult = ::connect(sock, ptr->ai_addr, ptr->ai_addrlen);

        if (iresult == SOCKET_ERROR) {
            closesocket(sock);
            sock = INVALID_SOCKET;
            continue;
        }
        break;
    }


    if (sock == INVALID_SOCKET) {
        std::stringstream err;
        err << "Unable to connect to server" << std::endl;
        std::cout << err.str();
        freeaddrinfo(result);
        return false;
    }

    set_nonblocking(nonblocking);

    sockaddr_in* addr_in = (sockaddr_in*)ptr->ai_addr;


    char s[INET_ADDRSTRLEN];
    s[0] = 0;

    inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);


    //std::cout << "Connected to host '" << url << ":" << port << "' (" << s << ")" << std::endl;
    freeaddrinfo(result);


    _open = true;


    return true;

}

bool connection::check_is_blocking() {
    int r = 0;
    char b[1];
    r = recv(sock, b, 0, 0);
    if (r == 0)
        return true;
    else if (r == -1 && GetLastError() == WSAEWOULDBLOCK)
        return false;
    return false; /* In  case it is a connection socket (TCP) and it is not in connected state you will get here 10060 */
}

void connection::set_nonblocking(bool value)
{
    _nonblocking = value;
    // enable non-blocking
    u_long iMode = _nonblocking ? 1 : 0;

    int iresult = ioctlsocket(sock, FIONBIO, &iMode);
    if (iresult != NO_ERROR) {
        std::stringstream err;
        err << "ioctlsocket failed with error: " << iresult << std::endl;
        std::cout << err.str();

        return;
    }

}

int connection::send(std::string msg) {

    int iresult;

    iresult = ::send(sock, msg.c_str(), msg.size(), 0);

    if (iresult == SOCKET_ERROR) {
        std::cout << "send failed with error: " << WSAGetLastError() << std::endl;
        close();
        return -1;
    }
    return 0;
}

int connection::receive(char* buf, int len) {
    int iresult;

    iresult = ::recv(sock, buf, len, 0);
    if (iresult > 0) {
        return iresult;
    }
    else if (iresult == 0) {
        std::cout << "Connection closed" << std::endl;
        close();
        return 0;
    }
    else {
        int lasterr = WSAGetLastError();

        if (_nonblocking && lasterr == WSAEWOULDBLOCK) {
            return 0;
        }

        std::cout << "recv failed with error: " << lasterr << std::endl;
        return iresult;
    }
}




inline void connection::close() {
    closesocket(sock);
    _open = false;
    sock = INVALID_SOCKET;
}

conn_err tls_socket::tls_connect() {

    // initialize schannel
    {
        SCHANNEL_CRED cred = { 0 };
        cred.dwVersion = SCHANNEL_CRED_VERSION;
        cred.dwFlags = SCH_USE_STRONG_CRYPTO
            | SCH_CRED_AUTO_CRED_VALIDATION
            | SCH_CRED_NO_DEFAULT_CREDS;
        cred.grbitEnabledProtocols = SP_PROT_TLS1_2;

        if (AcquireCredentialsHandleA(NULL, (LPSTR)UNISP_NAME_A, SECPKG_CRED_OUTBOUND, NULL, &cred, NULL, NULL, &tlshandle, NULL) != SEC_E_OK)
        {
            con.close();
            return conn_err::TLS_FAILURE;
        }
    }

    // tls handshake

    // 1 - InitializeSecurityContext

    CtxtHandle* context = 0;

    conn_err iresult = conn_err::OK;

    char* tls_buffer = new char[TLS_MAX_PACKET_SIZE];
    int tls_received = 0;

    while (1) {

        SecBuffer inbuffers[2] = { 0 };
        inbuffers[0].BufferType = SECBUFFER_TOKEN;
        inbuffers[0].pvBuffer = tls_buffer;
        inbuffers[0].cbBuffer = tls_received;
        inbuffers[1].BufferType = SECBUFFER_EMPTY;

        SecBuffer outbuffers[1] = { 0 };
        outbuffers[0].BufferType = SECBUFFER_TOKEN;

        SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
        SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };

        DWORD flags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;

        SECURITY_STATUS sec = InitializeSecurityContextA(
            &tlshandle,
            context,
            context ? NULL : (SEC_CHAR*)con.hostname().c_str(),
            flags,
            0,
            0,
            context ? &indesc : NULL,
            0,
            context ? NULL : &tlscontext,
            &outdesc,
            &flags,
            NULL);

        context = &tlscontext;


        if (inbuffers[1].BufferType == SECBUFFER_EXTRA) {

            MoveMemory(tls_buffer, tls_buffer + (tls_received - inbuffers[1].cbBuffer), inbuffers[1].cbBuffer);
            tls_received = inbuffers[1].cbBuffer;
        }
        else {
            tls_received = 0;
        }

        if (sec == SEC_E_OK) {
            //tls handshake complete
            break;
        }
        else if (sec == SEC_I_INCOMPLETE_CREDENTIALS) {

            //client certificate not supported
            iresult = conn_err::TLS_FAILURE;
            break;
        }
        else if (sec == SEC_I_CONTINUE_NEEDED) {

            char* buffer = (char*)outbuffers[0].pvBuffer;
            int size = outbuffers[0].cbBuffer;

            while (size != 0) {
                int d = ::send(con.socket(), buffer, size, 0);
                if (d <= 0) break;
                size -= d;
                buffer += d;
            }

            FreeContextBuffer(outbuffers[0].pvBuffer);
            if (size != 0) {
                //failed to send data
                iresult = conn_err::TLS_FAILURE;
                break;
            }

        }
        else if (sec != SEC_E_INCOMPLETE_MESSAGE) {
            //dont handle yet
            iresult = conn_err::TLS_FAILURE;
            break;
        }


        if (tls_received >= TLS_MAX_PACKET_SIZE) {
            //too much data in buffer
            iresult = conn_err::TLS_FAILURE;
            break;
        }

        int r = recv(con.socket(), tls_buffer + tls_received, TLS_MAX_PACKET_SIZE - tls_received, 0);
        if (r == 0) {
            //disconnected
            delete[] tls_buffer;
            return conn_err::SOCKET_ERR;
        }
        else if (r < 0) {
            std::cout << "TLS handshake recv error: " << WSAGetLastError() << std::endl;
            iresult = conn_err::SOCKET_ERR;
            break;
        }
        tls_received += r;
    }

    if (iresult != conn_err::OK) {
        DeleteSecurityContext(context);
        FreeCredentialsHandle(&tlshandle);
        delete[] tls_buffer;
        return iresult;
    }

    //std::cout << "tls handshake success" << std::endl;


    QueryContextAttributes(&tlscontext, SECPKG_ATTR_STREAM_SIZES, &sizes);
    delete[] tls_buffer;

    _tls_buffer = new char[max_packet_size()];

    return conn_err::OK;
}

void tls_socket::tls_close()
{
    DWORD type = SCHANNEL_SHUTDOWN;

    SecBuffer inbuffers[1];
    inbuffers[0].BufferType = SECBUFFER_TOKEN;
    inbuffers[0].pvBuffer = &type;
    inbuffers[0].cbBuffer = sizeof(type);

    SecBufferDesc indesc = { SECBUFFER_VERSION, ARRAYSIZE(inbuffers), inbuffers };
    ApplyControlToken(&tlscontext, &indesc);

    SecBuffer outbuffers[1];
    outbuffers[0].BufferType = SECBUFFER_TOKEN;

    SecBufferDesc outdesc = { SECBUFFER_VERSION, ARRAYSIZE(outbuffers), outbuffers };
    DWORD flags = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    if (InitializeSecurityContextA(&tlshandle, &tlscontext, NULL, flags, 0, 0, &outdesc, 0, NULL, &outdesc, &flags, NULL) == SEC_E_OK)
    {
        char* buffer = (char*)outbuffers[0].pvBuffer;
        int size = outbuffers[0].cbBuffer;
        while (size != 0)
        {
            int d = send(con.socket(), buffer, size, 0);
            if (d <= 0)
            {
                // ignore any failures socket will be closed anyway
                break;
            }
            buffer += d;
            size -= d;
        }
        FreeContextBuffer(outbuffers[0].pvBuffer);
    }

    DeleteSecurityContext(&tlscontext);
    FreeCredentialsHandle(&tlshandle);
}

int tls_socket::tls_send(std::string msg) {
    const char* buffer = msg.c_str();
    size_t size = msg.size();

    char* wbuffer = new char[TLS_MAX_PACKET_SIZE];
    while (size != 0) {
        int use = std::min(size, (size_t)sizes.cbMaximumMessage);


        SecBuffer buffers[3];
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = wbuffer;
        buffers[0].cbBuffer = sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = wbuffer + sizes.cbHeader;
        buffers[1].cbBuffer = use;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = wbuffer + sizes.cbHeader + use;
        buffers[2].cbBuffer = sizes.cbTrailer;

        CopyMemory(buffers[1].pvBuffer, buffer, use);

        SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };
        SECURITY_STATUS sec = EncryptMessage(&tlscontext, 0, &desc, 0);
        if (sec != SEC_E_OK) {
            delete[] wbuffer;
            return -1;
        }

        int total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        int sent = 0;
        while (sent != total) {
            int d = ::send(con.socket(), wbuffer + sent, total - sent, 0);
            if (d <= 0) {
                //error sending data or disconnected
                delete[] wbuffer;
                return -1;
            }
            sent += d;
        }

        buffer = buffer + use;
        size -= use;
    }
    delete[] wbuffer;
    return 0;
}

int tls_socket::tls_receive(char* buf, int len) {

    int result = 0;

    while (len != 0)
    {
        if (_decrypted_buffer)
        {
            // if there is decrypted data available, then use it as much as possible
            int use = std::min(len, _decrypted_buflen);
            CopyMemory(buf, _decrypted_buffer, use);
            buf = (char*)buf + use;
            len -= use;
            result += use;

            if (use == _decrypted_buflen)
            {
                // all decrypted data is used, remove ciphertext from incoming buffer so next time it starts from beginning
                MoveMemory(_tls_buffer, _tls_buffer + _tls_used, _tls_buflen - _tls_used);
                _tls_buflen -= _tls_used;
                _tls_used = 0;
                _decrypted_buflen = 0;
                _decrypted_buffer = NULL;
            }
            else
            {
                _decrypted_buflen -= use;
                _decrypted_buffer += use;
            }
        }
        else
        {
            // if any ciphertext data available then try to decrypt it
            if (_tls_buflen != 0)
            {
                SecBuffer buffers[4];

                buffers[0].BufferType = SECBUFFER_DATA;
                buffers[0].pvBuffer = _tls_buffer;
                buffers[0].cbBuffer = _tls_buflen;
                buffers[1].BufferType = SECBUFFER_EMPTY;
                buffers[2].BufferType = SECBUFFER_EMPTY;
                buffers[3].BufferType = SECBUFFER_EMPTY;

                SecBufferDesc desc = { SECBUFFER_VERSION, ARRAYSIZE(buffers), buffers };

                SECURITY_STATUS sec = DecryptMessage(&tlscontext, &desc, 0, NULL);
                if (sec == SEC_E_OK)
                {

                    _decrypted_buffer = (char*)buffers[1].pvBuffer;
                    _decrypted_buflen = buffers[1].cbBuffer;
                    //std::cout << "decrypted " << _decrypted_buflen << std::endl;
                    _tls_used = _tls_buflen - (buffers[3].BufferType == SECBUFFER_EXTRA ? buffers[3].cbBuffer : 0);

                    // data is now decrypted, go back to beginning of loop to copy memory to output buffer
                    continue;
                }
                else if (sec == SEC_I_CONTEXT_EXPIRED)
                {
                    // server closed TLS connection (but socket is still open)
                    _tls_buflen = 0;
                    return result;
                }
                else if (sec == SEC_I_RENEGOTIATE)
                {
                    // server wants to renegotiate TLS connection, not implemented here
                    return -1;
                }
                else if (sec != SEC_E_INCOMPLETE_MESSAGE)
                {
                    // some other schannel or TLS protocol error
                    return -1;
                }
                // otherwise sec == SEC_E_INCOMPLETE_MESSAGE which means need to read more data
            }
            // otherwise not enough data received to decrypt

            if (result != 0)
            {
                // some data is already copied to output buffer, so return that before blocking with recv
                break;
            }

            if (_tls_buflen == max_packet_size())
            {
                // server is sending too much garbage data instead of proper TLS packet
                return -1;
            }



            char* dest = _tls_buffer + _tls_buflen;
            int maxcount = max_packet_size() - _tls_buflen;
            // wait for more ciphertext data from server
            int r = ::recv(con.socket(), dest , maxcount , 0);
            if (r == 0)
            {
                // server disconnected socket
                return 0;
            }
            else if (r < 0)
            {
                int lasterr = WSAGetLastError();

                if (con.non_blocking() && lasterr == WSAEWOULDBLOCK) {

                    //std::cout << "would block\n";
                    //continue;
                    return result;
                }
                else {
                    std::stringstream err;
                    err << "(" << con.socket() << ")" << "tls socket error: " << lasterr << std::endl;
                    std::cout << err.str();
                    // error receiving data from socket
                    result = -1;
                    break;
                }


            }
            _tls_buflen += r;
        }
    }

    return result;
}



conn_err http_connection::readwait() {

    if (!con.non_blocking()) return conn_err::OK;

    if (_use_tls) {
        if (tls->data_available()) {
            return conn_err::OK;
        }
    }

    fd_set set;
    set.fd_array[0] = con.socket();
    set.fd_count = 1;

    timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;

    int iresult = select(0, &set, NULL, NULL, &timeout);

    if (iresult == 0) {
        std::stringstream err;
        err << "(" << con.socket() << ")" << "Receive timed out" << std::endl;
        std::cout << err.str();
        return conn_err::TIMED_OUT;
    }
    else if (iresult == SOCKET_ERROR) {
        std::stringstream err;
        err << "(" << con.socket() << ")" << "Receive error: " << WSAGetLastError() << std::endl;
        std::cout << err.str();
        return conn_err::SOCKET_ERR;
    }

    return conn_err::OK;
}



conn_err http_connection::readbytes(size_t bytes, std::vector<char>& res) {
    res.reserve(bytes);

    //std::cout << "requested: " << bytes << std::endl;



    if (_buflen > 0) {
        size_t count = std::min((size_t)_buflen, bytes);
        res.insert(res.end(), _buffer, _buffer + count);
        MoveMemory(_buffer, _buffer + count, _buflen - count);
        _buflen -= count;
        bytes -= count;

        //std::cout << "buffered: " << count << std::endl;
    }

    char buf[5012];



    while (bytes) {
        conn_err err = readwait();
        if (err != conn_err::OK) return err;

        size_t req = bytes < 5012 ? bytes : 5012;

        int c = receive(buf, req);
        //std::cout << "recieved: " << c << std::endl;

        bytes -= c;
        res.insert(res.end(), buf, buf + c);
    }

    return conn_err::OK;
}

conn_err http_connection::readuntil(const char* str, std::string& res) {



    size_t len = strlen(str);

    std::string s;

    if (_buflen > 0) {
        s.append(_buffer, _buflen);
        _buflen = 0;
    }


    size_t i = s.find(str);
    while (i == std::string::npos) {

        conn_err err = readwait();
        if (err != conn_err::OK) return err;
        int iresult = receive(_buffer, CON_BUF_LEN - 1);
        
        if (iresult == -1) {
            std::stringstream err;
            err << "(" << con.socket() << ")" << "readuntil err " << WSAGetLastError() << std::endl;
            std::cout << err.str();
            //continue;
            return conn_err::SOCKET_ERR;
        }

        _buflen = iresult;
        _buffer[_buflen] = 0;

        s.append(_buffer, _buflen);
        _buflen = 0;

        i = s.find(str);
    }


    //+1 for null terminator
    memcpy(_buffer, s.c_str() + i + len, s.size() - i - len + 1);
    _buflen = s.size() - i - len;

    res = s.substr(0, i + len);
    return conn_err::OK;
}

bool http_connection::get_http_response(http_response& resp) {

    if (!con.open()) return false;

    //if (_use_tls) {
    //    tls->flush();
    //}

    std::string start_line;
    if (readuntil("\r\n", start_line) != conn_err::OK) return false;

    std::istringstream ss(start_line);
    ss >> resp.version;
    ss >> resp.error_code;
    std::getline(ss, resp.error_msg);

    resp.headers.clear();
    std::string header;
    while (1) {
        if (readuntil("\r\n", header) != conn_err::OK) return false;

        //std::cout << header << std::endl;

        //end of headers
        if (header == "\r\n") break;

        size_t split = header.find_first_of(':');
        if (split == std::string::npos) {
            std::stringstream err;
            err << "(" << con.socket() << ")" << "Invalid Header: " << header << std::endl;
            std::cout << err.str();

            return false;
        }



        std::string key = header.substr(0, split);

        std::transform(key.begin(), key.end(), key.begin(),
            [](unsigned char c) { return std::tolower(c); });

        split++;
        while (std::isspace(header[split])) {
            split++;
            if (split >= header.size()) {
                //std::cout << "Invalid Header: " << header << std::endl;
                //return false;

                resp.headers.insert({ key, "" });
                continue;
            }
        }


        //make sure to remove trailing \r\n
        std::string value = header.substr(split, header.size() - split - 2);

        resp.headers.insert({ key,value });
    }


    std::vector<char> content;

    if (resp.headers.count("transfer-encoding")) {
        if (resp.headers["transfer-encoding"] == "chunked") {

            while (1) {
                std::string s;
                char* p;
                if (readuntil("\r\n", s) != conn_err::OK) return false;
                if (s == "\r\n") continue;
                size_t chunklen = std::strtoull(s.c_str(), &p, 16);

                //terminating chunk
                if (chunklen == 0) {
                    break;
                }
                if (readbytes(chunklen, content) != conn_err::OK) return false;
            }

        }
        else {
            return false;
        }

    }
    else if (resp.headers.count("content-length")) {
        char* p;
        size_t contentlen = std::strtoull(resp.headers["content-length"].c_str(), &p, 10);

        if (readbytes(contentlen, content) != conn_err::OK) return false;
    }



    resp.body = content;


    //redirect
    if (resp.error_code == 301 || resp.error_code == 307) {
        if (resp.headers.count("location") == 0) {
            return false;
        }

        std::string& redir = resp.headers["location"];


        std::stringstream err;
        err << "(" << con.socket() << ")" << "Redirecting to '" << redir << "'\n";
        std::cout << err.str();


        size_t i = redir.find("://");
        if (i == std::string::npos) {

            if (redir[0] != '/') {
                redir = '/' + redir;

            }
            if (request(http_method::GET, redir, resp) == conn_err::OK) {
                return true;
            }
            return false;
        }

        i += 3;
        i = redir.find('/', i);
        if (i == std::string::npos) {
            return false;
        }

        std::string host = redir.substr(0, i + 1);
        std::string path = redir.substr(i);

        connect(host);
        if (request(http_method::GET, path, resp) == conn_err::OK) {
            return true;
        }

        return false;

    }



    //std::cout << content << std::endl;

    return true;
}


}