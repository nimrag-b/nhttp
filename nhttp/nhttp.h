#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <WinSock2.h>

#define SECURITY_WIN32
#include <security.h>


#include <string>
#include <unordered_map>
#include <memory>
#include <iostream>

#include <fstream>

#define HTTP_PORT 80
#define HTTPS_PORT 443

#define CON_BUF_LEN 2048

namespace nhttp {

    struct html_path {

        html_path(const std::string& protocol, const std::string& domain, const std::string& path) : protocol(protocol), domain(domain) {

            this->domain.erase(this->domain.find_last_not_of('/') + 1, std::string::npos);

            if (path[0] == '/') {
                this->path = path;
            }
            else {
                this->path = '/' + path;
            }
        }

        html_path(const std::string& request) {
            size_t s = request.find("://");

            protocol = request.substr(0, s);

            size_t p = request.find("/", s + 3);

            domain = request.substr(s + 3, p - s - 3);

            path = request.substr(p);
        }

        std::string protocol;
        std::string domain;
        std::string path;


        std::string full_path() const {
            return domain + path;
        }

        std::string url() const {
            return protocol + "://" + domain + path;
        }

    };

    struct http_response {
        std::string version;
        int error_code;
        std::string error_msg;
        std::unordered_map<std::string, std::string> headers;

        std::vector<char> body;


    };
    inline std::ostream& operator << (std::ostream& outs, const http_response& resp) {
        outs << resp.version << " " << resp.error_code << " " << resp.error_msg << "\r\n";
        for (auto& it : resp.headers) {
            // Do stuff
            outs << it.first << ": " << it.second << "\r\n";
        }
        outs << "\r\n";

        return outs;// << resp.body << "\r\n\r\n";
    }

    enum class conn_err {
        OK = 0,
        SOCKET_ERR,
        TIMED_OUT,
        TLS_FAILURE
    };


    enum class http_method {
        GET,
        POST,
        HEAD,
    };


    class connection {
    public:
        bool connect(const char* url, short port, bool nonblocking);

        void set_nonblocking(bool value);
        bool check_is_blocking();

        int send(std::string msg);

        int receive(char* buf, int len);


        void close();

        bool open() const {
            return _open;
        }

        const std::string& hostname() {
            return _hostname;
        }

        bool non_blocking() {
            return _nonblocking;
        }

        const SOCKET socket() {
            return sock;
        }

    private:
        std::string _hostname;
        bool _open = false;
        bool _nonblocking = false;

        SOCKET sock = INVALID_SOCKET;

    };


    class tls_socket {
    public:
        tls_socket(connection& con) : con(con) {
        }

        ~tls_socket() {
            if (_tls_buffer) {
                delete[] _tls_buffer;
            }
        }

        conn_err tls_connect();

        void tls_close();

        int tls_send(std::string msg);

        int tls_receive(char* buf, int len);

        bool data_available() {
            return (_decrypted_buffer != NULL) && (_decrypted_buflen > 0);
        }

        void flush() {
            _tls_buflen = 0;
            _tls_used = 0;
            _decrypted_buflen = 0;
            _decrypted_buffer = NULL;
        }


        const int max_packet_size() {
            return sizes.cbMaximumMessage + 512; //extra headroom for headers etc
        }

    private:
        connection& con;

        bool open = false;

        //tls
        CredHandle tlshandle;
        CtxtHandle tlscontext;
        SecPkgContext_StreamSizes sizes = { 0 };

        char* _tls_buffer = NULL;
        int _tls_buflen = 0;
        int _tls_used = 0;
        char* _decrypted_buffer = NULL;
        int _decrypted_buflen = 0;

    };


    class http_connection {

    public:


        bool connect(const html_path& url) {

            close();


            //size_t s = url.find("://");
            //if (s == std::string::npos) {
            //    return false;
            //}

            //std::string protocol = url.substr(0, s);

            //size_t s1 = url.find("/", s + 3);
            //if (s1 == std::string::npos) {
            //    return false;
            //}
            //std::string host = url.substr(s + 3, s1 - (s + 3));

            if (url.protocol == "http") {

                return con.connect(url.domain.c_str(), 80, true);

            }
            else if (url.protocol == "https") {
                if (!con.connect(url.domain.c_str(), 443, false)) 
                    return false;

                tls = std::make_unique<tls_socket>(con);

                bool tlss = false;
                for (size_t i = 0; i < 4; i++)
                {
                    if (tls->tls_connect() != conn_err::OK) {
                        std::cout << "tls handshake failed. retrying... " << std::endl;
                    }
                    else {
                        //std::cout << "tls success" << std::endl;
                        tlss = true;
                        break;
                    }
                }

                if (!tlss) {
                    std::cout << "tls handshake failed." << std::endl;
                    con.close();
                    return false;
                }


                con.set_nonblocking(true);

                _use_tls = true;
                return true;
            }

            
            
            return false;
            

        }

        void close() {
            if (con.open()) {
                if (_use_tls) {
                    tls->tls_close();
                }
                con.close();
            }
        }


        int send(std::string msg) {
            if (_use_tls) {
                return tls->tls_send(msg);
            }
            else {
                return con.send(msg);
            }
        }

        int receive(char* buf, int len) {
            int result;
            if (_use_tls) {
                result = tls->tls_receive(buf,len);


            }
            else {
                result =  con.receive(buf, len);
            }

            //raw.write(buf, result);

            return result;
        }


   
        conn_err request(http_method method, std::string page, http_response& resp) {

            std::string request;

            switch (method)
            {
            case nhttp::http_method::GET:
                request = "GET";
                break;
            case nhttp::http_method::POST:
                request = "POST";
                break;
            case nhttp::http_method::HEAD:
                request = "HEAD";
                break;
            default:
                break;
            }
             request += " " + page + " HTTP/1.1\r\nHost: " + con.hostname() + "\r\nUser-Agent: nimweb/0.0.1\r\nAccept: */*\r\n\r\n";

            std::cout << request << std::endl;

            _buflen = 0;

            if (_use_tls) {
                tls->flush();
            }


            send(request);

            //std::string rawpath = page.substr(page.find_last_of("/")+1) + ".raw";
            //raw.open(rawpath);

            if (get_http_response(resp)) {
                //raw.close();
                return conn_err::OK;
            }

            //raw.close();

            return conn_err::SOCKET_ERR;
        }


        conn_err readwait();


        conn_err readbytes(size_t bytes, std::vector<char>& res);

        conn_err readuntil(const char* str, std::string& res);

        bool get_http_response(http_response& resp);

    private:

        //std::ofstream raw;

        connection con;
        bool _use_tls = false;
        std::unique_ptr<tls_socket> tls = nullptr;


        //buffers
        char _buffer[CON_BUF_LEN];
        int _buflen = 0;

    };
}
