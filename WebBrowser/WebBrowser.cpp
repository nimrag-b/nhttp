// WebBrowser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <WinSock2.h>

#include "nhttp.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <thread>

bool init() {

    WSADATA wsaData;


    int iresult;
    iresult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iresult != 0) {
        std::cout << "WSA failed to startup with err: " << iresult << std::endl;
        return false;
    }

    return true;


}

int requested = 0;
int completed = 0;

void getres(nhttp::http_connection* con, const std::string& folder, const std::string& res) {

    std::cout << res << std::endl;
    //continue;


    std::string path;


    nhttp::http_response resp;
    int retrys = 0;
    while (con->request(nhttp::http_method::GET, "/" + res, resp) != nhttp::conn_err::OK) {
        //std::cout << "failed to GET resource " << res << std::endl;
        Sleep(50);
        retrys++;
        if (retrys > 3) {
            con->close();
            delete con;
            return;
        }
    }

    if (res[0] == '/') {
        path = folder.substr(0, folder.find('/')) + res;
    }
    else {
        path = folder + "/" + res;
    }


    con->close();
    delete con;

    size_t last = path.find_last_of('/');

    if (last != std::string::npos) {
        std::string dir = path.substr(0, last);

        std::error_code ec;
        if (!std::filesystem::create_directories(dir, ec) && ec) {
            std::cerr << "mkdirs failed: " << ec.message() << '\n';
            return;
        }
    }

    std::ofstream f;
    f.open(path, std::ios::binary);

    f << resp.body;

    f.close();

    completed++;
}

std::vector<std::thread> get_links(const std::string& folder, const std::string& url, const std::string& src, const std::string& tag) {

    std::vector<std::thread> threads;

    size_t i = 0;
    std::string search = tag + "=\"";
    while (1) {
        i = src.find(search, i);
        if (i == std::string::npos) break;

        int tagidx = i;

        i += search.length();


        while (src[tagidx] != '<') {
            tagidx--;
        }

        //dirty hack to exclude hyperlinks
        if (src[tagidx + 1] == 'a' && src[tagidx + 2] == ' ') continue;


        size_t end = src.find('\"', i);
        if (end == std::string::npos) {
            //malformed path, ignore
            continue;
        }
        std::string respath = src.substr(i, end - i);

        if (respath.find("http://") == 0 || respath.find("https://") == 0) {
            continue;
        }


        requested++;
        nhttp::http_connection* con = new nhttp::http_connection;

        if (!con->connect(url)) {
            continue;
        }



        //getres(con, folder, respath);
        std::thread t(getres,con, folder, respath);

        //threads.push_back(std::move(t));
        t.join();
        //t.detach();
    }

    return threads;
}

int main()
{

    if (!init()) {
        return -1;
    }

    nhttp::http_connection con;

    const std::string request = "https://xkcd.com/";


    size_t s = request.find("://");

    const std::string dir = request.substr(s + 3);

    s = request.find("/", s + 3);

    const std::string url = request.substr(0, s + 1);

    const std::string page = request.substr(s);


    std::filesystem::create_directories(dir);

    if (!con.connect(url)) {
        WSACleanup();
        return -1;
    }

    std::ofstream f;

    nhttp::http_response resp;
    con.request(nhttp::http_method::GET, page, resp);

    con.close();


    //std::cout << resp.body;

    f.open(dir +"/index.html");
    f << resp.body;

    f.close();



    std::vector<std::thread> threads = get_links(dir,url,resp.body, "src");
    std::vector<std::thread> threads1 = get_links(dir,url,resp.body, "href");

    for (auto& t : threads) {
        t.join();
    }
    for (auto& t : threads1) {
        t.join();
    }



    std::cout << "Completed\n";

    std::cout << "requested: " << requested << std::endl << "completed: " << completed << std::endl;

    WSACleanup();
    return 0;

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
