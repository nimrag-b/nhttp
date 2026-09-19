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
void scrape(const nhttp::html_path& request);
void get_all_links(nhttp::html_path& url, const std::string& src, std::vector<std::thread>& threads);

void getres(const nhttp::html_path& baseurl, const std::string& res) {

    std::string folder = baseurl.full_path();

    size_t isfile = folder.find_last_of("/.");
    if (folder[isfile] == '.') {
        folder = folder.substr(0, folder.find_last_of('/'));
    }

    folder += '/';

    std::string path;
    std::string resloc;

    if (res[0] == '/') {
        path = folder.substr(0, folder.find('/')) + res;
        resloc = res;
    }
    else {
        path = folder + res;
        resloc = folder.substr(folder.find('/')) + res;
    }

    size_t q = path.find('?');
    if (q != std::string::npos) {
        return;
    }

    q = path.find(':');
    if (q != std::string::npos) {
        return;
    }
    q = path.find('#');
    if (q != std::string::npos) {
        return;
    }
    if (std::filesystem::exists(path)) {
        std::cout << "resource already exists: " << path << std::endl;
        completed++;
        return;
    }


    std::cout << res << std::endl;
    //continue;

    nhttp::http_connection con;

    if (!con.connect(baseurl)) {
        return;
    }






    nhttp::http_response resp;
    int retrys = 0;
    while (con.request(nhttp::http_method::GET, resloc, resp) != nhttp::conn_err::OK) {
        std::cout << "failed to GET resource " << resloc << std::endl;
        Sleep(50);
        if (!con.connect(baseurl)) {
            return;
        }
        retrys++;
        if (retrys > 3) {
            con.close();

            return;
        }
    }
    con.close();

    if (resp.error_code >= 400 && resp.error_code < 500) {
        std::stringstream err;
        err << "Error in response for '" << resloc << "':" << std::endl << std::endl << resp << std::endl;

        std::cout << err.str();
        return;
    }




    size_t last = path.find_last_of('/');

    if (last != std::string::npos) {
        std::string dir = path.substr(0, last);

        std::error_code ec;
        if (!std::filesystem::create_directories(dir, ec) && ec) {
            std::cerr << "mkdirs failed: " << ec.message() << '\n';
            return;
        }
    }

    if (path.substr(last).find('.') == std::string::npos) {
        if (resp.headers["content-type"].find("text/html") != std::string::npos) {
            std::filesystem::create_directory(path);
            path += "/index.html";
        }

    }

    std::ofstream f;
    f.open(path, std::ios::binary);

    if (!f.is_open()) {
        std::cout << "failed to open file: " << path << std::endl;
        return;
    }

    //f << resp.body;
    f.write(resp.body.data(), resp.body.size());

    f.close();
     
    std::string s = "GET '" + resloc + "' complete\n";
    std::cout << s;

    completed++;

    //if (resp.headers["content-type"].find("text/html") != std::string::npos) {

    //    std::string strbody(resp.body.begin(), resp.body.end());

    //    std::vector<std::thread> threads;
    //    get_all_links(folder, url, strbody, threads);

    //    for (auto& it : threads) {
    //        it.join();
    //    }
    //}
}

void get_links(const nhttp::html_path& url, const std::string& src, const std::string& tag, std::vector<std::thread>& threads) {

    constexpr bool strip_hyperlinks = false;

    constexpr bool scrape_deep = false;

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
        tagidx++;
        size_t l = tagidx;
        while (src[l] != ' ') {
            l++;
        }

        std::string htmltag = src.substr(tagidx, l - tagidx);

        std::transform(htmltag.begin(), htmltag.end(), htmltag.begin(),
            [](unsigned char c) { return std::tolower(c); });

        if constexpr (strip_hyperlinks) {

            //dirty hack to exclude hyperlinks
            if (htmltag == "a") continue;

        }


        size_t end = src.find('\"', i);
        if (end == std::string::npos) {
            //malformed path, ignore
            continue;
        }
        std::string respath = src.substr(i, end - i);

        //std::string ext = respath.substr(respath.find('.'));


        if (htmltag == "frame") {
            scrape(nhttp::html_path{url.protocol, url.domain, respath});
            continue;
        }

        if (respath.find("http://") == 0 || respath.find("https://") == 0) {

            if (scrape_deep) {
                scrape(respath);
            }

            continue;
        }


        requested++;

        //getres(con, folder, respath);
        std::thread t(getres,url, respath);

        threads.push_back(std::move(t));
        //t.join();
        //t.detach();
    }

}

void get_all_links(const nhttp::html_path& url, const std::string& src, std::vector<std::thread>& threads) {
    get_links(url, src, "src", threads);
    get_links(url, src, "href", threads);
    get_links(url, src, "background", threads);
}


void scrape(const nhttp::html_path& request) {
    nhttp::http_connection con;




    const std::string dir = request.full_path();


    //skip
    if (dir.find('?') != std::string::npos) {
        return;
    }

    size_t last = dir.find_last_of('/');

    if (last != std::string::npos) {
        //std::string dirp = dir.substr(0, last);

        std::error_code ec;
        if (!std::filesystem::create_directories(dir, ec) && ec) {
            std::cerr << "mkdirs failed: " << ec.message() << '\n';
            return;
        }
    }

    if (!con.connect(request)) {
        std::cout << "Failed" << std::endl;
        return;
    }

    std::ofstream f;

    nhttp::http_response resp;
    con.request(nhttp::http_method::GET, request.path, resp);

    con.close();



    f.open(dir + "/index.html");
    f.write(resp.body.data(), resp.body.size());

    f.close();

    std::string strbody(resp.body.begin(), resp.body.end());

    std::vector<std::thread> threads;
    get_all_links(request, strbody, threads);

    for (auto& t : threads) {
        t.join();
    }




    std::cout << "Completed\n";
}


int main(int argc, char** argv)
{
    std::string request;
    if (false) {
        if (argc == 1) {
            std::cout << "input address\n";
            return -1;
        }
        request = argv[1];
    }
    else {
        request = "https://www.willfallows.net/gallery";
    }




    if (!init()) {
        return -1;
    }



    scrape(request);

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
