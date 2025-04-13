#pragma once

// ip2region的源文件中使用了winsock2.h，这个头文件需要显式链接ws2_32.lib
// 任何需要网络通信的 Windows 程序（如客户端/服务器应用、网络游戏、Web 服务等）均需依赖此库。
#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
#endif

#include "ip2region/xdb_search.h"

#include <string>
#include <memory>
#include "MiscUtil.h"

class IP2RegionUtil {
public:
    static bool init(const std::string& xdbFilePath);
    static std::string getIpLocation(const std::string& ip);

private:
    static std::string parseLocation(const std::string& input);
    static std::shared_ptr<xdb_search_t> xdbPtr;
};