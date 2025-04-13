#include "ip2region_util.h"
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

std::shared_ptr<xdb_search_t> IP2RegionUtil::xdbPtr;

bool IP2RegionUtil::init(const std::string& xdbFilePath) {

    xdbPtr = std::make_shared<xdb_search_t>(xdbFilePath);
    xdbPtr->init_content();
    return true;
}


bool validateIPv4(const std::string& ip) {
    // 步骤1：基础格式验证
    if (ip.empty() || ip.size() > 15) return false;
    if (std::count(ip.begin(), ip.end(), '.') != 3) return false;

    // 步骤2：分割字符串
    std::vector<std::string> parts;
    std::istringstream iss(ip);
    std::string part;
    while (getline(iss, part, '.')) {
        if (part.empty() || part.size() > 3) return false; // 防止空段或超长段
        parts.push_back(part);
    }
    if (parts.size() != 4) return false;

    // 步骤3：逐段校验
    for (const auto& p : parts) {
        // 前导零校验（文献[9](@ref)）
        if (p.size() > 1 && p[0] == '0') return false;

        // 数字范围校验
        try {
            int num = std::stoi(p);
            if (num < 0 || num > 255) return false;
        }
        catch (...) { // 非数字字符捕获
            return false;
        }
    }
    return true;
}

std::string IP2RegionUtil::getIpLocation(const std::string& ip) {

    if (!validateIPv4(ip)) {
        return "";
    }

    std::string location = xdbPtr->search(ip);
    if (!location.empty() && location.find("invalid") == std::string::npos) {
        return parseLocation(location);
    }
    else {
        return "";
    }
}

std::string IP2RegionUtil::parseLocation(const std::string& input) {
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream ss(input);

    if (input.find("内网") != std::string::npos) {
        return "内网";
    }

    while (std::getline(ss, token, '|')) {

        //token = MiscUtil::UTF8ToANSIString(token);

        tokens.push_back(token);
    }

    if (tokens.size() >= 4) {
        std::string result;
        if (tokens[0].compare("0") != 0) {
            result.append(tokens[0]);
        }
        if (tokens[2].compare("0") != 0) {
            result.append("-" + tokens[2]);
        }
        if (tokens[3].compare("0") != 0) {
            result.append("-" + tokens[3]);
        }

        return result;
    }
    else {
        return input;
    }
}