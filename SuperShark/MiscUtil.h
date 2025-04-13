#pragma once

#include <random>
#include <string>
#include <windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <Shlobj.h>
#include <vector>
#include <set>

#include <rapidxml/rapidxml.hpp>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

using namespace rapidxml;
using namespace rapidjson;

class MiscUtil {

public:

    // UTF-8转ANSI
    #ifdef _WIN32
    static std::string UTF8ToANSIString(const std::string& utf8Str) {
        // 获取UTF-8字符串的长度
        int utf8Length = static_cast<int>(utf8Str.length());

        // 将UTF-8转换为宽字符（UTF-16）
        int wideLength = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, nullptr, 0);
        std::wstring wideStr(wideLength, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, &wideStr[0], wideLength);

        // 将宽字符（UTF-16）转换为ANSI
        int ansiLength = WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, nullptr, 0, nullptr, nullptr);
        std::string ansiStr(ansiLength, '\0');
        WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, &ansiStr[0], ansiLength, nullptr, nullptr);

        return ansiStr;
    }
    #else
    static std::string UTF8ToANSIString(const std::string& utf8Str) {
        return utf8Str;
    }
    #endif


    // 获得随机字符串
    static std::string getRandomString(size_t length) {
        const std::string chars = "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789";
        std::random_device rd;  // 用于种子
        std::mt19937 generator(rd());  // 生成器
        std::uniform_int_distribution<> distribution(0, chars.size() - 1);

        std::string randomString;
        for (size_t i = 0; i < length; ++i) {
            randomString += chars[distribution(generator)];
        }

        return randomString;
    }

    template<typename Data>
	static std::vector<std::shared_ptr<Data>> vectorToSharedPtrVector(const std::vector<Data>& vec) {
		std::vector<std::shared_ptr<Data>> result;
		for (const auto& item : vec) {
			result.push_back(std::make_shared<Data>(item));
		}
		return result;
	}

    // 将XML转为JSON格式
    static bool xml2JSON(std::string xmlContent, Document& outJsonDoc) {

        // 解析 XML
        xml_document<> doc;
        try {
            doc.parse<0>(&xmlContent[0]);
        }
        catch (const parse_error& e) {
            std::cout << "XML Parsing error: " << e.what() << std::endl;
            return false;
        }

        // 创建 JSON 文档
        outJsonDoc.SetObject();
        Document::AllocatorType& allocator = outJsonDoc.GetAllocator();

        // 获取 XML 根节点
        xml_node<>* root = doc.first_node();
        if (root) {
            // 将根节点转换为 JSON
            Value root_json(kObjectType);
            xml_to_json_recursive(root_json, root, allocator);

            // 将根节点添加到 JSON 文档
            outJsonDoc.AddMember(Value(root->name(), allocator).Move(), root_json, allocator);
        }
        return true;
    }

    // 将Set转换为String
    static std::string convertSetToString(const std::set<std::string>& set, char seperator) {
		std::stringstream ss;
		for (const auto& item : set) {
			ss << item << seperator;
		}
		std::string result = ss.str();
		if (!result.empty()) {
			result.pop_back();  // 去掉最后一个分隔符
		}
		return result;
    }

	// 按照指定的分隔符拆分字符串
	static std::set<std::string> splitString(const std::string& str, char delimiter) {
		std::set<std::string> result;
		std::stringstream ss(str);
		std::string item;
		while (std::getline(ss, item, delimiter)) {
			result.insert(item);
		}
		return result;
	}


    static std::string replaceAll(std::string str, const std::string& from, const std::string& to) {
        size_t start_pos = 0;
        while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
            str.replace(start_pos, from.length(), to);
            start_pos += to.length();
        }
        return str;
    }

    static std::string sanitizeForSql(const std::string& input) {
        std::string result;
        for (char c : input) {
            if (c == '\'') {
                result += "''";
            }
            else {
                result += c;
            }
        }
        return result;
    }

    static std::string joinStrings(const std::vector<std::string>& list, const std::string& delimiter) {
        std::stringstream ss;
        for (size_t i = 0; i < list.size(); ++i) {
            if (i > 0) {
                ss << delimiter;
            }
            ss << list[i];
        }
        return ss.str();
    }

    // 将std::set<std::string>转换为std::set<int>
	static std::set<int> toIntVector(const std::set<std::string>& set) {
		std::set<int> result;
		for (const auto& item : set) {
			result.insert(std::stoi(item));
		}
		return result;
	}

    static void trimEnd(std::string& str) {
        if (str.size() >= 2 && str.substr(str.size() - 2) == "\r\n") {
            str.erase(str.size() - 2);  // 删除末尾的 \r\n
        }
        else if (!str.empty() && str.back() == '\n') {
            str.erase(str.size() - 1);  // 删除末尾的 \n
        }
    }

private:
    // 私有函数，转换过程中需要递归处理子节点
    static void xml_to_json_recursive(Value& json, xml_node<>* node, Document::AllocatorType& allocator) {
        for (xml_node<>* cur_node = node->first_node(); cur_node; cur_node = cur_node->next_sibling()) {

            // 检查是否需要跳过节点
            xml_attribute<>* hide_attr = cur_node->first_attribute("hide");
            if (hide_attr && std::string(hide_attr->value()) == "yes") {
                continue;  // 如果 hide 属性值为 "true"，跳过该节点
            }

            // 检查是否已经有该节点名称的数组
            Value* array = nullptr;
            if (json.HasMember(cur_node->name())) {
                array = &json[cur_node->name()];
            }
            else {
                Value node_array(kArrayType); // 创建新的数组
                json.AddMember(Value(cur_node->name(), allocator).Move(), node_array, allocator);
                array = &json[cur_node->name()];
            }

            // 创建一个 JSON 对象代表当前节点
            Value child_json(kObjectType);

            // 处理节点的属性
            for (xml_attribute<>* attr = cur_node->first_attribute(); attr; attr = attr->next_attribute()) {
                Value attr_name(attr->name(), allocator);
                Value attr_value(attr->value(), allocator);
                child_json.AddMember(attr_name, attr_value, allocator);
            }

            // 递归处理子节点
            xml_to_json_recursive(child_json, cur_node, allocator);

            // 将当前节点对象添加到对应数组中
            array->PushBack(child_json, allocator);
        }
    }


public:

    // 获取数据存储目录
    static std::string getDefaultDataDir() {
        static std::string dir = "";
        if (!dir.empty()) {
            return dir;
        }
#ifdef _WIN32
        // 使用安全函数获取APPDATA路径
        char* appdata = nullptr;
        size_t len;
        errno_t err = _dupenv_s(&appdata, &len, "APPDATA");
        if (err == 0 && appdata != nullptr) {
            dir = std::string(appdata) + "\\easytshark\\";
            free(appdata);
        }
        else {
            // 回退到SHGetFolderPath获取AppData路径
            char path[MAX_PATH];
            if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_APPDATA, nullptr, 0, path))) {
                dir = std::string(path) + "\\easytshark\\";
            }
            else {
                // 终极回退到硬编码路径
                dir = "C:\\ProgramData\\easytshark\\";
            }
        }
#else
        const char* home = std::getenv("HOME");
        if (!home) {
            struct passwd* pw = getpwuid(getuid());
            if (pw) {
                home = pw->pw_dir;
            }
            else {
                // 回退到根目录
                home = "/";
            }
        }
        dir = std::string(home) + "/easytshark/";
#endif

        createDirectory(dir);
        return dir;
    }


    static bool fileExists(const char* path) {
        std::error_code ec;
        return std::filesystem::is_regular_file(path, ec) && !ec;
    }

    // 通过当前时间戳获取一个pcap文件名
    static std::string getPcapNameByCurrentTimestamp(bool isFullPath = true) {
        // 获取当前时间
        std::time_t now = std::time(nullptr);
        std::tm localTime = {};

        // 跨平台安全的时间转换
#if defined(_WIN32)
        if (localtime_s(&localTime, &now) != 0) {
            return "error_time.pcap"; // 错误处理示例
        }
#else
        if (!localtime_r(&now, &localTime)) {
            return "error_time.pcap"; // 错误处理示例
        }
#endif

        // 格式化文件名
        char buffer[64];
        std::strftime(buffer, sizeof(buffer), "easytshark_%Y-%m-%d_%H-%M-%S.pcap", &localTime);

        return isFullPath ? getDefaultDataDir() + std::string(buffer) : std::string(buffer);
    }

private:

    static void createDirectory(const std::string& dir) {
#if __has_include(<filesystem>) // 检查是否支持 <filesystem>
#include <filesystem>
        std::filesystem::create_directories(dir);
#else
#ifdef _WIN32
        // Windows 手动实现
        std::wstring wdir;
        int len = MultiByteToWideChar(CP_UTF8, 0, dir.c_str(), dir.size(), nullptr, 0);
        wdir.resize(len);
        MultiByteToWideChar(CP_UTF8, 0, dir.c_str(), dir.size(), &wdir[0], len);
        if (SHCreateDirectoryExW(nullptr, wdir.c_str(), nullptr) != ERROR_SUCCESS) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                throw std::runtime_error("目录创建失败: " + dir);
            }
        }
#else
        // Linux/macOS 手动实现
        std::string path = dir;
        size_t pos = 0;
        while (pos != std::string::npos) {
            pos = path.find('/', pos + 1);
            std::string subdir = path.substr(0, pos);
            if (mkdir(subdir.c_str(), 0777) != 0 && errno != EEXIST) {
                throw std::runtime_error("目录创建失败: " + subdir);
            }
        }
#endif
#endif
    }

};