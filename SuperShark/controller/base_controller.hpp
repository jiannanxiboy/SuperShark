#pragma once

#include "httplib.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"

#include "../tshark_datatype.h"
#include "../TsharkManager.h"
#include "../tshark_errorcode.hpp"
#include "../MiscUtil.h"


// 数据包相关的接口
class BaseController {
public:
    BaseController(httplib::Server& server, std::shared_ptr<TsharkManager> tsharkManager)
        : __server(server)
        , __tsharkManager(tsharkManager){}

    virtual void registerRoute() = 0;

    // 从URL中提取整数参数
    static int getIntParam(const httplib::Request& req, std::string paramName, int defaultValue = 0) {

        int value = defaultValue;
        auto it = req.params.find(paramName);
        if (it != req.params.end()) {
            value = std::stoi(it->second);
        }
        return value;
    }

    // 从URL中提取字符串参数
    static std::string getStringParam(const httplib::Request& req, std::string paramName, std::string defaultValue = "") {
        std::string value = defaultValue;
        auto it = req.params.find(paramName);
        if (it != req.params.end()) {
            value = it->second;
        }
        return value;
    }

protected:
    httplib::Server& __server;
    std::shared_ptr<TsharkManager> __tsharkManager;

    // 使用模板的形式返回数据列表
    template<typename Data>
    void sendDataList(httplib::Response& res, std::vector<std::shared_ptr<Data>>& dataList, int total) {
        /**
         * 返回数据格式：
         * {
         *     "code": 0,
         *     "msg": "操作成功",
         *     "data" [] / {}
         * }
         */
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();

        // 添加 "code" 和 "msg"
        resDoc.AddMember("code", ERROR_SUCCESS, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);
        resDoc.AddMember("total", total, allocator);

        // 构建 "data" 数组
        rapidjson::Value dataArray(rapidjson::kArrayType);
        for (const auto& data : dataList) {
            rapidjson::Value obj(rapidjson::kObjectType);
            data->toJsonObj(obj, allocator);
            assert(obj.IsObject());
            dataArray.PushBack(obj, allocator);
        }

        resDoc.AddMember("data", dataArray, allocator);

        // 序列化为 JSON 字符串
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        // 设置响应内容
        res.set_content(buffer.GetString(), "application/json");
    }

    // 发生错误响应
    void sendErrorResponse(httplib::Response& res, int errorCode) {
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", errorCode, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(errorCode).c_str(), allocator), allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }

    // 返回成功响应，但没有数据
    void sendSuccessResponse(httplib::Response& res) {
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", 0, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }

    // 成功响应，返回JSON内容
    void sendJsonResponse(httplib::Response& res, rapidjson::Document& dataDoc) {
        /**
         * 返回数据格式：
         * {
         *     "code": 0,
         *     "msg": "操作成功",
         *     "data" [] / {}
         * }
         */
        rapidjson::Document resDoc;
        rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
        resDoc.SetObject();
        resDoc.AddMember("code", ERROR_SUCCESS, allocator);
        resDoc.AddMember("msg", rapidjson::Value(TsharkError::getErrorMsg(ERROR_SUCCESS).c_str(), allocator), allocator);
        resDoc.AddMember("data", dataDoc, allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        resDoc.Accept(writer);

        res.set_content(buffer.GetString(), "application/json");
    }

    // 提取请求体中的参数
    bool parseQueryCondition(const httplib::Request& req, QueryCondition& queryCondition) {

        try {

            // 检查是否有 body 数据
            if (req.body.empty()) {
                throw std::runtime_error("Request body is empty");
            }

            // 使用 RapidJSON 解析 JSON
            rapidjson::Document doc;
            if (doc.Parse(req.body.c_str()).HasParseError()) {
                throw std::runtime_error("Failed to parse JSON");
            }

            // 验证是否是 JSON 对象
            if (!doc.IsObject()) {
                throw std::runtime_error("Invalid JSON format, expected an object");
            }

            // 提取字段并赋值到 QueryCondition 中
            if (doc.HasMember("ip") && doc["ip"].IsString()) {
                queryCondition.ip = doc["ip"].GetString();
            }

            if (doc.HasMember("port") && doc["port"].IsUint()) {
                queryCondition.port = static_cast<uint16_t>(doc["port"].GetUint());
            }

            if (doc.HasMember("proto") && doc["proto"].IsString()) {
                queryCondition.proto = doc["proto"].GetString();
            }

            //Mac地址
            if (doc.HasMember("mac") && doc["mac"].IsString()) {
                queryCondition.mac = doc["mac"].GetString();
            }

            //归属地
            if (doc.HasMember("location") && doc["location"].IsString()) {
                queryCondition.location = doc["location"].GetString();
            }

            //会话ID
            if (doc.HasMember("session_id") && doc["session_id"].IsUint()) {
				queryCondition.session_id = static_cast<uint16_t>(doc["session_id"].GetUint());
            }

        }
        catch (std::exception&) {
            std::cout << "parse parameter error" << std::endl;
            return false;
        }

        return true;
    }
};
