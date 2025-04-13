#pragma once

#include <sstream>
#include "../tshark_datatype.h"
#include "loguru/loguru.hpp"
#include "page_helper.hpp"
#include "../MiscUtil.h"

class PacketSQL {
public:
    static std::string buildPacketQuerySQL(QueryCondition& condition) {
        std::stringstream ss;
        ss << "SELECT * FROM t_packets";
        std::vector<std::string> conditionList;

        // 处理IP条件（支持模糊查询）
        if (!condition.ip.empty()) {
            std::string safeValue = MiscUtil::sanitizeForSql(condition.ip);
            std::string pattern = MiscUtil::replaceAll(safeValue, "*", "%");
            conditionList.push_back("(src_ip LIKE '" + pattern + "' OR dst_ip LIKE '" + pattern + "')");
        }

        // 处理端口条件（精确匹配）
        if (condition.port != 0) {
            conditionList.push_back("(src_port=" + std::to_string(condition.port) +
                " OR dst_port=" + std::to_string(condition.port) + ")");
        }

        // 处理协议条件（精确匹配）
        if (!condition.proto.empty()) {
            std::string safeProto = MiscUtil::sanitizeForSql(condition.proto);
            conditionList.push_back("protocol='" + safeProto + "'");
        }

        // 处理MAC地址（支持模糊查询）
        if (!condition.mac.empty()) {
            std::string safeValue = MiscUtil::sanitizeForSql(condition.mac);
            std::string pattern = MiscUtil::replaceAll(safeValue, "*", "%");
            conditionList.push_back("(src_mac LIKE '" + pattern + "' OR dst_mac LIKE '" + pattern + "')");
        }

        // 处理地理位置（支持模糊查询）
        if (!condition.location.empty()) {
            std::string safeValue = MiscUtil::sanitizeForSql(condition.location);
            std::string pattern = MiscUtil::replaceAll(safeValue, "*", "%");
            conditionList.push_back("(src_location LIKE '" + pattern + "' OR dst_location LIKE '" + pattern + "')");
        }

        // 拼接WHERE条件
        if (!conditionList.empty()) {
            ss << " WHERE " << MiscUtil::joinStrings(conditionList, " AND ");
        }

        ss << PageHelper::getPageSql();

        std::string sql = ss.str();
        LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
        return sql;
    }

    static std::string buildPacketQuerySQL_Count(QueryCondition& condition) {
        std::string sql = buildPacketQuerySQL(condition);
        auto pos = sql.find("LIMIT");
        if (pos != std::string::npos) {
            sql = sql.substr(0, pos);
        }
        std::string countSql = "SELECT COUNT(0) FROM (" + sql + ") t_temp;";
        LOG_F(INFO, "[BUILD SQL]: %s", countSql.c_str());
        return countSql;
    }
};