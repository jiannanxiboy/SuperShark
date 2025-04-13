#pragma once

#include <sstream>
#include "../tshark_datatype.h"
#include "loguru/loguru.hpp"


class StatsSQL {
public:
	// IP统计查询语句
	static std::string buildIPStatsQuerySQL(QueryCondition& condition) {
		std::string sql;
		std::stringstream ss;
		ss << R"(
SELECT
	ip,
	location,
	MIN(start_time) AS earliest_time,
	MAX(end_time) AS latest_time,
	GROUP_CONCAT(DISTINCT port) AS ports,
	GROUP_CONCAT(DISTINCT trans_proto) AS trans_protos,
	GROUP_CONCAT(DISTINCT app_proto) AS app_protos,
	SUM(sent_packets) AS total_sent_packets,
	SUM(sent_bytes) AS total_sent_bytes,
	SUM(recv_packets) AS total_recv_packets,
	SUM(recv_bytes) AS total_recv_bytes,
	SUM(tcp_sessions) AS tcp_session_count,
	SUM(udp_sessions) AS udp_session_count
FROM (
	SELECT
		ip1 AS ip,
		ip1_location AS location,
		start_time,
		end_time,
		ip1_port AS port,
		trans_proto,
		app_proto,
		ip1_send_packets_count AS sent_packets,
		ip1_send_bytes_count AS sent_bytes,
		ip2_send_packets_count AS recv_packets,
		ip2_send_bytes_count AS recv_bytes,
		CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions,
		CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions
	FROM t_sessions
	UNION ALL
	SELECT
		ip2 AS ip,
		ip2_location AS location,
		start_time,
		end_time,
		ip2_port AS port,
		trans_proto,
		app_proto,
		ip2_send_packets_count AS sent_packets,
		ip2_send_bytes_count AS sent_bytes,
		ip1_send_packets_count AS recv_packets,
		ip1_send_bytes_count AS recv_bytes,
		CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions,
		CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions
	FROM t_sessions
) t
)";

		std::vector<std::string> conditionList;
		if (!condition.ip.empty()) {
			char buf[100] = { 0 };
			snprintf(buf, sizeof(buf), "(ip='%s')", condition.ip.c_str());
			conditionList.push_back(buf);
		}
		if (condition.port != 0) {
			char buf[100] = { 0 };
			snprintf(buf, sizeof(buf), "(port=%d)", condition.port);
			conditionList.push_back(buf);
		}
		if (!condition.proto.empty()) {
			char buf[100] = { 0 };
			snprintf(buf, sizeof(buf), "(proto='%s')", condition.proto.c_str());
			conditionList.push_back(buf);
		}
		if (!condition.mac.empty()) {
			char buf[100] = { 0 };
			snprintf(buf, sizeof(buf), "(mac='%s')", condition.mac.c_str());
			conditionList.push_back(buf);
		}
		if (!condition.location.empty()) {
			char buf[100] = { 0 };
			snprintf(buf, sizeof(buf), "(location='%s')", condition.location.c_str());
			conditionList.push_back(buf);
		}
		// 拼接 WHERE 条件
		if (!conditionList.empty()) {
			ss << " WHERE ";
			for (size_t i = 0; i < conditionList.size(); ++i) {
				if (i > 0) {
					ss << " AND ";
				}
				ss << conditionList[i];
			}
		}

		ss << "GROUP BY ip";

		ss << PageHelper::getPageSql();

		sql = ss.str();
		LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
		return sql;
	};

	// IP统计查询-查询总数
	static std::string buildIPStatsQuerySQL_Count(QueryCondition& condition) {
		std::string sql = buildIPStatsQuerySQL(condition);

		auto pos = sql.find("LIMIT");
		if (pos != std::string::npos) {
			sql = sql.substr(0, pos);
		}

		std::string countSQL = "SELECT COUNT(*) FROM (" + sql + ") t_temp;";
		LOG_F(INFO, "[BUILD SQL]: %s", countSQL.c_str());
		return countSQL;
	}

	// 协议统计查询语句
	static std::string buildProtoStatsQuerySQL(QueryCondition& condition) {
		std::string sql;
		std::stringstream ss;
		ss << R"(
SELECT
    protocol,
    SUM(packet_count) AS totalPackets,
    SUM(total_bytes) AS total_bytes,
    COUNT(DISTINCT session_id) AS sessionCount
FROM (
    SELECT session_id, trans_proto AS protocol, packet_count, total_bytes
    FROM t_sessions
    WHERE trans_proto IS NOT NULL AND trans_proto != ''
    UNION ALL
    SELECT session_id, app_proto AS protocol, packet_count, total_bytes
    FROM t_sessions
    WHERE app_proto IS NOT NULL AND app_proto != ''
) AS combined
GROUP BY protocol
		)";

		ss << PageHelper::getPageSql();

		sql = ss.str();
		LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
		return sql;
	}

	// 协议统计查询-查询总数
	static std::string buildProtocolStatsQuerySQL_Count(QueryCondition& condition) {
		std::string sql = buildProtoStatsQuerySQL(condition);
		auto pos = sql.find("LIMIT");
		if (pos != std::string::npos) {
			sql = sql.substr(0, pos);
		}
		std::string countSQL = "SELECT COUNT(*) FROM (" + sql + ") t_temp;";
		LOG_F(INFO, "[BUILD SQL]: %s", countSQL.c_str());
		return countSQL;
	}


	// 地区统计查询语句
	static std::string buildLocationStatsQuerySQL(QueryCondition& condition) {
		std::string sql;
		std::stringstream ss;
		ss << R"(
SELECT
    -- 提取国家部分
    CASE 
        -- 处理以"-"开头的情况（如"-内网IP"）
        WHEN location LIKE '-%' THEN '内网'
        -- 正常提取国家（第一个"-"前的内容）
        WHEN INSTR(location, '-') > 0 
        THEN SUBSTR(location, 1, INSTR(location, '-') - 1)
        -- 其他情况保留原值
        ELSE location
    END AS country,
    COUNT(DISTINCT ip) AS ip_count,
    GROUP_CONCAT(DISTINCT ip) AS ips,
    COUNT(session_id) as session_count,
    MIN(start_time) AS earliest_time,
    MAX(end_time) AS latest_time,
    GROUP_CONCAT(DISTINCT trans_proto) AS trans_protos,
    GROUP_CONCAT(DISTINCT app_proto) AS app_protos,
    SUM(sent_packets) AS total_sent_packets,
    SUM(sent_bytes) AS total_sent_bytes,
    SUM(recv_packets) AS total_recv_packets,
    SUM(recv_bytes) AS total_recv_bytes,
	SUM(sent_packets) + SUM(recv_packets) AS packet_count,
    SUM(tcp_sessions) AS tcp_session_count,
    SUM(udp_sessions) AS udp_session_count
FROM (
    SELECT
        session_id,
        ip1 AS ip,
        ip1_location AS location,
        start_time,
        end_time,
        ip1_port AS port,
        trans_proto,
        app_proto,
        ip1_send_packets_count AS sent_packets,
        ip1_send_bytes_count AS sent_bytes,
        ip2_send_packets_count AS recv_packets,
        ip2_send_bytes_count AS recv_bytes,
        CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions,
        CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions
    FROM t_sessions
    UNION ALL
    SELECT
        session_id,
        ip2 AS ip,
        ip2_location AS location,
        start_time,
        end_time,
        ip2_port AS port,
        trans_proto,
        app_proto,
        ip2_send_packets_count AS sent_packets,
        ip2_send_bytes_count AS sent_bytes,
        ip1_send_packets_count AS recv_packets,
        ip1_send_bytes_count AS recv_bytes,
        CASE WHEN trans_proto LIKE '%TCP%' THEN 1 ELSE 0 END AS tcp_sessions,
        CASE WHEN trans_proto LIKE '%UDP%' THEN 1 ELSE 0 END AS udp_sessions
    FROM t_sessions
) t
GROUP BY country
		)";

		ss << PageHelper::getPageSql();

		sql = ss.str();
		LOG_F(INFO, "[BUILD SQL]: %s", sql.c_str());
		return sql;
	}

	// 地区统计查询-查询总数
	static std::string buildLocationStatsQuerySQL_Count(QueryCondition& condition) {
		std::string sql = buildLocationStatsQuerySQL(condition);
		auto pos = sql.find("LIMIT");
		if (pos != std::string::npos) {
			sql = sql.substr(0, pos);
		}
		std::string countSQL = "SELECT COUNT(*) FROM (" + sql + ") t_temp;";
		LOG_F(INFO, "[BUILD SQL]: %s", countSQL.c_str());
		return countSQL;
	}
};