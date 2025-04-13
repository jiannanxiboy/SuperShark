#pragma once

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "MiscUtil.h"

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <set>


// PCAP全局文件头
struct PcapHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// 每一个数据报文前面的头
struct PacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t caplen;
    uint32_t len;
};

// 查询条件
class QueryCondition {
public:
    std::string ip;
    uint16_t port = 0;
    std::string proto;
    std::string mac;
    std::string location;

    uint32_t session_id = 0;
};


// 网卡信息
struct AdapterInfo {
    int id;
    std::string name;
    std::string remark;

    void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        rapidjson::Value pktObj(rapidjson::kObjectType);
        obj.AddMember("id", id, allocator);
        obj.AddMember("name", rapidjson::Value(name.c_str(), allocator), allocator);
        obj.AddMember("remark", rapidjson::Value(remark.c_str(), allocator), allocator);
    }
};


class BaseDataObject {
public:
    // 将对象转换为JSON Value，用于转换为JSON格式输出
    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const = 0;
};


class Packet {
public:
    int frame_number;
    double time;
    uint32_t cap_len;
    uint32_t len;
    std::string src_mac;
    std::string dst_mac;
    std::string src_ip;
    std::string src_location;
    uint16_t src_port;
    std::string dst_ip;
    std::string dst_location;
    uint16_t dst_port;
    std::string trans_proto;       // 传输层协议
    std::string protocol;
    std::string info;
    uint32_t file_offset;
    uint32_t belong_session_id;    // 所属的会话ID，为0表示不属于任何会话

    void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        rapidjson::Value pktObj(rapidjson::kObjectType);
        obj.AddMember("frame_number", frame_number, allocator);
        obj.AddMember("timestamp", time, allocator);
        obj.AddMember("src_mac", rapidjson::Value(src_mac.c_str(), allocator), allocator);
        obj.AddMember("dst_mac", rapidjson::Value(dst_mac.c_str(), allocator), allocator);
        obj.AddMember("src_ip", rapidjson::Value(src_ip.c_str(), allocator), allocator);
        obj.AddMember("src_location", rapidjson::Value(src_location.c_str(), allocator), allocator);
        obj.AddMember("src_port", src_port, allocator);
        obj.AddMember("dst_ip", rapidjson::Value(dst_ip.c_str(), allocator), allocator);
        obj.AddMember("dst_location", rapidjson::Value(dst_location.c_str(), allocator), allocator);
        obj.AddMember("dst_port", dst_port, allocator);
        obj.AddMember("trans_proto", rapidjson::Value(trans_proto.c_str(), allocator), allocator);
        obj.AddMember("len", len, allocator);
        obj.AddMember("cap_len", cap_len, allocator);
        obj.AddMember("protocol", rapidjson::Value(protocol.c_str(), allocator), allocator);
        obj.AddMember("info", rapidjson::Value(info.c_str(), allocator), allocator);
        obj.AddMember("file_offset", file_offset, allocator);
    }
};


// 会话信息
class Session : public BaseDataObject {
public:
    uint32_t session_id;
    std::string ip1;
    uint16_t ip1_port;
    std::string ip1_location;
    std::string ip2;
    uint16_t ip2_port;
    std::string ip2_location;
    std::string trans_proto;
    std::string app_proto;
    double start_time;
    double end_time;
    uint32_t ip1_send_packets_count;   // ip1发送的数据包数
    uint32_t ip1_send_bytes_count;     // ip1发送的字节数
    uint32_t ip2_send_packets_count;   // ip2发送的数据包数
    uint32_t ip2_send_bytes_count;     // ip2发送的字节数
    uint32_t packet_count;           // 数据包数量
    uint32_t total_bytes;            // 总字节数

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("session_id", session_id, allocator);
        obj.AddMember("ip1", rapidjson::Value(ip1.c_str(), allocator), allocator);
        obj.AddMember("ip1_port", ip1_port, allocator);
        obj.AddMember("ip1_location", rapidjson::Value(ip1_location.c_str(), allocator), allocator);
        obj.AddMember("ip2", rapidjson::Value(ip2.c_str(), allocator), allocator);
        obj.AddMember("ip2_port", ip2_port, allocator);
        obj.AddMember("ip2_location", rapidjson::Value(ip2_location.c_str(), allocator), allocator);
        obj.AddMember("trans_proto", rapidjson::Value(trans_proto.c_str(), allocator), allocator);
        obj.AddMember("app_proto", rapidjson::Value(app_proto.c_str(), allocator), allocator);
        obj.AddMember("start_time", start_time, allocator);
        obj.AddMember("end_time", end_time, allocator);
        obj.AddMember("ip1_send_packets_count", ip1_send_packets_count, allocator);
        obj.AddMember("ip1_send_bytes_count", ip1_send_bytes_count, allocator);
        obj.AddMember("ip2_send_packets_count", ip2_send_packets_count, allocator);
        obj.AddMember("ip2_send_bytes_count", ip2_send_bytes_count, allocator);
        obj.AddMember("packet_count", packet_count, allocator);
        obj.AddMember("total_bytes", total_bytes, allocator);
    }
};

// IP通信统计信息
struct IPStatsInfo : public BaseDataObject {
    std::string ip;
    std::string location;
    double earliest_time = 0.0;
    double latest_time = 0.0;
    std::set<int> ports;
    std::set<std::string> protocols; // 通信协议集合（包括transProto与appProto）

    // 数据统计
    int total_sent_packets = 0;
    int total_recv_packets = 0;
    int total_sent_bytes = 0;
    int total_recv_bytes = 0;
    int tcp_session_count = 0;
    int udp_session_count = 0;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("ip", rapidjson::Value(ip.c_str(), allocator), allocator);
        obj.AddMember("location", rapidjson::Value(location.c_str(), allocator), allocator);
        std::string s_protocols = MiscUtil::convertSetToString(protocols, ',');
        obj.AddMember("proto", rapidjson::Value(s_protocols.c_str(), allocator), allocator);

        rapidjson::Value portsValue;
        portsValue.SetArray();
        for (auto port : ports) {
            portsValue.PushBack(rapidjson::Value(port), allocator);
        }
        obj.AddMember("ports", portsValue, allocator);

        obj.AddMember("earliest_time", earliest_time, allocator);
        obj.AddMember("latest_time", latest_time, allocator);
        obj.AddMember("total_sent_packets", total_sent_packets, allocator);
        obj.AddMember("total_recv_packets", total_recv_packets, allocator);
        obj.AddMember("total_sent_bytes", total_sent_bytes, allocator);
        obj.AddMember("total_recv_bytes", total_recv_bytes, allocator);
        obj.AddMember("tcp_session_count", tcp_session_count, allocator);
        obj.AddMember("udp_session_count", udp_session_count, allocator);
    }
};

// 协议统计信息
struct ProtoStatsInfo : public BaseDataObject {

    std::string proto;
    int total_packets = 0;
    int total_bytes = 0;
    int session_count = 0;
    std::string proto_description;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("proto", rapidjson::Value(proto.c_str(), allocator), allocator);
        obj.AddMember("total_packets", total_packets, allocator);
        obj.AddMember("total_bytes", total_bytes, allocator);
        obj.AddMember("session_count", session_count, allocator);
        obj.AddMember("proto_description", rapidjson::Value(proto_description.c_str(), allocator), allocator);
    }
};

// 地区统计信息
struct LocationStatsInfo : public BaseDataObject {
    std::string location;
    uint32_t ip_count = 0;

    uint32_t session_count = 0;
    uint32_t packet_count = 0;
    uint32_t total_bytes = 0;            // 总字节数
    uint32_t total_sent_packets = 0;
    uint32_t total_recv_packets = 0;
    uint32_t total_sent_bytes = 0;
    uint32_t total_recv_bytes = 0;
    uint32_t tcp_session_count = 0;
    uint32_t udp_session_count = 0;

    double earliest_time = 0.0;
    double latest_time = 0.0;

    std::set<std::string> ips;
    std::set<std::string> protocols;

	virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
		obj.AddMember("location", rapidjson::Value(location.c_str(), allocator), allocator);
		obj.AddMember("ip_count", ip_count, allocator);
		obj.AddMember("session_count", session_count, allocator);
		obj.AddMember("packet_count", packet_count, allocator);
		obj.AddMember("total_bytes", total_bytes, allocator);
		obj.AddMember("total_sent_packets", total_sent_packets, allocator);
		obj.AddMember("total_recv_packets", total_recv_packets, allocator);
		obj.AddMember("total_sent_bytes", total_sent_bytes, allocator);
		obj.AddMember("total_recv_bytes", total_recv_bytes, allocator);
		obj.AddMember("earliest_time", earliest_time, allocator);
		obj.AddMember("latest_time", latest_time, allocator);
		obj.AddMember("tcp_session_count", tcp_session_count, allocator);
		obj.AddMember("udp_session_count", udp_session_count, allocator);
		rapidjson::Value ipsValue;
		ipsValue.SetArray();
		for (auto ip : ips) {
			ipsValue.PushBack(rapidjson::Value(ip.c_str(), allocator), allocator);
		}
		obj.AddMember("ips", ipsValue, allocator);
		rapidjson::Value protocalsValue;
		protocalsValue.SetArray();
		for (auto protocol : protocols) {
			protocalsValue.PushBack(rapidjson::Value(protocol.c_str(), allocator), allocator);
		}
		obj.AddMember("protocols", protocalsValue, allocator);
	}
};


// 数据流条目结构
class DataStreamItem : public BaseDataObject {
public:
    std::string hexData;
    std::string srcNode;
    std::string dstNode;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("hexData", rapidjson::Value(hexData.c_str(), allocator), allocator);
        obj.AddMember("srcNode", rapidjson::Value(srcNode.c_str(), allocator), allocator);
        obj.AddMember("dstNode", rapidjson::Value(dstNode.c_str(), allocator), allocator);
    }
};


// 数据流统计信息
class DataStreamCountInfo : public BaseDataObject {
public:
    uint32_t totalPacketCount = 0;
    std::string node0;
    uint32_t node0PacketCount = 0;
    uint32_t node0BytesCount = 0;
    std::string node1;
    uint32_t node1PacketCount = 0;
    uint32_t node1BytesCount = 0;

    virtual void toJsonObj(rapidjson::Value& obj, rapidjson::Document::AllocatorType& allocator) const {
        obj.AddMember("totalPacketCount", totalPacketCount, allocator);

        obj.AddMember("node0", rapidjson::Value(node0.c_str(), allocator), allocator);
        obj.AddMember("node0PacketCount", node0PacketCount, allocator);
        obj.AddMember("node0BytesCount", node0BytesCount, allocator);

        obj.AddMember("node1", rapidjson::Value(node1.c_str(), allocator), allocator);
        obj.AddMember("node1PacketCount", node1PacketCount, allocator);
        obj.AddMember("node1BytesCount", node1BytesCount, allocator);
    }
};