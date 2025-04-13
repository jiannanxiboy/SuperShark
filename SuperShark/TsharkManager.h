#pragma once

#include "httplib.h"
#include "tshark_datatype.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/stringbuffer.h"
#include "ip2region_util.h"
#include "ProcessUtil.h"
#include "db_util.hpp"
#include "tshark_translate.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <sstream>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <cmath>
#include <set>
#include <mutex>


enum WORK_STATUS {
    STATUS_IDLE = 0,                    // 空闲状态
    STATUS_ANALYSIS_FILE = 1,           // 离线分析文件中
    STATUS_CAPTURING = 2,               // 在线采集抓包中
    STATUS_MONITORING = 3               // 监控网卡流量中
};


class TsharkManager
{

public:
    TsharkManager(std::string workDir);
    ~TsharkManager();

    WORK_STATUS getWorkStatus();

    // 分析数据包文件
    bool analysisFile(std::string filePath);

    // 打印所有数据包的信息
    void printAllPackets();

    // 获取数据包数量
    int getPacketSize();

    // 获取指定编号数据包的十六进制数据
    bool getPacketHexData(uint32_t frameNumber, std::vector<unsigned char>& data);

    // 枚举网卡列表
    std::vector<AdapterInfo> getNetworkAdapters();

    // 开始监控所有网卡流量统计数据
    void startMonitorAdaptersFlowTrend();

    // 停止监控所有网卡流量统计数据
    void stopMonitorAdaptersFlowTrend();

    // 获取所有网卡流量统计数据
    void getAdaptersFlowTrendData(std::map<std::string, std::map<long, long>>& flowTrendData);

    // 开始抓包
    bool startCapture(std::string adapterName);

    // 停止抓包
    bool stopCapture();

    // 获取指定数据包的详情内容
    bool getPacketDetailInfo(uint32_t frameNumber, std::string& result);


    // -----------------------------数据查询相关接口-----------------------------------
    void queryPackets(QueryCondition queryConditon, std::vector<std::shared_ptr<Packet>>& packets, int& total);

private:

    // 工作状态
    WORK_STATUS workStatus = STATUS_IDLE;
    std::recursive_mutex workStatusLock;

    std::string workDir;

    std::string tsharkPath;
    std::string editcapPath;


    // 在线分析线程
    std::shared_ptr<std::thread> captureWorkThread;

    // 在线抓包的tshark进程PID
    PID_T captureTsharkPid = 0;

    // 是否停止抓包的标记
    bool stopFlag;

    // 当前分析的文件路径
    std::string currentFilePath;

    // 分析得到的所有数据包信息，key是数据包ID，value是数据包信息指针，方便根据编号获取指定数据包信息
    std::unordered_map<uint32_t, std::shared_ptr<Packet>> allPackets;


    // 等待存储入库的数据
    std::vector<std::shared_ptr<Packet>> packetsTobeStore;

    // 访问待存储数据的锁
    std::mutex storeLock;

    // 存储线程，负责将获取到的数据包和会话信息存储入库
    std::shared_ptr<std::thread> storageThread;

    // 数据库存储
    std::shared_ptr<TsharkDatabase> storage;

    // 英译中
    Translator translator;

    // 解析每一行
    bool parseLine(std::string line, std::shared_ptr<Packet> packet);

    // 在线采集数据包的工作线程
    void captureWorkThreadEntry(std::string adapterName);

    void processPacket(std::shared_ptr<Packet>);

    // 获取指定网卡的流量趋势数据
    void adapterFlowTrendMonitorThreadEntry(std::string adapterName);

    // 负责存储数据包和会话信息的存储线程函数
    void storageThreadEntry();

    // 将数据包格式转换为旧的pcap格式
    bool convertToPcap(const std::string& inputFile, const std::string& outputFile);

    // 重置数据
    void reset();


    // -----------------------------以下与网卡流量趋势监控有关-----------------------------------
    // 网卡监控相关的信息
    class AdapterMonitorInfo {
    public:
        AdapterMonitorInfo() {
            monitorTsharkPipe = nullptr;
            tsharkPid = 0;
        }
        std::string adapterName;                            // 网卡名称
        std::map<long, long> flowTrendData;                 // 流量趋势数据
        std::shared_ptr<std::thread> monitorThread;         // 负责监控该网卡输出的线程
        FILE* monitorTsharkPipe;                            // 线程与tshark通信的管道
        PID_T tsharkPid;                                    // 负责捕获该网卡数据的tshark进程PID
    };

    // 后台流量趋势监控信息
    std::map<std::string, AdapterMonitorInfo> adapterFlowTrendMonitorMap;

    // 访问上面流量趋势数据的锁
    std::recursive_mutex adapterFlowTrendMapLock;

    // 网卡流量监控的开始时间
    time_t adapterFlowTrendMonitorStartTime = 0;


    // -----------------------------以下与会话分析有关-----------------------------------
private:
    std::map<uint8_t, std::string> ipProtoMap = {
        {1, "ICMP"},
        {2, "IGMP"},
        {6, "TCP"},
        {17, "UDP"},
        {47, "GRE"},
        {50, "ESP"},
        {51, "AH"},
        {88, "EIGRP"},
        {89, "OSPF"},
        {132, "SCTP"}
    };

    // 定义五元组
    class FiveTuple {
    public:
        std::string src_ip;
        std::string dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        std::string trans_proto;

        // 重载比较操作符，用于 unordered_map 的键比较，确保会话对称性
        bool operator==(const FiveTuple& other) const {
            return ((src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port && dst_port == other.dst_port)
                || (src_ip == other.dst_ip && dst_ip == other.src_ip && src_port == other.dst_port && dst_port == other.src_port))
                && trans_proto == other.trans_proto;

        }
    };

    // 定义哈希函数，确保会话对称性
    class FiveTupleHash {
    public:
        std::size_t operator()(const FiveTuple& tuple) const {
            std::hash<std::string> hashFn;
            std::size_t h1 = hashFn(tuple.src_ip);
            std::size_t h2 = hashFn(tuple.dst_ip);
            std::size_t h3 = std::hash<uint16_t>()(tuple.src_port);
            std::size_t h4 = std::hash<uint16_t>()(tuple.dst_port);

            // 返回源和目的地址/端口的哈希组合，支持对称性
            std::size_t directHash = h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
            std::size_t reverseHash = h2 ^ (h1 << 1) ^ (h4 << 2) ^ (h3 << 3);

            // 确保无论是正向还是反向，都会返回相同的哈希值
            return directHash ^ reverseHash;
        }
    };

    std::unordered_map<FiveTuple, std::shared_ptr<Session>, FiveTupleHash> sessionMap;
    std::map<uint32_t, std::shared_ptr<Session>> sessionIdMap;

    // 等待存储入库的会话列表，使用unordered_set，自动去重
    std::unordered_set<std::shared_ptr<Session>> sessionSetTobeStore;

public:
    // 打印所有会话信息
    void printAllSessions();

	// 获取所有会话信息
	std::vector<std::shared_ptr<Session>> getAllSessions();

    // 数据库会话查询接口
    void querySessions(QueryCondition& condition, std::vector<std::shared_ptr<Session>>& sessionList, int& total);


    // ------------------------------IP通信统计相关------------------------------
public:
    // 查询IP通信统计列表数据
    bool getIPStatsList(QueryCondition& condition, std::vector<std::shared_ptr<IPStatsInfo>>& ipStatsList, int& total);

	// 查询协议统计列表数据
    bool getProtoStatsList(QueryCondition& condition, std::vector<std::shared_ptr<ProtoStatsInfo>>& ipStatsList, int& total);

    // 查询地区统计列表数据
	bool getLocationStatsList(QueryCondition& condition, std::vector<std::shared_ptr<LocationStatsInfo>>& locationStatsList, int& total);

    // 获取会话数据流
    DataStreamCountInfo getSessionDataStream(uint32_t sessionId, std::vector<DataStreamItem>& dataStreamList);

};