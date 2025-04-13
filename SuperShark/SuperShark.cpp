#include "loguru/loguru.hpp"
#include "TsharkManager.h"
#include "controller/packet_controller.hpp"
#include "controller/adaptor_controller.hpp"
#include "controller/session_controller.hpp"
#include "controller/stats_controller.hpp"

void InitLog(int argc, char* argv[]) {
    loguru::init(argc, argv);
    loguru::add_file("logs.txt", loguru::Append, loguru::Verbosity_MAX);
}


//int main(int argc, char* argv[]) {
//    // windows上需要设置控制台编码setlocale(LC_ALL, "zh_CN.UTF-8")
//    setlocale(LC_ALL, "zh_CN.UTF-8");
//
//    InitLog(argc, argv);
//
//    TsharkManager tsharkManager("C:/Users/JNXB/source/repos/SuperShark/SuperShark/");
//
//    // 启动监控
//    tsharkManager.startMonitorAdaptersFlowTrend();
//
//    // 睡眠10秒，等待监控网卡数据
//    std::this_thread::sleep_for(std::chrono::seconds(5));
//
//    // 读取监控到的数据
//    std::map<std::string, std::map<long, long>> trendData;
//    tsharkManager.getAdaptersFlowTrendData(trendData);
//
//    // 停止监控
//    tsharkManager.stopMonitorAdaptersFlowTrend();
//
//    // 把获取到的数据打印输出
//    rapidjson::Document resDoc;
//    rapidjson::Document::AllocatorType& allocator = resDoc.GetAllocator();
//    resDoc.SetObject();
//    rapidjson::Value dataObject(rapidjson::kObjectType);
//    for (const auto& adaptorItem : trendData) {
//        rapidjson::Value adaptorDataList(rapidjson::kArrayType);
//        for (const auto& timeItem : adaptorItem.second) {
//            rapidjson::Value timeObj(rapidjson::kObjectType);
//            timeObj.AddMember("time", (unsigned int)timeItem.first, allocator);
//            timeObj.AddMember("bytes", (unsigned int)timeItem.second, allocator);
//            adaptorDataList.PushBack(timeObj, allocator);
//        }
//
//        dataObject.AddMember(rapidjson::StringRef(adaptorItem.first.c_str()), adaptorDataList, allocator);
//    }
//
//    resDoc.AddMember("data", dataObject, allocator);
//
//    // 序列化为 JSON 字符串
//    rapidjson::StringBuffer buffer;
//    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
//    resDoc.Accept(writer);
//
//     LOG_F(INFO, "网卡流量监控数据: %s", buffer.GetString());
//
//    return 0;
//}

//#include <fstream>
//
//int main(int argc, char* argv[]) {
//
//    // windows上需要设置控制台编码setlocale(LC_ALL, "zh_CN.UTF-8")
//    setlocale(LC_ALL, "zh_CN.UTF-8");
//
//    InitLog(argc, argv);
//
//    TsharkManager tsharkManager("C:/Users/JNXB/source/repos/SuperShark/SuperShark/");
//
//    // 全静态类也要初始化实例才能调用
//    IP2RegionUtil ip2RegionUtil;
//    ip2RegionUtil.init("C:/Users/JNXB/source/repos/SuperShark/SuperShark/third_library/ip2region/ip2region.xdb");
//
//    //tsharkManager.startCapture("\\Device\\NPF_{87C48D23-8C5A-4157-840B-83DC2CD817B9}"); // WLAN
//    //tsharkManager.startCapture("\\Device\\NPF_{A52835D4-9B60-44BE-9285-9EDD48F8F97F}"); // 以太网
//    
//    // 主线程进入命令等待停止抓包
//    std::string input;
//    std::cout << "请输入要分析的PCAP文件路径: ";
//    // C:\Users\JNXB\source\repos\SuperShark\SuperShark\data\packets.pcap
//    std::cin >> input;
//    tsharkManager.analysisFile(input);
//    std::cout << "请输入要获取详情的数据包编号（1-" << tsharkManager.getPacketSize() << "）:";
//    int index;
//    std::cin >> index;
//
//    std::string result;
//    if (tsharkManager.getPacketDetailInfo(index, result)) {
//        LOG_F(INFO, result.c_str());
//        // 将 JSON 内容保存到 n.json
//        std::string fileName = std::to_string(index) + ".json";
//        std::ofstream outFile(fileName);
//        if (outFile.is_open()) {
//            outFile << result;
//            outFile.close();
//            std::cout << "数据包详情已保存到 " << fileName << std::endl;
//        } else {
//            LOG_F(ERROR, "无法创建文件 %s", fileName.c_str());
//            return -1;
//        }
//    } else {
//        LOG_F(ERROR, "获取数据包详情失败");
//        return -1;
//    }
//    
//
//    return 0;
//}




//int main(int argc, char* argv[]) {
//    // Windows 控制台设置为 UTF-8 编码（确保中文输出正确）
//    setlocale(LC_ALL, "zh_CN.UTF-8");
//
//    // 初始化日志（示例）
//    InitLog(argc, argv);
//
//    // 输入数据（确保存在于 map 和 unordered_map 中）
//    const std::string input = "Time delta from previous displayed frame";
//    Translator translator;
//
//    // 对比 map 的查询效率
//    volatile size_t dummy = 0;  // 防止编译器优化
//    auto start_map = std::chrono::high_resolution_clock::now();
//    for (int i = 0; i < 10000; i++) {
//        std::string result = translator.translationMap.at(input);
//        dummy += result.size(); // 确保循环不被优化
//    }
//    auto end_map = std::chrono::high_resolution_clock::now();
//    auto duration_map = std::chrono::duration_cast<std::chrono::microseconds>(end_map - start_map).count();
//
//    // 对比 unordered_map 的查询效率
//    auto start_unordered_map = std::chrono::high_resolution_clock::now();
//    for (int i = 0; i < 10000; i++) {
//        std::string result = translator.translationUnorderedMap.at(input);
//        dummy += result.size(); // 确保循环不被优化
//    }
//    auto end_unordered_map = std::chrono::high_resolution_clock::now();
//    auto duration_unordered_map = std::chrono::duration_cast<std::chrono::microseconds>(end_unordered_map - start_unordered_map).count();
//
//    // 输出结果
//    std::cout << "std::map 查询 10000 次耗时: " << duration_map << " 微秒\n";
//    std::cout << "std::unordered_map 查询 10000 次耗时: " << duration_unordered_map << " 微秒\n";
//
//    return 0; // 返回 0 表示正常退出
//}


//#include "sqlite3/sqlite3.h"
//#include <iostream>
//#include <string>
//
//int main(int argc, char* argv[]) {
//
//    // Windows 控制台设置为 UTF-8 编码（确保中文输出正确）
//    setlocale(LC_ALL, "zh_CN.UTF-8");
//
//    sqlite3* db;
//    char* errMessage = 0;
//
//    // 打开数据库（如果没有数据库文件，它会创建一个）
//    int rc = sqlite3_open("packets.db", &db);
//    if (rc) {
//        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << std::endl;
//        return (0);
//    }
//    else {
//        std::cout << "Opened database successfully" << std::endl;
//    }
//
//
//
//    // 创建表的SQL语句
//    std::string createTableSQL = R"(
//            CREATE TABLE IF NOT EXISTS t_packets (
//                frame_number INTEGER PRIMARY KEY,
//                src_ip TEXT,
//                src_port INTEGER,
//                dst_ip TEXT,
//                dst_port INTEGER
//            );
//        )";
//
//    // 执行SQL语句来创建数据表
//    rc = sqlite3_exec(db, createTableSQL.c_str(), nullptr, nullptr, &errMessage);
//    if (rc != SQLITE_OK) {
//        std::cerr << "SQL error: " << errMessage << std::endl;
//        sqlite3_free(errMessage);
//    }
//    else {
//        std::cout << "Table created successfully" << std::endl;
//    }
//
//    char* errMsg = nullptr;
//    int rcc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errMsg);
//    if (rcc != SQLITE_OK) {
//        // 优先使用 sqlite3_errmsg 获取错误信息
//        const char* detailedErr = sqlite3_errmsg(db);
//        LOG_F(ERROR, "开启事务失败 (错误码 %d): %s", rcc, detailedErr ? detailedErr : "未知错误");
//        if (errMsg) sqlite3_free(errMsg);
//        return false;
//    }
//
//    // 插入一条示例数据
//    const char* insertSQL = "INSERT INTO t_packets (frame_number, src_ip, src_port, dst_ip, dst_port) VALUES (1, '192.168.1.1', 12345, '192.168.1.2', 80);";
//    rc = sqlite3_exec(db, insertSQL, nullptr, 0, &errMessage);
//    if (rc != SQLITE_OK) {
//        std::cerr << "SQL error: " << errMessage << std::endl;
//        sqlite3_free(errMessage);
//    }
//    else {
//        std::cout << "Records created successfully" << std::endl;
//    }
//
//
//    // 关闭数据库
//    sqlite3_close(db);
//
//    return 0;
//}




std::shared_ptr<TsharkManager> g_ptrTsharkManager;

httplib::Server::HandlerResponse before_request(const httplib::Request& req, httplib::Response& res) {
    LOG_F(INFO, "Request received for %s", req.path.c_str());

    // 提取分页参数
    PageAndOrder* pageAndOrder = PageHelper::getPageAndOrder();
    pageAndOrder->pageNum = BaseController::getIntParam(req, "pageNum", 1);
    pageAndOrder->pageSize = BaseController::getIntParam(req, "pageSize", 100);
    pageAndOrder->orderBy = BaseController::getStringParam(req, "orderBy", "");
    pageAndOrder->descOrAsc = BaseController::getStringParam(req, "descOrAsc", "asc");
    return httplib::Server::HandlerResponse::Unhandled;
}


void after_response(const httplib::Request& req, httplib::Response& res) {
    if (req.method != "OPTIONS") {
        res.set_header("Access-Control-Allow-Origin", "http://localhost:5173");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.set_header("Access-Control-Allow-Credentials", "true");
    }
    LOG_F(INFO, "Received response with status %d", res.status);
}


int main(int argc, char* argv[]) {

    // Windows 控制台设置为 UTF-8 编码（确保中文输出正确）
    setlocale(LC_ALL, "zh_CN.UTF-8");

    // capture command = "D:\\Tools\\Wireshark\\tshark -i \Device\NPF_{A52835D4-9B60-44BE-9285-9EDD48F8F97F} -c 100 -F pcap -w packets.pcap"

    InitLog(argc, argv);
 
    // WLAN "\\Device\\NPF_{87C48D23-8C5A-4157-840B-83DC2CD817B9}"
    // 以太网 "\\Device\\NPF_{A52835D4-9B60-44BE-9285-9EDD48F8F97F}"

    //std::string Tshark_dir;
    //std::cout << "请输入Tshark路径: ";
    //std::cin >> Tshark_dir;
    //g_ptrTsharkManager = std::make_shared<TsharkManager>(Tshark_dir);
    g_ptrTsharkManager = std::make_shared<TsharkManager>("C:/Users/JNXB/source/repos/SuperShark/SuperShark");

    //std::string packet_dir;
    //std::cout << "请输入要分析的数据包路径: ";
    //std::cin >> packet_dir;
    //g_ptrTsharkManager->analysisFile(packet_dir);
    g_ptrTsharkManager->analysisFile("C:/Users/JNXB/source/repos/SuperShark/SuperShark/data/packets.pcap");
    //g_ptrTsharkManager->printAllSessions();
    //g_ptrTsharkManager->startCapture("\\Device\\NPF_{A52835D4-9B60-44BE-9285-9EDD48F8F97F}");

    // 主线程进入命令等待停止抓包
    //std::string input;
    //while (true) {
    //    std::cout << "请输入q退出抓包: ";
    //    std::cin >> input;
    //    if (input == "q") {
    //        g_ptrTsharkManager->stopCapture();
    //        break;
    //    }
    //}

    // 打印所有捕获到的数据包信息
    //g_ptrTsharkManager->printAllPackets();
     
     //网卡信息

    //std::vector<AdapterInfo> adaptors = tsharkManager.getNetworkAdapters();
    //for (auto item : adaptors) {
    //    LOG_F(INFO, "网卡[%d]: name[%s] remark[%s]", item.id, item.name.c_str(), item.remark.c_str());
    //}



    // 第 11 课

    ////tsharkManager.startCapture("\\Device\\NPF_{87C48D23-8C5A-4157-840B-83DC2CD817B9}"); // WLAN
    //tsharkManager.startCapture("\\Device\\NPF_{A52835D4-9B60-44BE-9285-9EDD48F8F97F}"); // 以太网

    //// 主线程进入命令等待停止抓包
    //std::string input;
    //while (true) {
    //    std::cout << "请输入q退出抓包: ";
    //    std::cin >> input;
    //    if (input == "q") {
    //        tsharkManager.stopCapture();
    //        break;
    //    }
    //}

    //// 打印所有捕获到的数据包信息
    //tsharkManager.printAllPackets();

     
	// 第 12 课

    //    std::string input;
    //    std::cout << "请输入要分析的PCAP文件路径: ";
    //    // C:\Users\JNXB\source\repos\SuperShark\SuperShark\data\packets.pcap
    //    std::cin >> input;
    //    tsharkManager.analysisFile(input);
    
    // 创建一个 HTTP 服务器对象
    httplib::Server server;
    server.Options(".*", [](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "http://localhost:5173");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, PUT");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With");
        res.set_header("Access-Control-Allow-Credentials", "true");
        res.status = 200;
        });

    // 设置钩子函数
    server.set_pre_routing_handler(before_request);
    server.set_post_routing_handler(after_response);

    // 创建Controller并注册路由
	std::vector<std::shared_ptr<BaseController>> controllersList;
	controllersList.push_back(std::make_shared<PacketController>(server, g_ptrTsharkManager));
	controllersList.push_back(std::make_shared<AdaptorController>(server, g_ptrTsharkManager));
	controllersList.push_back(std::make_shared<SessionController>(server, g_ptrTsharkManager));
	controllersList.push_back(std::make_shared<StatsController>(server, g_ptrTsharkManager));
    

	for (auto controller : controllersList) {
		controller->registerRoute();
	}

    // 启动服务器，监听 8080 端口
    server.listen("127.0.0.1", 8080);

    return 0;
}
