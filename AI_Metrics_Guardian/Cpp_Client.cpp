#include <iostream>
#include <boost/asio.hpp>
#include <nlohmann/json.hpp>  // Include this for JSON

using boost::asio::ip::tcp;
using json = nlohmann::json;
/*

system monitor class
initialize com+wmi once in a class
use menber functions in parallel to collect data
no need of mutex as it has read only methods

*/
#include<iostream>
#include<chrono>
#include<wbemidl.h>
#include<windows.h>
#include<comdef.h>
#include<thread>
#include<fstream>

#include <wchar.h>
#pragma comment(lib,"wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")


using json = nlohmann::json;

class SystemMonitor {
private:
    IWbemLocator* pLocator = nullptr;
    IWbemServices* pServices = nullptr;
public:
    SystemMonitor() {
        HRESULT hres;

        //1.initialize com

        HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hr)) throw std::runtime_error("COM init failed");

        //2.set security of com

        hr = CoInitializeSecurity(
            NULL, -1, NULL, NULL,
            RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE, NULL
        );
        if (FAILED(hr)) throw std::runtime_error("COM security init failed");


        // 3.pointer (locator) pf wmi

        hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
            IID_IWbemLocator, (LPVOID*)&pLocator);
        if (FAILED(hr)) throw std::runtime_error("WbemLocator creation failed");

        // 4.initialize wmi connection

        BSTR namespaceStr = SysAllocString(L"ROOT\\CIMV2");
        hr = pLocator->ConnectServer(
            namespaceStr, NULL, NULL, 0, LONG(0), 0, 0, &pServices
        );
        SysFreeString(namespaceStr);
        if (FAILED(hr)) throw std::runtime_error("WMI connect failed");


        // 5.proxy blanket for wmi security

        hr = CoSetProxyBlanket(
            pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL, EOAC_NONE
        );
        if (FAILED(hr)) throw std::runtime_error("WMI proxy blanket failed");

        std::cout << "WMI Initialized Successfully\n";

    }

    ~SystemMonitor() {
        if (pServices) pServices->Release();
        if (pLocator) pLocator->Release();
    }
    // Helper to get a uint32 value from VARIANT safely
    uint32_t GetUInt32FromVariant(VARIANT& vt) {
        if (vt.vt == VT_UI4) {  // unsigned int 32
            return vt.uintVal;
        }
        else if (vt.vt == VT_I4) { // signed int 32
            return static_cast<uint32_t>(vt.intVal);
        }
        else if (vt.vt == VT_BSTR) { // string, try to convert to int
            return static_cast<uint32_t>(_wtoi(vt.bstrVal));
        }
        else if (vt.vt == VT_R4) { // float
            return static_cast<uint32_t>(vt.fltVal);
        }
        else if (vt.vt == VT_R8) { // double
            return static_cast<uint32_t>(vt.dblVal);
        }
        else if (vt.vt == VT_EMPTY || vt.vt == VT_NULL) {
            return 0; // no data
        }
        else {
            // try VariantChangeType to VT_UI4
            VARIANT vtDest;
            VariantInit(&vtDest);
            HRESULT hr = VariantChangeType(&vtDest, &vt, 0, VT_UI4);
            if (SUCCEEDED(hr)) {
                uint32_t val = vtDest.uintVal;
                VariantClear(&vtDest);
                return val;
            }
            VariantClear(&vtDest);
            return 0; // fallback zero
        }

    }

    float GetFloatFromVariant(VARIANT& vt) {
        if (vt.vt == VT_R4) return vt.fltVal;
        if (vt.vt == VT_R8) return static_cast<float>(vt.dblVal);
        if (vt.vt == VT_BSTR) return static_cast<float>(_wtof(vt.bstrVal));
        return 0.0f;
    }
    std::string BSTRToString(BSTR bstr) {
        if (!bstr) return "";

        int len = WideCharToMultiByte(CP_UTF8, 0, bstr, -1, NULL, 0, NULL, NULL);
        if (len == 0) return "";

        std::string str(len - 1, 0); // len includes null terminator
        WideCharToMultiByte(CP_UTF8, 0, bstr, -1, &str[0], len, NULL, NULL);

        return str;
    }


    json GetCPUInfo() {
        json cpuInfoJson = json::array();

        IEnumWbemClassObject* pEnumerator = nullptr;

        //  wmi query for each cpu (Win32_PerfFormattedData_PerfOS_Processor)
        BSTR queryLang = SysAllocString(L"WQL");
        BSTR queryStr = SysAllocString(L"SELECT Name, PercentProcessorTime, PercentUserTime, PercentPrivilegedTime, PercentIdleTime FROM Win32_PerfFormattedData_PerfOS_Processor");

        HRESULT hr = pServices->ExecQuery(
            queryLang,
            queryStr,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        SysFreeString(queryLang);
        SysFreeString(queryStr);
        if (FAILED(hr)) {
            std::cerr << "Failed to run WMI query for CPU performance data. " << std::endl;
            return cpuInfoJson;
        }
        IWbemClassObject* pClassObject = nullptr;
        ULONG uReturn = 0;

        while (pEnumerator) {
            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
            if (uReturn == 0) break;

            VARIANT vtProp;
            json singleCPU;


            // name
            pClassObject->Get(L"Name", 0, &vtProp, 0, 0);


            singleCPU["Name"] = BSTRToString(vtProp.bstrVal);

            VariantClear(&vtProp);
            // processortime
            pClassObject->Get(L"PercentProcessorTime", 0, &vtProp, 0, 0);
            singleCPU["ProcessorTime"] = GetUInt32FromVariant(vtProp);
            VariantClear(&vtProp);

            // usertime

            pClassObject->Get(L"PercentUserTime", 0, &vtProp, 0, 0);
            singleCPU["UserTime"] = GetUInt32FromVariant(vtProp);
            VariantClear(&vtProp);

            // kernel time
            pClassObject->Get(L"PercentPrivilegedTime", 0, &vtProp, 0, 0);
            singleCPU["KernelTime"] = GetUInt32FromVariant(vtProp);
            VariantClear(&vtProp);

            // idle time
            pClassObject->Get(L"PercentIdleTime", 0, &vtProp, 0, 0);
            singleCPU["IdleTime"] = GetUInt32FromVariant(vtProp);
            VariantClear(&vtProp);

            // adding to main array
            cpuInfoJson.push_back(singleCPU);
            pClassObject->Release();

        }

        if (pEnumerator) pEnumerator->Release();
        return cpuInfoJson;


    }

    json GetDiskInfo() {
        json diskInfoJson = json::array();

        std::map<std::string, json> diskMap;

        
        IEnumWbemClassObject* pEnumerator = nullptr;
        BSTR queryLang = SysAllocString(L"WQL");
        BSTR queryStr = SysAllocString(
            L"SELECT Name, FreeSpace, Size, FileSystem FROM Win32_LogicalDisk WHERE DriveType=3"
        );

        HRESULT hr = pServices->ExecQuery(queryLang, queryStr,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        SysFreeString(queryLang);
        SysFreeString(queryStr);

        if (FAILED(hr)) {
            std::cerr << "Failed logical disk WMI query." << std::endl;
            return diskInfoJson;
        }

        IWbemClassObject* pClassObject = nullptr;
        ULONG uReturn = 0;
        VARIANT vtProp;

        while (pEnumerator && SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn)) && uReturn != 0) {
            json singleDisk;

            // Name
            pClassObject->Get(L"Name", 0, &vtProp, 0, 0);
            std::string name = BSTRToString(vtProp.bstrVal);
            singleDisk["Name"] = name;
            VariantClear(&vtProp);

            // FileSystem
            pClassObject->Get(L"FileSystem", 0, &vtProp, 0, 0);
            singleDisk["FileSystem"] = vtProp.vt == VT_NULL ? "Unknown" : BSTRToString(vtProp.bstrVal);
            VariantClear(&vtProp);

            // Total Size
            pClassObject->Get(L"Size", 0, &vtProp, 0, 0);
            singleDisk["TotalSize"] = vtProp.vt == VT_NULL ? 0 : wcstoll(vtProp.bstrVal, nullptr, 10);
            VariantClear(&vtProp);

            // Free Space
            pClassObject->Get(L"FreeSpace", 0, &vtProp, 0, 0);
            singleDisk["FreeSpace"] = vtProp.vt == VT_NULL ? 0 : wcstoll(vtProp.bstrVal, nullptr, 10);
            VariantClear(&vtProp);

            diskMap[name] = singleDisk;
            pClassObject->Release();
        }
        if (pEnumerator) pEnumerator->Release();

        
        queryLang = SysAllocString(L"WQL");
        queryStr = SysAllocString(L"SELECT Name, PercentDiskTime, AvgDiskSecPerRead, AvgDiskSecPerWrite, CurrentDiskQueueLength FROM Win32_PerfFormattedData_PerfDisk_LogicalDisk");

        hr = pServices->ExecQuery(queryLang, queryStr,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
        SysFreeString(queryLang);
        SysFreeString(queryStr);

        if (FAILED(hr)) {
            std::cerr << "Failed performance disk WMI query." << std::endl;
            return diskInfoJson;
        }

        while (pEnumerator && SUCCEEDED(pEnumerator->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn)) && uReturn != 0) {
            // Name
            pClassObject->Get(L"Name", 0, &vtProp, 0, 0);
            std::string name = BSTRToString(vtProp.bstrVal);
            VariantClear(&vtProp);

            if (diskMap.find(name) != diskMap.end()) {
                // % Disk Time
                pClassObject->Get(L"PercentDiskTime", 0, &vtProp, 0, 0);
                diskMap[name]["PercentDiskTime"] = GetUInt32FromVariant(vtProp);
                VariantClear(&vtProp);

                // AvgDiskSecPerRead
                pClassObject->Get(L"AvgDiskSecPerRead", 0, &vtProp, 0, 0);
                diskMap[name]["AvgDiskSecPerRead"] = GetFloatFromVariant(vtProp);
                VariantClear(&vtProp);

                // AvgDiskSecPerWrite
                pClassObject->Get(L"AvgDiskSecPerWrite", 0, &vtProp, 0, 0);
                diskMap[name]["AvgDiskSecPerWrite"] = GetFloatFromVariant(vtProp);
                VariantClear(&vtProp);

                // Queue Length
                pClassObject->Get(L"CurrentDiskQueueLength", 0, &vtProp, 0, 0);
                diskMap[name]["QueueLength"] = GetUInt32FromVariant(vtProp);
                VariantClear(&vtProp);
            }
            pClassObject->Release();
        }
        if (pEnumerator) pEnumerator->Release();

      
        for (auto& pair : diskMap) {
            diskInfoJson.push_back(pair.second);
        }

        return diskInfoJson;
    }


    json GetNetworkInfo() {
        json networkInfoJson = json::array();

        IEnumWbemClassObject* pEnumAdapters = nullptr;
        BSTR queryLang = SysAllocString(L"WQL");
        BSTR queryStr = SysAllocString(L"SELECT Name, NetEnabled, NetConnectionStatus FROM Win32_NetworkAdapter");

        HRESULT hr = pServices->ExecQuery(
            queryLang,
            queryStr,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumAdapters
        );

        SysFreeString(queryLang);
        SysFreeString(queryStr);

        if (FAILED(hr)) {
            std::cerr << "Failed to run WMI query for network adapter data." << std::endl;
            return networkInfoJson;
        }

        std::map<std::string, json> adapterMap;
        IWbemClassObject* pClassObject = nullptr;
        ULONG uReturn = 0;

        while (pEnumAdapters) {
            hr = pEnumAdapters->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
            if (uReturn == 0) break;

            VARIANT vtProp;
            json adapter;

            // Adapter Name
            pClassObject->Get(L"Name", 0, &vtProp, 0, 0);
            std::string name = BSTRToString(vtProp.bstrVal);
            adapter["Name"] = name;
            VariantClear(&vtProp);

            // NetEnabled
            pClassObject->Get(L"NetEnabled", 0, &vtProp, 0, 0);
            adapter["NetEnabled"] = (vtProp.vt != VT_NULL && vtProp.vt != VT_EMPTY) ? (vtProp.boolVal == VARIANT_TRUE) : false;
            VariantClear(&vtProp);

            // NetConnectionStatus
            pClassObject->Get(L"NetConnectionStatus", 0, &vtProp, 0, 0);
            adapter["NetConnectionStatus"] = GetUInt32FromVariant(vtProp);
            VariantClear(&vtProp);

            adapterMap[name] = adapter;
            pClassObject->Release();
        }
        if (pEnumAdapters) pEnumAdapters->Release();

        // Get Performance Metrics
        IEnumWbemClassObject* pEnumPerf = nullptr;
        queryLang = SysAllocString(L"WQL");
        queryStr = SysAllocString(L"SELECT Name, BytesSentPerSec, BytesReceivedPerSec, PacketsOutboundErrors, PacketsReceivedErrors, OutputQueueLength FROM Win32_PerfFormattedData_Tcpip_NetworkInterface");

        hr = pServices->ExecQuery(
            queryLang,
            queryStr,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumPerf
        );

        SysFreeString(queryLang);
        SysFreeString(queryStr);

        if (FAILED(hr)) {
            std::cerr << "Failed to run WMI query for network interface stats." << std::endl;
            return networkInfoJson;
        }

        pClassObject = nullptr;
        uReturn = 0;

        while (pEnumPerf) {
            hr = pEnumPerf->Next(WBEM_INFINITE, 1, &pClassObject, &uReturn);
            if (uReturn == 0) break;

            VARIANT vtProp;

            // Name (for matching)
            pClassObject->Get(L"Name", 0, &vtProp, 0, 0);
            std::string name = BSTRToString(vtProp.bstrVal);
            VariantClear(&vtProp);

            if (adapterMap.find(name) != adapterMap.end()) {
                json& adapter = adapterMap[name];

                // BytesSentPerSec
                pClassObject->Get(L"BytesSentPerSec", 0, &vtProp, 0, 0);
                adapter["BytesSentPerSec"] = GetUInt32FromVariant(vtProp);
                VariantClear(&vtProp);

                // BytesReceivedPerSec
                pClassObject->Get(L"BytesReceivedPerSec", 0, &vtProp, 0, 0);
                adapter["BytesReceivedPerSec"] = GetUInt32FromVariant(vtProp);
                VariantClear(&vtProp);

                // PacketsOutboundErrors
                pClassObject->Get(L"PacketsOutboundErrors", 0, &vtProp, 0, 0);
                adapter["PacketsOutboundErrors"] = GetUInt32FromVariant(vtProp);
                VariantClear(&vtProp);

                // PacketsReceivedErrors
                pClassObject->Get(L"PacketsReceivedErrors", 0, &vtProp, 0, 0);
                adapter["PacketsReceivedErrors"] = GetUInt32FromVariant(vtProp);
                VariantClear(&vtProp);

                // OutputQueueLength
                pClassObject->Get(L"OutputQueueLength", 0, &vtProp, 0, 0);
                adapter["OutputQueueLength"] = GetUInt32FromVariant(vtProp);
                VariantClear(&vtProp);
            }

            pClassObject->Release();
        }

        if (pEnumPerf) pEnumPerf->Release();

       
        for (auto& entry : adapterMap) {
            networkInfoJson.push_back(entry.second);
        }

        return networkInfoJson;
    }


};





int main() {
    SystemMonitor monitor;

    json finalJson;

    json cpuJson, diskJson, networkJson;

    std::thread t1([&]() { cpuJson = monitor.GetCPUInfo();});
    std::thread t2([&]() { diskJson = monitor.GetDiskInfo();});
    std::thread t4([&]() { networkJson = monitor.GetNetworkInfo(); });

    t1.join();
    t2.join();
    t4.join();

    finalJson["CPU"] = cpuJson;
    finalJson["Disk"] = diskJson;
    finalJson["Network"] = networkJson;

    try {
        boost::asio::io_context io;
        tcp::socket socket(io);
        socket.connect(tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 12345));

        std::cout << "Connected to server\n";

        
        std::string msg = finalJson.dump();

        // Send the JSON data
        boost::asio::write(socket, boost::asio::buffer(msg));

        // Receive response from server
        char reply[1024];
        size_t reply_length = socket.read_some(boost::asio::buffer(reply));
        std::cout << "Server replied: " << std::string(reply, reply_length) << "\n";

        socket.close();
    }
    catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}
