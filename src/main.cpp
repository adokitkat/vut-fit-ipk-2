#include <iostream>
#include <string>
#include <cstring>
#include <ctime>
#include <chrono>
#include <atomic>
#include <iomanip>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <getopt.h>

#include <net/ethernet.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

using std::cout;
using std::endl;
using std::string;

// Structure for easy passing of custom time stamp
struct timeStamp
{
    std::tm* time;
    std::chrono::microseconds microseconds;
};

// Global arguments
std::atomic<int>    packetCount {1};
string              mode {"both"}, port;
pcap_t*             handle;

// Prints time with microseconds
void printTime(timeStamp t) {
    cout << std::setw(2) << std::setfill('0') << t.time->tm_hour
        << ":" << std::setw(2) << std::setfill('0') << t.time->tm_min
        << ":" << std::setw(2) << std::setfill('0') <<  t.time->tm_sec
        << "." << t.microseconds.count() << " ";
    std::cout.copyfmt(std::ios(nullptr));
}

// Prints content - hex & ASCII representation
void printContent(int &line, const u_char* data, int data_size) {
    int i {0};
    for (; i < data_size; ++i) {
        if (i != 0 and i % 16 == 0) { // text representation
            cout << "   ";
            for (auto j = i - 16 ; j < i ; ++j) {
                if(data[j] >= 32 and data[j] < 127) {cout << (unsigned char)data[j];}
                else {cout << ".";}
            }
            cout << endl;
        }

        if (i % 16 == 0) { // print 0xXXXX on start of a line
            cout << "0x" << std::setw(4) << std::setfill('0') << line << ":  ";
            std::cout.copyfmt(std::ios(nullptr));
            line += 10;
        }
        // hex form
        cout << " " << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)data[i];
        std::cout.copyfmt(std::ios(nullptr));
                
        if (i == data_size - 1) { //print the last spaces
            for (auto j = 0; j < (15 - (i % 16)); ++j) {cout << "   ";} // extra spaces
            cout << "   ";
            for (auto j = i - (i % 16) ; j <= i ; ++j) {
                if (data[j] >= 32 and data[j] < 127) {cout << (unsigned char)data[j];}
                else {cout << ".";}
            }
        cout << endl;
        }
    }
    cout << endl;
}

// Prints head and payload of packet
void printPacket(const u_char* header, int header_size, const u_char* data, int data_size) {
    int line {0};
    printContent(line, header, header_size);
    if (data_size > 0) {printContent(line, data, data_size);}
}

// Saves custom timestamp
timeStamp saveTime() {
    struct timeStamp stamp;

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    stamp.time = std::localtime(&t);
     
    auto fraction = now - std::chrono::time_point_cast<std::chrono::seconds>(now);
    stamp.microseconds = std::chrono::duration_cast<std::chrono::microseconds>(fraction);

    return stamp;
}

// Callback function for pcap_loop()
void callbackPacketHandler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet_buffer) {
    if (packetCount <= 0) {pcap_breakloop(handle);}
    
    auto time = saveTime();
    auto size = header->len; //size of a whole packet
    const struct iphdr* ip_header = (struct iphdr*)(packet_buffer + sizeof(struct ethhdr)); 
    u_short ip_header_len = (ip_header->ihl) * 4;
    
    auto version = AF_INET;
    if (ip_header->version == 6) {version = AF_INET6;}

    struct in_addr addr_src_bin; struct in_addr addr_dest_bin;
    addr_src_bin.s_addr = ip_header->saddr;
    addr_dest_bin.s_addr = ip_header->daddr;
    auto addr_src = inet_ntoa(addr_src_bin);
    auto addr_dest = inet_ntoa(addr_dest_bin);
    struct hostent* name_src; struct hostent* name_dest;

    switch (ip_header->protocol)
    {
        case 6: { // TCP
            if ((packetCount <= 0) or (mode != "both" and mode != "tcp")) {break;}

            const struct tcphdr* tcp_header {(struct tcphdr*)(packet_buffer + sizeof(struct ethhdr) + ip_header_len)};
            auto header_size = sizeof(struct ethhdr) + ip_header_len + (tcp_header->doff) * 4;
            const u_char* data = packet_buffer + header_size;
            auto data_size = size - header_size;

            printTime(time);

            if ((name_src = gethostbyaddr(&addr_src_bin, sizeof(addr_src_bin), version)) != nullptr) {
                    cout << name_src->h_name;
            } else {cout << addr_src;}

            cout << " : " << ntohs(tcp_header->source) << " > ";

            if ((name_dest = gethostbyaddr(&addr_dest_bin, sizeof(addr_dest_bin), version)) != nullptr) {
                    cout << name_dest->h_name;
            } else {cout << addr_dest;}

            cout << " : " << ntohs(tcp_header->dest) << endl << endl;
            printPacket(packet_buffer, header_size, data, data_size);

            --packetCount;
            break;
        }
        case 17: { // UDP
            if ((packetCount <= 0) or (mode != "both" and mode != "udp")) {break;}

            const struct udphdr* udp_header {(struct udphdr*)(packet_buffer + sizeof(struct ethhdr) + ip_header_len)};
            auto header_size = sizeof(struct ethhdr) + ip_header_len + sizeof(udp_header);
            const u_char* data = packet_buffer + header_size;
            auto data_size = size - header_size;
            
            printTime(time);

            if ((name_src = gethostbyaddr(&addr_src_bin, sizeof(addr_src_bin), version)) != nullptr) {
                    cout << name_src->h_name;
            } else {cout << addr_src;}
            
            cout << " : " << ntohs(udp_header->source) << " > ";

            if ((name_dest = gethostbyaddr(&addr_dest_bin, sizeof(addr_dest_bin), version)) != nullptr) {
                    cout << name_dest->h_name;
            } else {cout << addr_dest;}
            
            cout << " : " << ntohs(udp_header->dest) << endl << endl;
            printPacket(packet_buffer, header_size, data, data_size);

            --packetCount;
            break;
        }
        default:
            break;
    }
}

// Function for help text
void showHelp() {
    cout << "./ipk-sniffer flags" << endl
         << "Possible flags:" << endl
         << "    -i               = show interfaces" << endl
         << "    -i interface     = start sniffing on the selected interface" << endl
         << "    -p port          = target selected port, default all" << endl
         << "    -t/u (--tcp/udp) = target selected protocol, default both" << endl
         << "    -n number        = max number of captured packets, default 1" << endl
         ;
}

// Start of a program
int main(int argc, char* argv[])
{
    string  interface;
    bool    show_interfaces {false}, tcp {false}, udp {false};
    int     arg {0};
    const struct option long_options[] =
    {
        {"tcp", no_argument, nullptr, 't'},
        {"udp", no_argument, nullptr, 'u'},
        {nullptr, no_argument, nullptr, 0}
    };

    // Load arguments
    while (arg != -1)
    {
        arg = getopt_long (argc, argv, "i::p:tun:", long_options, nullptr);
        switch (arg)
        {
        case 'i':
            if (!optarg and argv[optind] != nullptr and argv[optind][0] != '-') {
                interface = string(argv[optind++]);
            }
            else {show_interfaces = true; arg = -1;}
            break;

        case 'p':
            port = "port " + string(optarg);
            break;

        case 't':
            tcp = true;
            break;
        
        case 'u':
            udp = true;
            break;

        case 'n':
            packetCount = std::stoi(optarg);
            break;

        case 'h':
        case '?':
            showHelp();
            return 0;
        default:
            break;
        }
    }
    
    // If interface is not selected and program is not called with -i argument, then show help
    if (interface == "" and show_interfaces == false) {
        showHelp();
        return 0;
    }

    // Selects protocol
    if (tcp and udp)    {mode = "both";}
    else if (tcp)       {mode = "tcp";}
    else if (udp)       {mode = "udp";}

    // Creates list of available interfaces
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* device_list = nullptr;
    if(pcap_findalldevs(&device_list, errbuf) != 0) {
        cout << "pcap_findalldevs() failed:" << errbuf << endl;
        return 1;
    }

    // Loops through interfaces and finds selected one
    pcap_if_t* device = nullptr;
    for (pcap_if_t* curr_device = device_list; curr_device; curr_device = curr_device->next) {
        if (show_interfaces == true)        {cout << curr_device->name << endl;}
        if (curr_device->name == interface) {device = curr_device;}
    }

    // If argument -i is without paramenter, shows available interfaces
    if (show_interfaces == true) {pcap_freealldevs(device_list); return 0;}
    
    // If selected interface is not found
    if (!device) {
        pcap_freealldevs(device_list);
        cout << "Interface not found." << endl;
        return 1;
    }

    // Opens interface for catpuring packets
    handle = pcap_open_live(device->name, BUFSIZ, 1, 0, errbuf);
    if (!handle) {
        pcap_freealldevs(device_list);
        cout << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }
    pcap_freealldevs(device_list);

    // If ran with argument -p port, set and compile filter
    if (port != "") {
        bpf_program  filter;
        if (pcap_compile(handle, &filter, port.c_str(), 1, 0) == -1) {
            pcap_close(handle);
            cout << "pcap_compile() failed: " << pcap_geterr(handle);
            return 1;
        }
        if (pcap_setfilter(handle, &filter) == -1) {
            pcap_close(handle);
            cout << "pcap_setfilter() failed: " << pcap_geterr(handle);
            return 1;
        }
    }
    
    // Start capturing
    if (pcap_loop(handle, -1, callbackPacketHandler, nullptr) == PCAP_ERROR) {
        pcap_close(handle);
        cout << "pcap_loop() failed: " << pcap_geterr(handle);
        return 1;
    }
    pcap_close(handle);
    return 0;
}
