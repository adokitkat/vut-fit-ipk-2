all: src/main.cpp
	g++ -Wall -std=c++11 -o ipk-sniffer src/main.cpp -lpcap