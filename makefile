all: wireless.cpp header.h
	g++ -o Wireless wireless.cpp -lpcap
