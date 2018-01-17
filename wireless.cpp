#include <iostream>
#include <cstdio>
#include <pcap.h>
#include "header.h"

#include <arpa/inet.h>

using namespace std;


void print_MAC(u_char *MAC)
{
	for(int i = 0; i < 6; i++)
	{
		printf(":%02X", *(MAC+i));
	}
	cout << endl;
	return;
}

int main(int argc, char *argv[])
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];		//What is this?

	pcap_t *handle = NULL;
	struct pcap_pkthdr *header;
	const u_char *packet;
	radio_h *radio;
	IEEE11_h *IEEE11;
	int mode;

	if(argc == 1)
	{
		cout << "Wire [Device]" << endl;
	}
	else if(argc ==2)
	{
		//Add try exception
		handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);	//Use device
	}
	else
	{
		cout << "Give only one device" << endl;
		return 0;
	}

	while(true)
	{
		mode = pcap_next_ex(handle, &header, &packet);
		if(mode == 0)
			continue;
		else if(mode == -1)
			break;
		else if(mode == -2)
		{
			cout << "[End of File]" << endl;
			break;
		}
		radio = (radio_h*)packet;
		IEEE11 = (IEEE11_h*)(packet+radio->header_length);
		u_char type_subtype;
		type_subtype = IEEE11->FC_subtype & 0xF3;
		type_subtype = (type_subtype >> 4) + (type_subtype << 4);

		printf("Type_Subtype: %02X\t", type_subtype);
		switch(type_subtype)
		{
			case 4:
				cout << "[Probe request]" << endl;
				break;
			case 5:
				cout << "[Probe response]" << endl;
				break;
			case 8:
				cout << "[Beacon Frame]" << endl;
				break;
			case 11:
				cout << "[Authentication]" << endl;
				break;
			case 12:
				cout << "[DeAuthentication]" << endl;
				break;
			default:
				cout << "[I Don't Know]" << endl;
				continue;
		}
		cout << "Receiver/Destination\t";
		print_MAC(IEEE11->ADDR1);
		cout << "Transmitter/Source\t";
		print_MAC(IEEE11->ADDR2);
		cout << "BSSID\t\t\t";
		print_MAC(IEEE11->ADDR3);
		cout << endl;
	}
	pcap_close(handle);
	return 0;
}
