#include <iostream>
#include <cstdio>
#include <pcap.h>
#include "header.h"

#include <arpa/inet.h>

using namespace std;

enum TYPE_SUBTYPE { PROVE_REQUEST, PROVE_RESPONSE, BEACON, AUTH, DEAUTH, ELSE };

void print_MAC(u_char *MAC)
{
	for(int i = 0; i < 6; i++)
	{
		printf(":%02X", *(MAC+i));
	}
	cout << endl;
	return;
}

void Tag(u_char *LAN)
{
	u_char tag_length;
	if(*LAN == 0)
	{
		tag_length = *(LAN+1);
		cout << "ESSID\t\t\t:";
		for (u_char i = 0; i < tag_length; i++)
			cout << *(LAN+2+i);
		cout << endl;
	}
	else if(*LAN == 48)
	{
		cout << "ENC\t\t\t:PWA2" << endl;
	}
	else if(*LAN == 221)
		return;
	else
		return Tag(LAN+tag_length+2);
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

		printf("Frequency\t\t:%d [ch.%d]\n", radio->channel_frequency, (radio->channel_frequency-2407)/5);
		printf("SSI_Signal\t\t:%d dbm\n", radio->SSI_signal);
//------------------------------------------------------------------
		IEEE11 = (IEEE11_h*)(packet+radio->header_length);
		u_char type;
		u_char subtype;

		type = (IEEE11->FC_subtype & 0x0c) >> 2;
		subtype = (IEEE11->FC_subtype & 0xF0) >> 4;

		//subtype = type*0x10 + subtype;
		

		printf("Type\t\t\t:%d\n", type);
		printf("Type_Subtype\t\t:%d\t", subtype);
		
		if(type == 0)
		{
			switch(subtype)
			{
				case 4:
					cout << "[Probe request]" << endl;
					subtype = PROVE_REQUEST;
					break;
				case 5:
					cout << "[Probe response]" << endl;
					subtype = PROVE_RESPONSE;
					break;
				case 8:
					cout << "[Beacon Frame]" << endl;
					subtype = BEACON;
					break;
				case 11:
					cout << "[Authentication]" << endl;
					subtype = AUTH;
					break;
				case 12:
					cout << "[DeAuthentication]" << endl;
					subtype = DEAUTH;
					break;
				default:
					cout << "[I Don't Know]" << endl << endl;
					continue;
			}
		}
		else if(type == 1)
		{
			cout << "[Control Frame]" << endl << endl;
			continue;
		}
		else if(type == 2)
		{
			cout << "[Data Frame]" << endl << endl;
			continue;
		}
		else
		{
			cout << "[None Type]" << endl << endl;
			continue;
		}
		
		cout << "Receiver/Destination\t";
		print_MAC(IEEE11->ADDR1);
		cout << "Transmitter/Source\t";
		print_MAC(IEEE11->ADDR2);
		cout << "BSSID\t\t\t";
		print_MAC(IEEE11->ADDR3);
		

		if(subtype == BEACON)
		{
			u_char *LAN = (u_char*)(IEEE11)+24+12;  // IEEE Beacon 24, fixed 12
			Tag(LAN);
		}
		cout << endl;
	}
	pcap_close(handle);
	return 0;
}
