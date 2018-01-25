#include "header.h"

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
//------------------------------------------------------------------	device
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
//------------------------------------------------------------------	packet capture
	map<MAC, AP_H> AP_group;
	map<MAC, AP_H>::iterator iter;
	AP_H AP_info;

	MAC BSSID;

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

		AP_info.Set_info(packet);
		memcpy(BSSID.mac, AP_info.get_BSSID(), sizeof(BSSID.mac));	// Modify

		if(BEACON == AP_info.get_subtype())
		{
			if(AP_group.end() == AP_group.find(BSSID))
				AP_group.insert(pair<MAC, AP_H>(BSSID, AP_info));
			else
			{
				AP_info.set_beacon(AP_group[BSSID].get_beacon()+1);
				AP_group[BSSID] = AP_info;
			}

			system("clear");
			printf("\n BSSID              PWR  #Beacons  #Data  Frequency  CH  ENC  CIPHER  AUTH  ESSID\n\n");
			for (iter = AP_group.begin(); iter != AP_group.end(); iter++)
			{
				(iter->second).print_info();
			}
			cout << endl;
		}
	}
	pcap_close(handle);
	return 0;
}
