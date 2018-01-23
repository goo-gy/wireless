#include <iostream>
#include <cstdio>
#include <pcap.h>
#include <arpa/inet.h>
#include <string>
#include <list>
#include <map>
#include <stdlib.h>

using namespace std;

enum TYPE_SUBTYPE { PROVE_REQUEST, PROVE_RESPONSE, BEACON, AUTH, DEAUTH, ELSE };
enum ENCRYPT  { OPN, WEP, WPA, WPA2 };

typedef struct radio_header
{
	u_char revision;
	u_char pad;
	u_short header_length;
	u_int present_flags;
	u_char MAC_timestamp[8];
	u_char flags;	
	u_char data_rate;
	u_short channel_frequency;
	u_short channel_flags;
	char SSI_signal;
	u_char antenna;
	u_short RX_flags;
}radio_h;

typedef struct IEEE11_header
{
	u_char FC_subtype;
	u_char FC_flags;
	u_short Duration_ID;
	u_char ADDR1[6];
	u_char ADDR2[6];
	u_char ADDR3[6];
	u_short Sequence_Control;
	u_char ADDR4[6];
	u_short QoS_Control;
	u_int HT_Control;
}IEEE11_h;

class AP_H {
private:
	list<u_char> BSSID;
        string ESSID;
        u_char channel;
        char SSI_signal;
        unsigned int beacon_count;
        unsigned int data_count;
	u_char type_subtype;
	u_char encrypt;
public:
        AP_H()
        {
		channel = 0;
		beacon_count = 0;
		data_count = 0;
        }

	void Set_info(const u_char *packet)
	{
		encrypt = OPN;

		radio_h *radio;
		radio = (radio_h*)packet;

		channel = (radio->channel_frequency-2407)/5;
		SSI_signal = radio->SSI_signal;

		IEEE11_h *IEEE11;
		IEEE11 = (IEEE11_h*)(packet+radio->header_length);
		
		u_char type = (IEEE11->FC_subtype & 0x0c) >> 2;
		u_char subtype = (IEEE11->FC_subtype & 0xF0) >> 4;

		if( type == 0 )
		{
			switch(subtype)
			{
				case 8:
					type_subtype = BEACON;
					//beacon_count ++;
					break;
				default:
					type_subtype = ELSE;
					return;
			}

		}
		else if(type == 1)		// [Control Frame]
		{
			type_subtype = ELSE;
			return;
		}
		else if(type == 2)		// [Data Frame]
		{
			//data_count++;
			type_subtype = ELSE;
			return;
		}
		else
		{
			type_subtype = ELSE;
			 return;
		 }
                if(type_subtype == BEACON)
                {
			BSSID.clear();
			for(int i = 0; i < 6; i++)
			{
				BSSID.push_back((int)(*(IEEE11->ADDR3+i)));
			}
                        u_char *LAN = (u_char*)(IEEE11)+24+12;  // IEEE Beacon 24, fixed 12
                        Tag(LAN);
		}
	}

	void Tag(u_char *LAN)
	{
		u_char tag_length;
		tag_length = *(LAN+1);
		if(*LAN == 0)
		{
			ESSID.assign((char*)(LAN+2), tag_length);
		}
		else if(*LAN == 48)
		{
			cout << "";
			//cout << "ENC\t\t\t:WPA2 (Not Certain)" << endl;
			encrypt = WPA2;
		}
		else if(*LAN == 221)
		{
			return;
		}
		Tag(LAN+tag_length+2);
	}
	
	u_char get_subtype()
	{
		return type_subtype;
	}
	
	list<u_char> get_MAC()
	{
		return BSSID;
	}
	void set_beacon(unsigned int count)
	{
		beacon_count = count;
	}
	unsigned int get_beacon()
	{
		return beacon_count;
	}
	void print_info()
	{
		cout << "  ";
		printf("%3d  ", SSI_signal);
		printf("%7d  ", beacon_count);
		printf("%6d  ", data_count);
		printf("%2d  ", channel);
		switch(encrypt)
		{
			case 0:
				printf("%-4s ", "OPN");
				break;
			case 1:
				printf("%-4s ", "WEP");
				break;
			case 2:
				printf("%-4s ", "WPA");
				break;
			case 3:
				printf("%-4s ", "WPA2");
				break;
			default:
				cout << "Error" << endl;
		}
		cout << ESSID << endl;
	}
};

