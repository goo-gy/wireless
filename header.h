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
enum ENCRYPT  { OPN, WEP, WPA = 2, WPA2 = 4 };
enum CIPHER  { TKIP = 2, AES = 4 };
enum AUTH  { MGT = 1, PSK = 2 };

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
	u_char pair_cipher;
	u_char auth;
public:
        AP_H()
        {
		channel = 0;
		beacon_count = 0;
		data_count = 0;
		encrypt = OPN;
		pair_cipher = 0;
		auth = 0;
        }

	void Set_info(const u_char *packet)
	{
		encrypt = OPN;
		pair_cipher = 0;
		auth = 0;

		radio_h *radio;
		radio = (radio_h*)packet;

		channel = (radio->channel_frequency-2407)/5;
		//cout << radio->channel_frequency << " " << channel << endl;
		SSI_signal = radio->SSI_signal;

		IEEE11_h *IEEE11;
		IEEE11 = (IEEE11_h*)(packet+radio->header_length);
		
		u_char type = (IEEE11->FC_subtype & 0x0c) >> 2;
		u_char subtype = (IEEE11->FC_subtype & 0xF0) >> 4;

		u_char wep = (IEEE11->FC_subtype & 0x02) >> 1;
		if(wep)
			encrypt = WEP;

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
				BSSID.push_back(*(IEEE11->ADDR3+i));
			}
                        u_char *LAN = (u_char*)(IEEE11)+24+12;  // IEEE Beacon 24, fixed 12
                        Tag(LAN);
		}
	}

	void Tag(u_char *LAN)
	{
		u_char tag_length;
		tag_length = *(LAN+1);

		switch(*LAN)
		{
			u_short cipher_count;
			u_short auth_count;
			case 0:
				ESSID.assign((char*)(LAN+2), tag_length);
				break;
			case 48:
				encrypt = *(LAN+4+3);
				cipher_count = *((u_short*)(LAN+8));
				pair_cipher = *(LAN + 10 + 3);
				auth = *(LAN + 10 + 4*cipher_count + 2 + 3);
				printf("%d\n", *(LAN+4+3));
				break;
			case 221:
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
			case 4:
				printf("%-4s ", "WPA2");
				break;
			default:
				printf("%-7s ", "ERROR");
		}
                switch(pair_cipher)
                {
			case 0:
                                printf("%6s  ", "");
				break;
                        case 2:
                                printf("%6s  ", "TKIP");
                                break;
                        case 4:
                                printf("%6s  ", "CCMP");
                                break;
                        default:
				printf("%6s  ", "ERROR");
                }
		switch(auth)
		{
			case 0:
                                printf("%-5s ", "");
                                break;
			case 1:
                                printf("%-5s ", "MGT");
                        case 2:
                                printf("%-5s ", "PSK");
                                break;
                        default:
                                printf("%-5s ", "ERROR");
                }
		cout << ESSID << endl;
	}
};
