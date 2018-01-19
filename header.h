typedef struct radio_header
{
	u_char revision;
	u_char pad;
	u_short header_length;
	u_int present_flags;		//Too many;;
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

typedef struct AP_header
{
	char *BSSID;		// string
	char *ESSID;		//
	u_char channel;
	char SSI_signal;
	u_char encrypt;		//
	u_char cipher;
	u_char auth;
	u_int beacon_count;
}AP_h;
// 34 bytes
