#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>

/* enter your intended MAC address*/
#define DEST_MAC0    0xFC
#define DEST_MAC1    0x61
#define DEST_MAC2    0x98
#define DEST_MAC3    0x8A
#define DEST_MAC4    0x1F
#define DEST_MAC5    0x2F

#define IF_NAME     "eno1"
#define B_SIZE     2048

/* Enter your custom values in hexa decimal    */
char a[64][10]= { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x00, 0x0A, 0x14, 0x1E, 0x28, 0x32, 0x3C, 0x46, 0x50, 0x5A,
                  0x00, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 
                  0x00, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
                  0x00, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x0A, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
                  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 
                  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
                  0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 
		  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 
                  0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
                  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 
                  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
                  0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 
		  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 
                  0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
                  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 
                  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
                  0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 
		  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                  0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 
                  0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64, 0x64,
                  0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 
                  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 
                  0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14,
                  0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                  0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
                  0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16, 0x16 };
/* IP Header fields */
char ver_hl =0x45;  // version 4 and header length of ip is 20 (5) bytes (1 byte)
char tos = 0x00; // type of service. IP precedence and Differentiated Service code point (1 byte)
char totlen1 = 0x00; // Total length of the packet (header 20 + udp packet size 150= 170 bytes) (2 bytes)
char totlen2 = 0xAA;                    
char identification1 = 0x6B; // unique identification of each packet (2 bytes) 
char identification2 = 0xA1;
char frag_off1 = 0x00; //if the packets are fragmented, then this field will be used. (2 bytes)
char frag_off2 = 0x00;
char ttl = 0x80; // time to live (1 byte)
char protocol = 0x11; // next protocol in the sequence UDP (1 byte)
char hdrchks1 = 0x00; // header check sum (2 bytes)
char hdrchks2 = 0x00;

// source IP address (4 bytes)
char srcaddr0 = 0xEF; //239    127 --> 0x7F
char srcaddr1 = 0xBF; //191    0   --> 0x00
char srcaddr2 = 0x69; //105    0   --> 0x00
char srcaddr3 = 0xBA; //186    1   --> 0x01

// destination IP address (4 bytes)
char dstaddr0 = 0xC0; //192
char dstaddr1 = 0xA8; //168
char dstaddr2 = 0x01; //1
char dstaddr3 = 0x03; //3


/* UDP Header fields */
char srcport1 = 0xDA;
char srcport2 = 0xD1;

char dstport1 = 0x00;
char dstport2 = 0x66;

char lengt1= 0x00;
char lengt2 = 0x96; /* length of udp header 8 + udp pay load size 142 = 150   */  

char chksum1 = 0xD7;
char chksum2 = 0x3B; 
/* Session header */
char len_id = 0x01; /* Length identifier according to RFC1240 OSI connectionless transport services over */
char t_id = 0x40; // transport identifier 
char session_id = 0xA2; /* Non-tunnlled SV */
char length_id = 0x18;  /*  length of common session header 22  + length id 1 + common header 1 = 24 */
char common_header= 0x80;
char l_id = 0x16; /* length of common session header spdu length 4 + spdu num 4 + version 2 + timeofcurrent key 4 + timeofnextkey 2 + 
                          security algorithm 2 + keyID 4 = 22 bytes */
char spdu_length1=0x00; /* length of entire SPDU =199 bytes */
char spdu_length2=0x00; /* spdu num 4 + ver 2 + TofCkey 4 + TofNKey 2 + SA 2 + keyID 4 + len 4 + pl_type 1 + simulation 1  */
char spdu_length3=0x00; /* APPID 2 + length 2 + sv payload data size 102 + signature 1 + sig_len 1 =132 */
char spdu_length4=0x84;
char spdu_num1=0x00;    /* spdu unique identification number */
char spdu_num2=0x00;
char spdu_num3=0x00;
char spdu_num4=0x0C;
char ver1=0x00;
char ver2=0x01;
char TimeofCurrentKey1=0x00; /*hexadecimal timestamp/epoch */
char TimeofCurrentKey2=0x00; 
char TimeofCurrentKey3=0x00;
char TimeofCurrentKey4=0x00;
char TimeofNextKey1=0x00;
char TimeofNextKey2=0x00; /* 60 minutes for time of next key */
char sa1=0x00; /* Encryption algorithms used :None*/
char sa2=0x00; /* authentication algorithm used HMAC-SHA256 */
char keyID1=0x00; 
char keyID2=0x00;
char keyID3=0x00;
char keyID4=0x0D;
char len1=0x00; /* 1 payload type + 1 simulation + 2 APPDI + 2 length + sv payload data size 102 =108 */
char len2=0x00;
char len3=0x00;
char len4=0x6C;
char pl_type=0x82; /* 81 for GOOSE 82 for SV */
char simulation=0x00; 
char APPID1=0x00;
char APPID2=0x01;
char length1=0x00; /* sv payload data size 101 (38+64=102) */
char length2=0x66;

//sv data
char sav_PDU_tag=0x60;               /* sav_PDU tag  */
char sav_PDU_length=0x64; 	     /* sav_PDU length - size of APDU */
char noASDU_tag=0x80;		     /* number of ASDU tag  */ 
char noASDU_length=0x01;             /* number of ASDU length */
char noASDU=0x01;                    /* noASDU value  */
char SequenceofASDU_tag=0xA2;        /* SequenceofASDU tag   */
char SequenceofASDU_length=0x5F;     /* SequenceofASDU length - size of all ASDU  */
char ASDU_tag=0x30;                  /* ASDU tag */
char ASDU_length=0x5D;               /* ASDU length */
char svID_tag =0x80;                 /* Sample Value identifier tag   */
char svID_length =0x0C;              /* Sample Value identifier length */
char svID_1=0x46;                    /*  svID[12] naming   */
char svID_2=0x52;
char svID_3=0x45;
char svID_4=0x41;
char svID_5=0x2D;
char svID_6=0x47;
char svID_7=0x6F;
char svID_8=0x53;
char svID_9=0x56;
char svID_10=0x2D;  
char svID_11=0x31;
char svID_12=0x20;
char smpCnt_tag=0x82;                /* sample count tag */
char smpCnt_length =0x02;            /* sample count length */
char smpCnt_1=0x00;                  /* sample count */
char smpCnt_2=0x01;
char confRev_tag=0x83;               /* confRev tag - configuratin revision number */
char confRev_length=0x04;            /* confRev length */
char confRev1=0x00;                  /* confRev value */
char confRev2=0x00; 	     
char confRev3=0x00;
char confRev4=0x01;                   
char smpSynch_tag = 0x85;            /* smpSynch tag -synchronization identifier */
char smpSynch_length =0x01;          /* smpSynch_length */
char smpSynch =0x00; 		     /* smpSynch value  */
char SequenceofData_tag =0x87;       /* SequenceofData tag */
char SequenceofData_length=0x40;     /* SequenceofData length */
// sample count values
char smp[15] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

char signature=0x85; 
char sig_len=0x00; /* length of the signature value 0 */ 

int main(int argc, char *argv[])
{
    int sfd;
    int i=0,j=0,q=0;
    struct ifreq if_idx;
    struct ifreq if_mac;
    int tx_len;
    unsigned char sendbuf[B_SIZE],Data[173];
    struct sockaddr_ll socket_address; /* The sockaddr_ll structure is a device-independent physical-layer address.*/
    char ifName[IFNAMSIZ];

    /* Get interface name */
    strcpy(ifName, IF_NAME);

    /* Open RAW socket to send on */
    if ((sfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) 
    {
        perror("socket");
    }
    
    /* clear the struct ifreq if_idx with memset system call */
    memset(&if_idx, 0, sizeof(struct ifreq));

    /* copy interface name into struct ifreq if_idx */
    strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);

    /* configure the interface index */ 
    if (ioctl(sfd, SIOCGIFINDEX, &if_idx) < 0)
        perror("SIOCGIFINDEX");
    
    // Loop forever
    while(1) 
    {

        /* Buffer of BUF_SIZ bytes we'll construct our frame in.
           First, clear it all to zero. */
        memset(sendbuf, 0, B_SIZE);
        tx_len = 0;

        /* Construct the UDP header */

        /* Destination MAC address */
        sendbuf[tx_len++] = DEST_MAC0;
        sendbuf[tx_len++] = DEST_MAC1;
        sendbuf[tx_len++] = DEST_MAC2;
        sendbuf[tx_len++] = DEST_MAC3;
        sendbuf[tx_len++] = DEST_MAC4;
        sendbuf[tx_len++] = DEST_MAC5;

	   /* Source MAC address */
        sendbuf[tx_len++] = 0xA0;
        sendbuf[tx_len++] = 0xB3;
        sendbuf[tx_len++] = 0xCC; 
        sendbuf[tx_len++] = 0xC5; 
        sendbuf[tx_len++] = 0x77; 
        sendbuf[tx_len++] = 0xA1; 

        /* Ethertype field IP protocol */
        sendbuf[tx_len++] = 0x08;
        sendbuf[tx_len++] = 0x00;

        /*  PDU fields */
        sendbuf[tx_len++] = ver_hl;                  
        sendbuf[tx_len++] = tos; 
        sendbuf[tx_len++] = totlen1;                 
        sendbuf[tx_len++] = totlen2;
        sendbuf[tx_len++] = identification1;
	sendbuf[tx_len++] = identification2;                   
	sendbuf[tx_len++] = frag_off1;
        sendbuf[tx_len++] = frag_off2;                  
        sendbuf[tx_len++] = ttl;
        sendbuf[tx_len++] = protocol;
        sendbuf[tx_len++] = hdrchks1;
        sendbuf[tx_len++] = hdrchks2;
        sendbuf[tx_len++] = srcaddr0;
        sendbuf[tx_len++] = srcaddr1;
        sendbuf[tx_len++] = srcaddr2;
        sendbuf[tx_len++] = srcaddr3;
        sendbuf[tx_len++] = dstaddr0;
        sendbuf[tx_len++] = dstaddr1;
        sendbuf[tx_len++] = dstaddr2;
        sendbuf[tx_len++] = dstaddr3;

        sendbuf[tx_len++] = srcport1;
        sendbuf[tx_len++] = srcport2;
        sendbuf[tx_len++] = dstport1;
	sendbuf[tx_len++] = dstport2;
	sendbuf[tx_len++] = lengt1;
	sendbuf[tx_len++] = lengt2;
	sendbuf[tx_len++] = chksum1;
	sendbuf[tx_len++] = chksum2;
	
        sendbuf[tx_len++] = len_id;
	sendbuf[tx_len++] = t_id;
        sendbuf[tx_len++] = session_id;
	sendbuf[tx_len++] = length_id;
	sendbuf[tx_len++] = common_header;
	sendbuf[tx_len++] = l_id;
	sendbuf[tx_len++] = spdu_length1;
	sendbuf[tx_len++] = spdu_length2;
	sendbuf[tx_len++] = spdu_length3;
	sendbuf[tx_len++] = spdu_length4;
        sendbuf[tx_len++] = spdu_num1;
	sendbuf[tx_len++] = spdu_num2;
	sendbuf[tx_len++] = spdu_num3;
	sendbuf[tx_len++] = spdu_num4;
	sendbuf[tx_len++] = ver1;
	sendbuf[tx_len++] = ver2;
        sendbuf[tx_len++] = TimeofCurrentKey1;
        sendbuf[tx_len++] = TimeofCurrentKey2;
        sendbuf[tx_len++] = TimeofCurrentKey3;
	sendbuf[tx_len++] = TimeofCurrentKey4;
        sendbuf[tx_len++] = TimeofNextKey1;
        sendbuf[tx_len++] = TimeofNextKey2;
	sendbuf[tx_len++] = sa1;
	sendbuf[tx_len++] = sa2;
	sendbuf[tx_len++] = keyID1; 
	sendbuf[tx_len++] = keyID2;
	sendbuf[tx_len++] = keyID3;
	sendbuf[tx_len++] = keyID4;
        sendbuf[tx_len++] = len1;
	sendbuf[tx_len++] = len2;
	sendbuf[tx_len++] = len3;
	sendbuf[tx_len++] = len4;
	sendbuf[tx_len++] = pl_type;
	sendbuf[tx_len++] = simulation; /* boolean value*/
	sendbuf[tx_len++] = APPID1;
	sendbuf[tx_len++] = APPID2;
	sendbuf[tx_len++] = length1;
	sendbuf[tx_len++] = length2;

        sendbuf[tx_len++] = sav_PDU_tag;
        sendbuf[tx_len++] = sav_PDU_length;
	sendbuf[tx_len++] = noASDU_tag;
	sendbuf[tx_len++] = noASDU_length;
	sendbuf[tx_len++] = noASDU;
	sendbuf[tx_len++] = SequenceofASDU_tag;
	sendbuf[tx_len++] = SequenceofASDU_length;

	/* ASDU fields */
	sendbuf[tx_len++] = ASDU_tag;
	sendbuf[tx_len++] = ASDU_length;
	sendbuf[tx_len++] = svID_tag;        
        sendbuf[tx_len++] = svID_length;
        sendbuf[tx_len++] = svID_1;
        sendbuf[tx_len++] = svID_2;
	sendbuf[tx_len++] = svID_3;
	sendbuf[tx_len++] = svID_4;
	sendbuf[tx_len++] = svID_5;
	sendbuf[tx_len++] = svID_6;
	sendbuf[tx_len++] = svID_7;
	sendbuf[tx_len++] = svID_8;
	sendbuf[tx_len++] = svID_9;
	sendbuf[tx_len++] = svID_10;
	sendbuf[tx_len++] = svID_11;
	sendbuf[tx_len++] = svID_12;
	sendbuf[tx_len++] = smpCnt_tag;
	sendbuf[tx_len++] = smpCnt_length;
	sendbuf[tx_len++] = smpCnt_1;
        sendbuf[tx_len++] = smpCnt_2;
	//sendbuf[tx_len++] = smp[q];	

	q++;
	if (q==10)
	    q = 0;

        sendbuf[tx_len++] = confRev_tag;	
	sendbuf[tx_len++] = confRev_length;
	sendbuf[tx_len++] = confRev1;
        sendbuf[tx_len++] = confRev2;
	sendbuf[tx_len++] = confRev3;
	sendbuf[tx_len++] = confRev4;
	sendbuf[tx_len++] = smpSynch_tag;
	sendbuf[tx_len++] = smpSynch_length;
        sendbuf[tx_len++] = smpSynch;	
        sendbuf[tx_len++] = SequenceofData_tag;
	sendbuf[tx_len++] = SequenceofData_length;
        
        /* ASDU data */
        for(j=0;j<=63;j++)
           sendbuf[tx_len++]= a[j][i];
       
        i++;
        if ( i == 10)
           i=0;
	sendbuf[tx_len++] = signature;
	sendbuf[tx_len++] = sig_len;

	
      /*sendbuf[tx_len++] = 0xD5;
	sendbuf[tx_len++] = 0xA9;
	sendbuf[tx_len++] = 0x78;
	sendbuf[tx_len++] = 0x2B; */

	/* Index of the network device */
        socket_address.sll_ifindex = if_idx.ifr_ifindex;  /* Network Interface number */

        /* Address length*/
        socket_address.sll_halen = ETH_ALEN; /* Length of Ethernet address */

        /* Destination MAC */
        socket_address.sll_addr[0] = DEST_MAC0;
        socket_address.sll_addr[1] = DEST_MAC1;
        socket_address.sll_addr[2] = DEST_MAC2;
        socket_address.sll_addr[3] = DEST_MAC3;
        socket_address.sll_addr[4] = DEST_MAC4;
        socket_address.sll_addr[5] = DEST_MAC5;

        /* Send packet */
        if (sendto(sfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
            printf("Send failed\n");
        else {
            printf("Sent :");
            for (i=0; i < tx_len; i++)
                printf("%02x:", sendbuf[i]);
            printf("\n");
        }
        /* Wait specified number of microseconds
           1,000,000 microseconds = 1 second
           */
        usleep(1000000);
    }
    return 0;
}

