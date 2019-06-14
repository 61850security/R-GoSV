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
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* Keep your intended destination MAC here*/
#define DEST_MAC0    0xFC
#define DEST_MAC1    0x61
#define DEST_MAC2    0x98
#define DEST_MAC3    0x8A
#define DEST_MAC4    0x1F
#define DEST_MAC5    0x2F

#define IF_NAME     "eno1"
#define B_SIZE     2048
/* IP Header fields */
char ver_hl =0x45;  // version 4 and header length of ip is 20 (5) bytes (1 byte)
char tos = 0x00; // type of service. IP precedence and Differentiated Service code point (1 byte)
char totlen1 = 0x00; // Total length of the packet (header 20 + udp packet size 217) (2 bytes)
char totlen2 = 0xED;                    
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
char lengt2 = 0xD9; /* length of udp header 8 + udp pay load size = 209 (38+137+34) = 217 */  

char chksum1 = 0xD7;
char chksum2 = 0x3B; 
/* Session header */
char len_id = 0x01; /* Length identifier according to RFC1240 OSI connectionless transport services over */
char t_id = 0x40; // transport identifier 
char session_id = 0xA1; /* Non-tunnlled goose */
char length_id = 0x18;  /*  length of common session header 22  + length id 1 + common header 1 = 24 */
char common_header= 0x80;
char l_id = 0x16; /* length of common session header spdu length 4 + spdu num 4 + version 2 + timeofcurrent key 4 + timeofnextkey 2 + 
                          security algorithm 2 + keyID 4 = 22 bytes */
char spdu_length1=0x00; /* length of entire SPDU =199 bytes */
char spdu_length2=0x00; /* spdu num 4 + ver 2 + TofCkey 4 + TofNKey 2 + SA 2 + keyID 4 + len 4 + pl_type 1 + simulation 1  */
char spdu_length3=0x00; /* APPID 2 + length 2 + SV size  + signature 1 + sig_len 1 + sign_val 32 =199 */
char spdu_length4=0xC7;
char spdu_num1=0x00;    /* spdu unique identification number */
char spdu_num2=0x00;
char spdu_num3=0x00;
char spdu_num4=0x0D;
char ver1=0x00;
char ver2=0x01;
char TimeofCurrentKey1=0x5B; /*hexadecimal timestamp/epoch */
char TimeofCurrentKey2=0xFC;  /* Tuesday, November 27, 2018 4:48:00 PM */
char TimeofCurrentKey3=0xF6;
char TimeofCurrentKey4=0xB0;
char TimeofNextKey1=0x00;
char TimeofNextKey2=0x3C; /* 60 minutes for time of next key */
char sa1=0x00; /* Encryption algorithms used*/
char sa2=0x03; /* authentication algorithm used */
char keyID1=0x00; 
char keyID2=0x00;
char keyID3=0x00;
char keyID4=0x0C;
char len1=0x00; /* 1 payload type + 1 simulation + 2 APPDI + 2 length + goose data size 137 =143 */
char len2=0x00;
char len3=0x00;
char len4=0x8F;
char pl_type=0x81; /* 81 for GOOSE 82 for SV */
char simulation=0x01; /* boolean value*/
char APPID1=0x00;
char APPID2=0x01;
char length1=0x00; /* goose data size 137 */
char length2=0x89;
/* GOOSE message according to IEC 61850-8-1*/ 
char goosePDU_tag1=0x61;		/* goosePDU tag  */
char goosePDU_tag2=0x81;		
char goosePDU_length=0x86;		/* goosePDU length  */
char gocbRef_tag=0x80;			/* gocbRef (GOOSE Control Block Reference) tag  */
char gocbRef_length=0x1A;		/* gocbRef length  */
char gocbRef_value1=0x46;		/* gocbRef value  */
char gocbRef_value2=0x52;
char gocbRef_value3=0x45;
char gocbRef_value4=0x41;
char gocbRef_value5=0x2D;
char gocbRef_value6=0x47;
char gocbRef_value7=0x6F;
char gocbRef_value8=0x53;
char gocbRef_value9=0x56;
char gocbRef_value10=0x2D;
char gocbRef_value11=0x31;
char gocbRef_value12=0x20;
char gocbRef_value13=0x2F;
char gocbRef_value14=0x4C;
char gocbRef_value15=0x4C;
char gocbRef_value16=0x4E;
char gocbRef_value17=0x30;
char gocbRef_value18=0x24;
char gocbRef_value19=0x47;
char gocbRef_value20=0x4F;
char gocbRef_value21=0x24;
char gocbRef_value22=0x67;
char gocbRef_value23=0x63;
char gocbRef_value24=0x62;
char gocbRef_value25=0x30;
char gocbRef_value26=0x31; 
char timeAllowedtoLive_tag=0x81;	/* timeAllowedtoLive tag  */
char timeAllowedtoLive_length=0x03;	/* timeAllowedtoLive length  */
char timeAllowedtoLive_value1=0x00;	/* timeAllowedtoLive value  */
char timeAllowedtoLive_value2=0x9C;
char timeAllowedtoLive_value3=0x40;
char dataset_tag=0x82;			/* data set tag*/
char dataset_length=0x18;		/* data set length*/
char dataset_value1=0x46;		/* data set value*/
char dataset_value2=0x52;
char dataset_value3=0x45;
char dataset_value4=0x41;
char dataset_value5=0x2D;
char dataset_value6=0x47;
char dataset_value7=0x6F;
char dataset_value8=0x53;
char dataset_value9=0x56;
char dataset_value10=0x2D;
char dataset_value11=0x31;
char dataset_value12=0x20;
char dataset_value13=0x2F;
char dataset_value14=0x4C;
char dataset_value15=0x4C;
char dataset_value16=0x4E;
char dataset_value17=0x30;
char dataset_value18=0x24;
char dataset_value19=0x47;
char dataset_value20=0x4F;
char dataset_value21=0x4F;
char dataset_value22=0x53;
char dataset_value23=0x45;
char dataset_value24=0x31;
char goID_tag=0x83;			/* goID tag*/
char goID_length=0x0B;			/* goID length*/
char goID_value1=0x46;			/* goID value [11]*/
char goID_value2=0x52;
char goID_value3=0x45;
char goID_value4=0x41;
char goID_value5=0x2D;
char goID_value6=0x47;
char goID_value7=0x6F;
char goID_value8=0x53;
char goID_value9=0x56;
char goID_value10=0x2D;
char goID_value11=0x31;
char time_tag=0x84;			/* time tag*/
char time_length=0x08;			/* time length*/
char time_value1=0x38;			/* time value*/
char time_value2=0x6E;
char time_value3=0xBB;
char time_value4=0xF3;
char time_value5=0x42;
char time_value6=0x17;
char time_value7=0x28;
char time_value8=0x0A;			/* st_Num (State Number) tag */
char st_Num_tag=0x85;			/* st_Num length */
char st_Num_length=0x01;		/* st_Num value */
char st_Num_value=0x01;
char sq_Num_tag=0x86;			/* sq_Num (sequence Number) tag */
char sq_Num_length=0x01;		/* sq_Num length */
char sq_Num_value=0x0A;			/* sq_Num value */
char test_tag=0x87;			/*test tag*/
char test_length=0x01;			/*test length*/
char test_value=0x00;			/*test value*/
char confRev_tag=0x88;			/*confRev (Configuration Revision) tag*/
char confRev_length=0x01;		/*confRev length*/
char confRev_value=0x01;		/*confRev value*/
char ndsCom_tag=0x89;			/*ndsCom (needs Commissioning) tag*/
char ndsCom_length=0x01;		/*ndsCom length*/
char ndsCom_value=0x00;			/*ndsCom value*/
char numDatSetEntries_tag=0x8A;		/* number of members of Data Set */
char numDatSetEntries_length=0x01;
char numDatSetEntries_value=0x08;
char alldata_tag=0xAB;			/*all data*/
char alldata_length=0x20;
char alldata_value1=0x83;
char alldata_value2=0x01;
char alldata_value3=0x00;
char alldata_value4=0x84;
char alldata_value6=0x03;
char alldata_value5=0x03;
char alldata_value7=0x00;
char alldata_value8=0x00;
char alldata_value9=0x83;
char alldata_value10=0x01;
char alldata_value11=0x00;
char alldata_value12=0x84;
char alldata_value13=0x03;
char alldata_value14=0x03;
char alldata_value15=0x00;
char alldata_value16=0x00;
char alldata_value17=0x83;
char alldata_value18=0x01;
char alldata_value19=0x00;
char alldata_value20=0x84;
char alldata_value21=0x03;
char alldata_value22=0x03;
char alldata_value23=0x00;
char alldata_value24=0x00;
char alldata_value25=0x83;
char alldata_value26=0x01;
char alldata_value27=0x00;
char alldata_value28=0x84;
char alldata_value29=0x03;
char alldata_value30=0x03;
char alldata_value31=0x02;
char alldata_value32=0x01;

unsigned char goosedata[137] =  
			       { 
				  0x61, 0x81, 0x86, 0x80, 0x1A, 0x46, 0x52, 0x45, 0x41, 0x2D, 0x47, 0x6F, 0x53, 0x56, 0x2D,
				  0x31, 0x20, 0x2F, 0x4C, 0x4C, 0x4E, 0x30, 0x24, 0x47, 0x4F, 0x24, 0x67, 0x63, 0x62, 0x30,
				  0x31, 0x81, 0x03, 0x00, 0x9C, 0x40, 0x82, 0x18, 0x46, 0x52, 0x45, 0x41, 0x2D, 0x47, 0x6F,
				  0x53, 0x56, 0x2D, 0x31, 0x20, 0x2F, 0x4C, 0x4C, 0x4E, 0x30, 0x24, 0x47, 0x4F, 0x4F, 0x53,
				  0x45, 0x31, 0x83, 0x0B, 0x46, 0x52, 0x45, 0x41, 0x2D, 0x47, 0x6F, 0x53, 0x56, 0x2D, 0x31,
				  0x84, 0x08, 0x38, 0x6E, 0xBB, 0xF3, 0x42, 0x17, 0x28, 0x0A, 0x85, 0x01, 0x01, 0x86, 0x01,
                                  0x0A, 0x87, 0x01, 0x00, 0x88, 0x01, 0x01, 0x89, 0x01, 0x00, 0x8A, 0x01, 0x08, 0xAB, 0x20,
				  0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00,
				  0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03,
				  0x02, 0x01
				}; 

unsigned char signature_data[173]=
				{
				  0xA1, 0x18, 0x80, 0x16, 0x00, 0x00, 0x00, 0xC7, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x01, 0x5B, 0xFC,
				  0xF6, 0xB0, 0x00, 0x3C, 0x02, 0x03, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x8F, 0x81, 0x01,
				  0x00, 0x01, 0x00, 0x89, 0x61, 0x81, 0x86, 0x80, 0x1A, 0x46, 0x52, 0x45, 0x41, 0x2D, 0x47, 0x6F,
				  0x53, 0x56, 0x2D, 0x31, 0x20, 0x2F, 0x4C, 0x4C, 0x4E, 0x30, 0x24, 0x47, 0x4F, 0x24, 0x67, 0x63,
				  0x62, 0x30, 0x31, 0x81, 0x03, 0x00, 0x9C, 0x40, 0x82, 0x18, 0x46, 0x52, 0x45, 0x41, 0x2D, 0x47,
				  0x6F, 0x53, 0x56, 0x2D, 0x31, 0x20, 0x2F, 0x4C, 0x4C, 0x4E, 0x30, 0x24, 0x47, 0x4F, 0x4F, 0x53,
				  0x45, 0x31, 0x83, 0x0B, 0x46, 0x52, 0x45, 0x41, 0x2D, 0x47, 0x6F, 0x53, 0x56, 0x2D, 0x31, 0x84,
				  0x08, 0x38, 0x6E, 0xBB, 0xF3, 0x42, 0x17, 0x28, 0x0A, 0x85, 0x01, 0x01, 0x86, 0x01, 0x0A, 0x87,
				  0x01, 0x00, 0x88, 0x01, 0x01, 0x89, 0x01, 0x00, 0x8A, 0x01, 0x08, 0xAB, 0x20, 0x83, 0x01, 0x00,
				  0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00,
				  0x84, 0x03, 0x03, 0x00, 0x00, 0x83, 0x01, 0x00, 0x84, 0x03, 0x03, 0x02, 0x01
				};  //updated 
unsigned char ciphertext[173]=
			     {

				  0xA3, 0x50, 0x43, 0x00, 0xf3, 0x8f, 0x23, 0xb5, 0x3e, 0x07, 0x34, 0x99, 0x75, 0xd8, 0xbe, 0x6f, 
                                  0x7c, 0x66, 0x48, 0x6c, 0xa9, 0xe0, 0x7e, 0x8e, 0x7f, 0x3f, 0x16, 0x02, 0x31, 0x7f, 0x28, 0x4e,
				  0xdc, 0x48, 0xff, 0x26, 0x99, 0xd5, 0x28, 0xa7, 0x22, 0x54, 0x0e, 0x0a, 0x19, 0x93, 0xa4, 0xb7,
				  0x56, 0x52, 0xAD, 0xC9, 0x68, 0x3C, 0x82, 0xFD, 0xAF, 0x30, 0xAF, 0x7D, 0x48, 0xE8, 0x8B, 0x8E,
				  0x9B, 0x7C, 0xF9, 0x1C, 0x27, 0x0B, 0x05, 0xB8, 0x2B, 0xF7, 0x8D, 0xF2, 0x4F, 0x0D, 0xAB, 0x4D,
                                  0x57, 0xDA, 0x29, 0x0B, 0x7E, 0x75, 0x24, 0x24, 0x9A, 0x7C, 0xAA, 0x7A, 0x38, 0x7C, 0x1C, 0xAA,
				  0x8F, 0x39, 0xA8, 0xE3, 0x74, 0xE5, 0xBB, 0x2F, 0x6A, 0x9E, 0x39, 0xB0, 0x32, 0x9D, 0x56, 0x7E,
				  0xA8, 0x83, 0xE3, 0xF8, 0xEB, 0x2E, 0x97, 0xD8, 0x04, 0xA0, 0x4E, 0x56, 0x5D, 0xC6, 0xC2, 0xBB, 
				  0x5B, 0x26, 0x7C, 0x5E, 0x91, 0x41, 0x97, 0x08, 0x15, 0x30, 0x6D, 0x8E, 0x5F, 0x0E, 0x90, 0x13,
				  0xC4, 0x8F, 0xF9, 0x60, 0x66, 0x84, 0x08, 0x30, 0xD9, 0xFB, 0xBA, 0x97, 0x44, 0xC1, 0xBE, 0xA3,
			          0xAD, 0xA6, 0x37, 0x75, 0x18, 0xF6, 0xDB, 0xD8, 0x3E, 0x4B, 0xAA, 0x82, 0x21  
		
			     };	


char signature=0x85; 
char sig_len=0x20; /* length of the signature value 32 bytes generated by HMAC-SHA256*/ 

char sig_val[32]= /* It is calculated from session identifier(SI) to end of user data payload */ 
		{
			0x94, 0x86, 0x5b, 0x96, 0xbf, 0xc8, 0x8d, 0x25, 0x29, 0xd1, 0x15, 0x24, 0xd2, 0x2b, 0xcb, 0x62, 
                        0x58, 0xa5, 0x61, 0x9a, 0x81, 0x91, 0x99, 0x25, 0x06, 0x88, 0x0b, 0x96, 0xfa, 0x9c, 0x6a, 0x8c 
 		};
int main(int argc, char *argv[])
{
    int sfd;
    int i=0,j=0;
    struct ifreq if_idx;
    struct ifreq if_mac;
    int tx_len;
    unsigned char sendbuf[B_SIZE],Data[173];
    struct sockaddr_ll socket_address; /* The sockaddr_ll structure is a device-independent physical-layer address.*/
    char ifName[IFNAMSIZ];
    unsigned char key[14]= { 0x32, 0x21, 0x23, 0x52, 0x71, 0x98, 0x24, 0x03, 0x38, 0x27, 0x01, 0x12, 0x95, 0x23};
    unsigned char *hash;

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
    while(1) {


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
    
    /*  sendbuf[tx_len++] = session_id;
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
	sendbuf[tx_len++] = simulation; 
	sendbuf[tx_len++] = APPID1;
	sendbuf[tx_len++] = APPID2;
	sendbuf[tx_len++] = length1;
	sendbuf[tx_len++] = length2;

        
	for(j=0;j<137;j++)
  	    sendbuf[tx_len++] = goosedata[j];
	*/

	for(j=0;j<173;j++)
  	    sendbuf[tx_len++] = ciphertext[j];
	sendbuf[tx_len++] = signature;
	sendbuf[tx_len++] = sig_len;

        /*    
	for(j=0;j<32;j++)
  	    sendbuf[tx_len++] = hash[j]; */
	for(j=0;j<32;j++)
  	    sendbuf[tx_len++] = sig_val[j];

	/*sendbuf[tx_len++] = 0x3C;
	sendbuf[tx_len++] = 0x1D;
	sendbuf[tx_len++] = 0x1C;
	sendbuf[tx_len++] = 0x98;  */
	
	sendbuf[tx_len++] = 0xEF;
	sendbuf[tx_len++] = 0x1B;
	sendbuf[tx_len++] = 0x13;
	sendbuf[tx_len++] = 0x81; 

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

