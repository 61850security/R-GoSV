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

/* Session layer fields*/ 
char session_id = 0xA1; 
char length_id = 0x18;  
char common_header= 0x80;
char l_id = 0x16; 
char spdu_length1=0x00; 
char spdu_length2=0x00; 
char spdu_length3=0x00; 
char spdu_length4=0xC7;
char spdu_num1=0x00;    
char spdu_num2=0x00;
char spdu_num3=0x00;
char spdu_num4=0x0D;
char ver1=0x00;
char ver2=0x01;
char TimeofCurrentKey1=0x5B; 
char TimeofCurrentKey2=0xFC; 
char TimeofCurrentKey3=0xF6;
char TimeofCurrentKey4=0xB0;
char TimeofNextKey1=0x00;
char TimeofNextKey2=0x3C; 
char sa1=0x00; 
char sa2=0x03; 
char keyID1=0x00; 
char keyID2=0x00;
char keyID3=0x00;
char keyID4=0x0C;
char len1=0x00; 
char len2=0x00;
char len3=0x00;
char len4=0x8F;
char pl_type=0x81; 
char simulation=0x01; 
char APPID1=0x00;
char APPID2=0x01;
char length1=0x00; 
char length2=0x89;

/* GOOSE APDU fields according to IEC 61850-8-1*/.
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
int main(int argc, char *argv[])
{
    
    int j=0;
    unsigned char Data[346];
    unsigned char key[32]= { 
			0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66, 0x5f, 0x8a, 0xe6, 0xd1,
                        0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69, 0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f 
			   };
    unsigned char *hash,hash_string[32];

    /* Session layer fields along with GOOSE APDU fields to generate 32 bytes of HMAC value*/
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
				}; 

    for ( j=0; j<173; j++)
    {
	sprintf( &(Data[j * 2]) , "%02x", signature_data[j]); 
        //printf(" %s",Data);
    }
    hash = HMAC(EVP_sha256(), key, strlen((char *)key), signature_data, strlen((char *) signature_data), NULL, NULL);

    for (j = 0; j < 32 ; j++)
	sprintf(&(hash_string[j * 2]), "%02x", hash[j]);
    printf("\n \n Hash value: %s \n", hash_string);
    
    
   return 0;
}

	
