#include<stdio.h>
#include<stdlib.h>
#include<string.h>


/* comment out it if whole qname needs to copied to the response
 * else keep it for compression
*/
//#define use_compression


/* comment out it before using in network
 * else keep it for in development
*/
#define windows

#ifdef windows

#include<winsock.h>

#else

#include<netinet/in.h>
#include<arpa/inet.h>

#endif

#define type_A      1
#define type_NS     2
#define type_MD     3
#define type_MF     4
#define type_CNAME  5
#define type_SOA    6
#define type_MB     7
#define type_MG     8
#define type_MR     9
#define type_NULL   10
#define type_WKS    11
#define type_PTR    12
#define type_HINFO  13
#define type_Minfo  14
#define type_MX     15
#define type_TXT    16

#define DNS_QUERY_BIT       0
#define DNS_RESPONSE_VALUE    1


#define class_IN    1
#define class_CS    2
#define class_CH    3
#define class_HS    4

#define MAX_LABEL_LENGTH 64

#define MAX_DOMAIN_NAME_LENGTH 256
#define MAX_RDATA_LENGTH 256 ///since we are generating this field we can set the rdata length according to out needs

#define MAX_IP_SIZE 16

struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short qdcount; // number of question entries
    unsigned short ancount; // number of answer entries
    unsigned short nscount; // number of authority entries
    unsigned short arcount; // number of resource entries
};


struct DNS_QUESTION
{
    unsigned char qname[MAX_DOMAIN_NAME_LENGTH];
    unsigned short qtype;
    unsigned short qclass;
};

struct DNS_ANSWER
{
    unsigned char name[MAX_DOMAIN_NAME_LENGTH];  /* this array suppose to store the domain name in question
 *                             but we store the memory offset to which domain name is stored in the query
 *                             this is done by domain name compression technique
 *                          */

    unsigned short type;
    unsigned short class;
    unsigned int ttl;
    unsigned short rd_length;

    unsigned char rdata[MAX_RDATA_LENGTH];
};


/**
 * function reads the domain name from the dns query message
 * @param qname | stores the domain name
 * @param reader | pointing to the position in the dns message where domain name starts
 * @return number of bytes read from the dns question counting from the starting position of the domain name so that the
 *         reader can be moved forward
 */
int read_domain_name(unsigned char *qname, unsigned char *reader, unsigned char *buf)
{
    unsigned char compressed = 0;
    unsigned int index = 0, offset;

    int count = 0;

    while (*reader != 0)
    {
        if (*reader >= 192)
        {
            offset = (*reader) * 256 + *(reader + 1) - 49152;   /*  if data is compressed the value starts with 11 and
                                                                    the remaining 14 bits in the 2 byte field represents
                                                                    the memory address where the next characters of the
                                                                    domain is stored
                                                                */
            reader = buf + offset - 1;
            compressed = 1;
        } else
        {
            qname[index++] = *reader;
        }

        reader++;

        if (compressed == 0)
            count++;
    }

    count++;
    qname[index++] = '\0';
    if (compressed == 1)
    {
        count++;
    }
    return count;
}

/**
 * reads the dns message header and stores the location in header pointer
 * @param header | it is a pointer to a pointer so that we can keep the changes after function call
 *                  header has to a pointer to pointer because we want to point it to the actual dns message
 *                  so that we can change the dns message through the structure when returning the response
 *                  message
 * @param reader | it is a pointer to a pointer so that we can keep the changes after function call
 *                 reader points to the dns message buffer, after reading the header we increament it to make it
 *                 ready to read values after the header
 */
void read_header(struct DNS_HEADER **header, unsigned char **reader)
{
    *header = (struct DNS_HEADER *) (*reader);
    *reader += sizeof(struct DNS_HEADER);
}


/**
 * this function take dns question structure and message reader pointing to the start if the question after the dns header
 * @param question | dns question structure pointer for storing the qname, qtype, qclass
 * @param reader | pointer to pointer for reading the dns query message and incrementing the reader for reading next values in the query or
 *                 writing the response after the query in the same message buffer
 */
void read_question(struct DNS_QUESTION *question, unsigned char **reader, unsigned char *buf)
{
    int reader_moved = 0;

    reader_moved = read_domain_name(question->qname, *reader, buf);
    *reader += reader_moved;

    question->qtype = *((unsigned short *) (*reader));
    *reader += sizeof(question->qtype);

    question->qclass = *((unsigned short *) (*reader));
    *reader += sizeof(question->qclass);
}

/**
 * initializes the answer for writing dns response message with redirection ip
 * @param answer | structure for holding the components of dns answer
 * @param question | structure that has the values from dns query message ,used for type and class
 */
void init_answer(struct DNS_ANSWER *answer, struct DNS_QUESTION *question)
{
    unsigned char redirection_ip[MAX_IP_SIZE];

    FILE *fp;
    fp = fopen("E:\\config", "r");
    if (fp == NULL)
    {
        printf("could not open config file\n");
        exit(0);
    }

    fgets((char*)redirection_ip, MAX_IP_SIZE, fp);
    fclose(fp);

    memset(answer->name,0,sizeof(answer->name));

    struct in_addr in;

    unsigned short name_location=(192*256)+12;  /// 11000000 00001100   indicating compression and offset=12
    /// this is for domain name compression
    /// 192 12 is for the offset of where the domain was previously saved
    /// since we know the domain name was stored after dns header so we set the
    /// offset value to 12, means domain name is at after 12 bytes in the dns message
    /// this will work untill dns query format is changed which is unlikely
#ifdef windows
    answer->ttl = 2;
    in.s_addr = 757935405;
    answer->rd_length = sizeof(in.s_addr);
#else
    name_location=htons(name_location);
    answer->ttl=htons(2);
    inet_aton(redirection_ip,&in);
    answer->rd_length = htons(sizeof(in.s_addr));
#endif

#ifdef use_compression
    memcpy(answer->name,(unsigned char*)&name_location,sizeof(unsigned short));
#else
    memcpy(answer->name,question->qname,strlen((const char*)question->qname));
#endif
    answer->type = question->qtype;
    answer->class = question->qclass;
    if (memcpy(answer->rdata, (unsigned char *) &in.s_addr, sizeof(in.s_addr)) == NULL)
    {
        perror("Unable to copy redirection IP to rdata");
    }
}

/**
 * this functions writes dummy response message at the position where query ends
 * @param writer | pointer to the position after the question where answers starts
 * @param answer | structure which holds the dummy data, used for writing dummy response in dns message
 */
void write_answer(unsigned char **writer, struct DNS_ANSWER *answer)
{
    int size;
#ifdef use_compression
    size=0;
#else
    size=1;
#endif
    memcpy(*writer, answer->name, strlen((const char*)answer->name)+size);
    *writer += strlen((const char*)answer->name)+size;   /// if we stored the actual domain name instead of offset then we had to
                                       /// store another character in the writer for NULL termination of string

    memcpy(*writer, (unsigned char *) &(answer->type), sizeof(unsigned short));
    *writer += sizeof(unsigned short);

    memcpy(*writer, (unsigned char *) &answer->class, sizeof(unsigned short));
    *writer += sizeof(unsigned short);

    memcpy(*writer, (unsigned char *) &answer->ttl, sizeof(unsigned int));
    *writer += sizeof(unsigned int);

    memcpy(*writer, (unsigned char *) &answer->rd_length, sizeof(unsigned short));
    *writer += sizeof(unsigned short);

    memcpy(*writer, answer->rdata, strlen((const char*)answer->rdata));
    *writer += sizeof(unsigned short);
}

/**
 * changes the header values for dns response
 * @param header
 */
void change_dnsheader_for_response(struct DNS_HEADER *header)
{
    header->qr = 1; /// for response

#ifdef windows
    header->ancount = 1;
#else
    header->ancount = htons(1);  /// one answer which is the redirection ip
#endif
}

unsigned char *generate_fake_dns_response(unsigned char *dns_message)
{

    unsigned char *reader, *writer;

    struct DNS_HEADER *dnsheader;
    struct DNS_QUESTION question;
    struct DNS_ANSWER answer;

    reader = dns_message;

    read_header(&dnsheader, &reader);

    change_dnsheader_for_response(dnsheader);

    read_question(&question, &reader, dns_message);

    init_answer(&answer, &question);

    writer = reader;

    write_answer(&writer, &answer);

    return dns_message;
}


void test()
{
    int i;

    struct DNS_HEADER *dns;
    unsigned char buf[50000], *reader;
    memset(buf, 0, sizeof(buf));

    dns = (struct DNS_HEADER *) buf;

    dns->id = (unsigned short) (111);

    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->rcode = 0;

    dns->qdcount = (1);
    dns->ancount = 0;
    dns->nscount = 0;
    dns->arcount = 0;

    reader = buf;
    reader += sizeof(struct DNS_HEADER);

    unsigned char domain[100] = "3www6google3com0";

    for (i = 0; i < strlen((const char*)domain); i++)
    {
        if (domain[i] >= '0' && domain[i] <= '9')
        {
            domain[i] -= '0';
        }
    }

    memcpy(reader, domain, strlen(domain) + 1);
    reader += strlen(domain) + 1;

    unsigned short *x;
    x = (unsigned short *) reader;
    *x = (1);
    reader += 2;

    x = (unsigned short *) reader;
    *x = (1);
    reader += 2;


    for (i = 0; i < 40; i++)
    {
        printf("%d %d\n", i, (buf[i]));
    }

    printf("******************query*******************");

    int query_size = sizeof(struct DNS_HEADER) + (strlen((const char *) domain) + 1) + 4;
    printf("\n\nquery size - %d\n", query_size);

    generate_fake_dns_response(buf);

    for (i = 0; i < 70; i++)
    {
        printf("%d %d\n", i, (buf[i]));
    }

    dns=(struct DNS_HEADER*)buf;
    printf("ans count - %d\n",dns->ancount);
    reader = buf + query_size;
    unsigned char name[1000];
    int moved = read_domain_name(name, reader, buf);

    printf("%d %s\n", moved, name);

    reader += moved;

    printf("current pos - %d\n", reader - buf);

    unsigned short type = *((unsigned short *) reader);
    printf("type - %d\n", (type));
    reader += sizeof(unsigned short);
    printf("current pos - %d\n", reader - buf);

    unsigned class = *((unsigned short *) reader);
    printf("class - %d\n", class);
    reader += sizeof(unsigned short);
    printf("current pos - %d\n", reader - buf);

    unsigned int ttl = *((unsigned int *) reader);
    printf("ttl - %d\n", ttl);
    reader += sizeof(unsigned int) + 2;

    printf("current pos - %d\n", reader - buf);
    unsigned int ip = *((unsigned int *) reader);
    printf("ip - %d", ip);
}

int main()
{
    test();


}