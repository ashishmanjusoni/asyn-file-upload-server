#include<iostream>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<string.h>
#include<unistd.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<cstdint>

#ifndef O_BINARY
#define O_BINARY 0
#endif
#define HANDSHAKE_PACKET 'H'
#define FILE_DATA_PACKET 'D'

using namespace std;

int server_socket_descriptor;
char error_message[4096];

typedef struct _handshake_request_packet
{
char packet_type;
char overwrite;
char target_file_name[256];
char buffer[7926];
uint64_t source_file_size;
}handshake_request_packet;

typedef struct _request_packet
{
char packet_type;
char buffer[8187];
uint32_t chunk_number;
}request_packet;

typedef struct _response_packet
{
char buffer[8192];
}response_packet;

typedef struct _handshake_response_packet
{
char can_copy;
char buffer[8191];
}handshake_response_packet;

enum fft_enums
{
SUCCESS,
SOCKET_ERROR,
SERVER_IP_ERROR,
CONNECT_ERROR,
NOT_CONNECTED_ERROR,
IS_FILE,
IS_DIRECTORY,
INVALID_SOURCE_PATH,
SOURCE_OPEN_ERROR,
CANNOT_REMOTE_COPY_ERROR
};

int fft_connect(const char *ip,int port)
{
	int fd=socket(AF_INET,SOCK_STREAM,0);
	if(fd<0) return SOCKET_ERROR;
	// initialize all the bytes of server_address structure to zero
	struct sockaddr_in server_address;
	bzero(&server_address,sizeof(server_address));
	server_address.sin_family=AF_INET;
	server_address.sin_port=htons(port); int ret=inet_pton(AF_INET,ip,&server_address.sin_addr);
	if(ret==0)
	{
		close(fd);
		return SERVER_IP_ERROR;
	}
	if(connect(fd,(struct sockaddr *)&server_address,sizeof(server_address))<0)
	{
		close(fd);
		return CONNECT_ERROR;
	}
	server_socket_descriptor=fd;
	return SUCCESS;
}

void write_error(int error)
{
	switch(error)
	{
		case SOCKET_ERROR: cout<<"Socket error"<<endl; break; 
		case SERVER_IP_ERROR: cout<<"server ip error"<<endl; break; 
		case CONNECT_ERROR: cout<<"Unable to connect to server"<<endl; break; 
		case INVALID_SOURCE_PATH: cout<<"source path does not exist"<<endl; break; 
		case NOT_CONNECTED_ERROR: cout<<"Not connected to server"<<endl; break;
	}
}

void fft_close_connection()
{
	if(server_socket_descriptor!=-1) close(server_socket_descriptor);
	server_socket_descriptor=-1;
}

int is_connected()
{
	return server_socket_descriptor!=-1;
}

int get_file_type(char *path)
{
	struct stat s;
	if(stat(path,&s)<0) return 0;
	if(S_ISREG(s.st_mode)) return IS_FILE;
	if(S_ISDIR(s.st_mode)) return IS_DIRECTORY;
	return INVALID_SOURCE_PATH;
}

int copy_file_to_remote(char *source,char *target,char overwrite)
{
size_t bytes_fetched;
struct stat s;
stat(source,&s);
handshake_request_packet handshake_request_pkt;
handshake_request_pkt.source_file_size=s.st_size;
int fd;
fd=open(source,O_RDONLY | O_BINARY);
if(fd<0) return SOURCE_OPEN_ERROR; 
handshake_request_pkt.packet_type=HANDSHAKE_PACKET;
handshake_request_pkt.overwrite=overwrite;
strcpy(handshake_request_pkt.buffer,target);
strcpy(handshake_request_pkt.target_file_name,basename(source));
cout<<"File size: "<<s.st_size<<endl;
send(server_socket_descriptor,&handshake_request_pkt,sizeof(handshake_request_pkt),0);
// what to do if send fails
handshake_response_packet handshake_response_pkt; 
size_t bytes_remaining=sizeof(handshake_response_pkt);
char *ptr;
ptr=(char *)&handshake_response_pkt;
while(bytes_remaining>0)
{
bytes_fetched=read(server_socket_descriptor,ptr,bytes_remaining);
bytes_remaining-=bytes_fetched;
ptr+=bytes_fetched;
}
if(!(handshake_response_pkt.can_copy))
{
close(fd); 
strcpy(error_message,handshake_response_pkt.buffer); 
printf("%s\n",error_message); // to be removed later on
return CANNOT_REMOTE_COPY_ERROR;
}
uint64_t bytes_fetched_from_file=0; 
uint64_t bytes_yet_to_be_fetched=handshake_request_pkt.source_file_size;
request_packet pkt;
pkt.chunk_number=1;
pkt.packet_type=FILE_DATA_PACKET;
uint32_t bytes_to_read;
uint32_t offset;
while(bytes_yet_to_be_fetched>0)
{
offset=0;
bytes_to_read=8187;
if(bytes_to_read>bytes_yet_to_be_fetched) bytes_to_read=bytes_yet_to_be_fetched; 
while(bytes_to_read>0)
{
bytes_fetched_from_file=read(fd,pkt.buffer+offset,bytes_to_read);
offset+=bytes_fetched_from_file;
bytes_to_read-=bytes_fetched_from_file;
}
bytes_yet_to_be_fetched-=offset;
send(server_socket_descriptor,&pkt,sizeof(pkt),0);
printf("Chunk %d has been sent\n", pkt.chunk_number);
pkt.chunk_number++;
}
close(fd);
response_packet res_pkt;
int n=recv(server_socket_descriptor,&res_pkt,sizeof(res_pkt),0);
if(n==0) cout<<"Did not get anything from server"<<endl;
else cout<<res_pkt.buffer[0]<<" Received from Server"<<endl;
return SUCCESS;
}

int copy_to_remote(char *source,char *target,char overwrite)
{
int error; 
if(!is_connected) return NOT_CONNECTED_ERROR;
int file_type;
file_type=get_file_type(source);
if(file_type==INVALID_SOURCE_PATH) return INVALID_SOURCE_PATH; 
if(file_type==IS_FILE) return copy_file_to_remote(source,target,overwrite); 
//else if(file_type==IS_DIRECTORY) return copy_directory_to_remote(source,target);
return SUCCESS; // this is unreachable
}

int main(int argc,char *argv[])
{
if(argc!=6)
{
cout<<"Usage : [fft-client server port source target]"<<endl;
return EXIT_FAILURE;
}
// validate arguments
char *server=argv[1];
int port=atoi(argv[2]);
char *source=argv[3];
char *target=argv[4];
char *overwrite=argv[5];
int error;
server_socket_descriptor=-1;
error=fft_connect(server,port);
if(error!=SUCCESS)
{
write_error(error);
return EXIT_FAILURE;
}
error=copy_to_remote(source,target,*overwrite);
if(error!=SUCCESS) write_error(error);
else cout<<"File transferred"<<endl;
fft_close_connection(); 
static_assert(sizeof(handshake_request_packet)==8192,"struct _handshake_request_packet is not of 8192"); 
static_assert(sizeof(request_packet)==8192,"struct _request_packet is not of 8192");
return EXIT_SUCCESS;
}

