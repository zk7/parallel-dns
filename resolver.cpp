//DNS Resolver
//Author: Zain Shamsi

#pragma comment(lib, "ws2_32.lib")
#include "dnsclasses.h"

bool batch_run;

int main(int argc, char* argv[]){
	char* filename = "dns-in.txt";
	int num_threads;
	int tries;
	double time;
	char* temp;
	WSADATA wsaData = {0};
    int iResult = 0;

	if (argc < 2){
		printf("Usage: %s [IP or Hostname] for interactive mode\n", argv[0]);
		printf("Usage: %s [# threads] [file] for batch mode\n", argv[0]);
		return 1;
	}	
	
	// Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        wprintf(L"WSAStartup failed: %d\n", iResult);
        return 1;
    }

	if (strspn(argv[1], "1234567890") == strlen(argv[1])){
		//batch mode
		num_threads = atoi(argv[1]);
		if (argc == 3) filename = argv[2];
		printf("Running batch mode DNS Lookups\nUsing %d threads and reading from file %s...\n", num_threads, filename);
		batch_run = true;
		batchDNS(num_threads, filename);
	}
	else { 
		//interactive mode
		batch_run = false;
		if (strspn(argv[1], "1234567890.") == strlen(argv[1])){ //if contains only numbers and dot, then ip
			DWORD IP = inet_addr(argv[1]);
			if (IP == INADDR_NONE){
				printf("Invalid IP!\n");
				WSACleanup();
				return 1;
			}			
			string host = ReverseIPString(argv[1]);
			printf("Running Reverse Lookup on IP %s...\n", host.c_str()); 
			DNSRequest((char *)host.c_str(), true, &tries, &time, &temp);
		}
		else { //assume hostname
			printf("Running IP Lookup on Hostname %s...\n", argv[1]);
			DNSRequest(argv[1], false, &tries, &time, &temp);
		}
	}


	WSACleanup();
	return 0;
}

//Reverse IP and add ".in-addr.arpa"
string ReverseIPString(char* IP){
	char* token;
	char* context;
	char* delimiters = ".";
	string ret;
	
	token = strtok_s(IP, delimiters, &context);

	while (token != NULL){
		ret = "." + string(token) + ret;
		token = strtok_s(NULL, delimiters, &context);
	}	
	ret.erase(0, 1);
	ret.append(".in-addr.arpa");
	return ret;
}

//Starting point for making the request
int DNSRequest(char* host, bool rev_lookup, int* attempts, double* time, char** answer){
	int pkt_size = strlen(host) + 2 + sizeof(fixedDNSheader) + sizeof(queryHeader); 
	char* buf = new char[pkt_size];
	int tries = 0;
	clock_t start, end;
	
	start = clock();

	fixedDNSheader *dns_header = (fixedDNSheader *) buf;
	queryHeader *query_header = (queryHeader*) (buf + pkt_size - sizeof(queryHeader));
 
	// fixed field initialization 
	dns_header->ID = htons(1);
	dns_header->flags = htons(DNS_QUERY | DNS_RD);
	dns_header->questions = htons(1);
	dns_header->answers = htons(0);
	dns_header->authority = htons(0);
	dns_header->additional = htons(0);
	
	//set query fields
	query_header->qclass = htons(DNS_INET);
	if (rev_lookup) query_header->qtype = htons(DNS_PTR);
	else query_header->qtype = htons(DNS_A);
 
	//make into 3www6google3com0 format
	MakeDNSQuestion((char*)(dns_header + 1), host); 
	//send request
	int ret = SendRequest(buf, pkt_size, rev_lookup, &tries, answer);
	end = clock();
	
	*time = (double)(end - start);
	*attempts = tries;
	if (!batch_run) printf( "Queried in %.0f ms\n", *time );

	delete buf; 
	return ret;
}

//makes string into 3www6google3com0
void MakeDNSQuestion (char* buf, char* host) { 
	char* token;
	char* context;
	char* delimiters = ".";
	int i = 0;
	int size;
	token = strtok_s(host, delimiters, &context);

	while(token != NULL){ 
		size = strlen(token);
		buf[i++] = size;  //write the size number into ith spot
		memcpy (buf+i, token, size); //write the token into the next <size> spots
		i += size; //keep running counter of where we are in buf

		token = strtok_s(NULL, delimiters, &context);
	} 
	buf[i] = 0; // last word NULL-terminated
}

//unmake string into normal string www.google.com
char* UnMakeDNSQuestion (char* buf) { 
	int i = 0;
	int size;
	char* host = new char[strlen(buf)];
	char* writeptr = host;

	size = buf[0]; //read initial size
	while(size != 0){ 		
		buf = buf + 1; //advance buf to URL part
		memcpy (writeptr, buf, size); //write the token into the next <size> spots
		writeptr = writeptr + size; //advance host pointer to after URL portion
		memcpy (writeptr, ".", 1);	
		buf = buf + size; //advance buf to next size		
		writeptr = writeptr + 1; //advance host pointer
		i += (size + 1); //keep running counter of where we are in buf	
		size = buf[0]; //read next size
	} 
	host[i-1] = '\0'; // remove last dot and NULL-terminate

	return host;
}

//Reverse IP using char*
char* ReverseIP(char* IP){
	char* token;
	char* context;
	char* delimiters = ".";
	int ip_length = strlen(IP);
	int token_size = 0, i = 0;
	char* rev_IP = new char(ip_length + 15);
	
	
	token = strtok_s(IP, delimiters, &context);

	while (token != NULL){
		token_size += strlen(token);
		//write the token to the back of the array
		memcpy(rev_IP + (ip_length - token_size - i), token, strlen(token));
		//write the dot
		if ((token_size + i + 1) <= ip_length) 
			memcpy(rev_IP + (ip_length - token_size - i - 1), ".", 1);	
		//keep track of dots written, so we dont overwrite dots from the back
		i++; 
		token = strtok_s(NULL, delimiters, &context);
	}	
	memcpy(rev_IP + ip_length, ".in-addr.arpa", 13); 
	rev_IP[ip_length + 13] = '\0';
	return rev_IP;
}

//main workhorse function
int SendRequest(char* request, int packet_size, bool rev_lookup, int* attempts, char** return_answer){
	int result;
	int count = 0;

	// Create a SOCKET for connecting to server
	SOCKET ConnectSocket;
	ConnectSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ConnectSocket == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		return 0;
	}

	sockaddr_in service;
	service.sin_family = AF_INET;
	service.sin_addr.s_addr = INADDR_ANY;
	service.sin_port = htons(0);
	
	// Bind the socket.
	if (bind( ConnectSocket, (SOCKADDR*) &service, sizeof(service)) == SOCKET_ERROR) {
		printf("bind() failed.\n");
		closesocket(ConnectSocket);
		return 0;
	}

	// Set up the RecvAddr structure with the IP address of
	// the receiver and the specified port number.
	sockaddr_in RecvAddr;
	RecvAddr.sin_family = AF_INET;
	RecvAddr.sin_port = htons(53);
	RecvAddr.sin_addr.s_addr = inet_addr(getDNSServer());

	while (count++ < 2) { 
		// send request to the server 
		result = sendto (ConnectSocket, request, packet_size, 0, (SOCKADDR *)&RecvAddr, sizeof(RecvAddr));
		if (result == SOCKET_ERROR){
			printf("%d error\n",WSAGetLastError());
			break;
		}
		//else printf("Sent Request of %d bytes\n", result);

		// get ready to receive 
		fd_set fd; 	
		struct timeval tv;
		FD_ZERO (&fd);    // clear the set 
		FD_SET(ConnectSocket, &fd); // add your socket to the set 	
		tv.tv_sec = 30;
		tv.tv_usec = 30 * 1000;
		int available = select (0, &fd, NULL, NULL, &tv); 
		if (available > 0) { 
			// parse the response 
			char answer[512];   // max DNS packet size 
			result = recvfrom (ConnectSocket, answer, 512, 0, NULL, NULL); 
			if (result == SOCKET_ERROR){
				printf("%d error\n",WSAGetLastError());
				closesocket(ConnectSocket);
				return 0;
			}

			fixedDNSheader *fdh = (fixedDNSheader*)answer; 
			// read fdh->ID and other fields 
			int ans_count = ntohs(fdh->answers); 
			int auth_count = ntohs(fdh->authority); 			
			int additional_count = ntohs(fdh->additional); 
			if (ans_count == 0){
				if (auth_count == 0){
					if (!batch_run) printf("No authoritative DNS Server\n");
					return 3;
				}
				if (!batch_run) printf("No DNS Entry\n");
				closesocket(ConnectSocket);
				return 2;
			}
			// skip over variable fields to the answer(s) section 

			int name_length, rdata_length;
			fixedRR *frr;
			char* readptr = answer + packet_size; //advance readptr to the answer section

			//loop through each resource record
			int total_records = ans_count+auth_count+additional_count;
			for (int i = 0; i < total_records; i++){				
				name_length = 0;
				char* name = GetName(readptr, answer, &name_length);
				if (name == NULL){
					if (!batch_run) printf("Jumped too many times in packet\n");
					closesocket(ConnectSocket);
					return 0;
				}
				readptr = readptr + name_length; //advance readptr past the name

				frr = (fixedRR*)readptr; 
				rdata_length = ntohs(frr->data_length);
				readptr = readptr + sizeof(*frr); //advance readptr past the resource record		
				
				char* ans_string = new char[rdata_length+1];
				memcpy(ans_string, readptr, rdata_length);
				ans_string[rdata_length] = '\0';
				readptr = readptr + rdata_length; //advance readptr past the rdata

				if (readptr > answer + result){ //sanity check
					if (!batch_run) printf("Read pointer past packet memory size!\n");
					closesocket(ConnectSocket);
					return 0;
				}

				if (i < ans_count || i >= (total_records - additional_count)){
					//if either answer or additional record, then we bother printing
					if (ntohs(frr->atype) == DNS_CNAME){
						//if CNAME
						if (!batch_run) printf("%s is aliased to %s\n", name, GetName(ans_string, answer, &name_length));
					}
					if (ntohs(frr->atype) == DNS_A || ntohs(frr->atype) == DNS_PTR){
						//If Type A or PTR
						if (ntohs(frr->atype) == DNS_A){
							long *ip;
							ip = (long*)ans_string;
							service.sin_addr.s_addr = *ip;
							if (!batch_run) printf("%s is %s\n", name, inet_ntoa(service.sin_addr));					
						}
						if (ntohs(frr->atype) == DNS_PTR){
							*return_answer = GetName(ans_string, answer, &name_length);
							if (!batch_run) printf("%s is %s\n", name, GetName(ans_string, answer, &name_length));
						}
					}	
				}
				delete ans_string;
			}
			// break from the loop 
			break;
		}
	} 
	closesocket(ConnectSocket);
	if (count >= 3){
		if (!batch_run) printf("Timed out %d times.\n", count);
		return 4;
	}
	*attempts = count;
	return 1;
}

//create string that may contain offsets, and determine length of name field
char* GetName(char* buffer, char* full_response, int* length){
	int i = 0;
	u_char* readptr = (u_char*)buffer;
	int jumpcount = 0;
	char name[100];

	while (*readptr != 0){
		if (*readptr >= 192){
			if (jumpcount > 5) return NULL; //jumped too many times
			if (jumpcount == 0) *length += 2; //only increment length when we havent jumped
			int offset = (*readptr)* (1 << 8) + *(readptr+1) - (192 << 8);
			readptr = (u_char*)(full_response + offset);
			jumpcount++;
		}
		else{
			if (jumpcount == 0) *length += 1; //only increment length when we havent jumped
			name[i] = *readptr;
			i++;
			readptr += 1;
		}
	}
	name[i] = '\0';
	return UnMakeDNSQuestion(name);
}
