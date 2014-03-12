//DNS Lookup from file
//Author: Zain Shamsi

//Complements the Gnutella Crawler
//File read in has to be in format
//IP:Port
//IP:Port
//Will parse out IP and resolve against system-set DNS servers
#include <fstream>
#include <vector>
#include "dnsclasses.h"

using namespace std;

// link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

class Shared_Vars{
public:	
	HANDLE mutex;
	vector<string> ip_list;
	vector<string> out_list;
	int success;
	int noDNS;
	int noAuth;
	int timeout;
	int count;
	int error;
	vector<int> connects;
	vector<int> times;
};

void ThreadRun(LPVOID thread_vars);
string ReverseIPbatch(char* IP);

int batchDNS(int num_threads, char* filename)
{

    //-----------------------------------------
    // Declare and initialize variables
    int iResult = 0;
	int col_position;
	Shared_Vars vars;
	int total_ips;
	clock_t finish, start;

	ifstream file;
	file.open(filename, ifstream::in);
	if (file.is_open()){
		while (!file.eof()){
			string read_line, temp;
			getline(file, read_line);
			col_position = read_line.find(":");
			temp = read_line.substr(0, col_position);			
			vars.ip_list.push_back(ReverseIPString((char*)temp.c_str()));
		}
	}

	printf("Starting %d threads\n", num_threads);
	vars.mutex = CreateMutex(NULL, false, NULL);
	total_ips = vars.ip_list.size();
	vars.error = 0; vars.noAuth = 0; vars.noDNS = 0; vars.success = 0; 
	vars.timeout = 0; vars.count = total_ips - 1;
	for (int i = 0; i < 3; i++) vars.connects.push_back(0);
	for (int i = 0; i < 11; i++) vars.times.push_back(0);

	start = clock();

	//Split Threads
	HANDLE *handles = new HANDLE [num_threads];
	for (int i = 0; i < num_threads; i++){
		handles[i] = CreateThread (NULL, 4096, (LPTHREAD_START_ROUTINE)ThreadRun, &vars, 0, NULL);	
		SetThreadPriority(handles[i], THREAD_PRIORITY_LOWEST);
	}
	while (true){
		WaitForSingleObject(vars.mutex, INFINITE);
		if (vars.ip_list.empty()){
			ReleaseMutex(vars.mutex);
			break;
		}
		printf("Remaining: %d\n", vars.ip_list.size());
		ReleaseMutex(vars.mutex);
		Sleep(10000);
	}

	WaitForMultipleObjects(num_threads, handles, TRUE, INFINITE);

    // Close handles
    for(int i = 0; i < num_threads; i++) CloseHandle(handles[i]);
	
	finish = clock();

	//Parse on set
	printf("Done. Stopped %d threads\n", num_threads);
	printf("\nStats:\n");
	printf("Total: %d\nSuccess: %d (%.2f%%)\n", total_ips, vars.success, ((double)vars.success/total_ips) * 100.0);
	printf("No DNS: %d (%.2f%%)\n", vars.noDNS, ((double)vars.noDNS/total_ips) * 100.0);
	printf("No Auth: %d (%.2f%%)\n", vars.noAuth, ((double)vars.noAuth/total_ips) * 100.0);
	printf("Timeouts: %d (%.2f%%)\n", vars.timeout, ((double)vars.timeout/total_ips) * 100.0);
	printf("Errors: %d (%.2f%%)\n", vars.error, ((double)vars.error/total_ips) * 100.0);
	printf("Total Time: %.2f seconds (avg. delay %.2fms)\n", (double)(finish-start) / CLOCKS_PER_SEC, (double)(finish-start)/total_ips);
	

	//Write file
	FILE* ofile;
	vector<string>::iterator sit;
	ofile = fopen("dns-out.txt", "w");
	if (ofile != NULL){
		for ( sit=vars.out_list.begin() ; sit < vars.out_list.end(); sit++ )
			fprintf(ofile, "%s\n", sit->c_str());
	}
	fclose(ofile);

	ofile = fopen("stats.txt", "w");
	if (ofile != NULL){		
		fprintf(ofile, "\nStats:\n");
		fprintf(ofile, "Total: %d\nSuccess: %d (%.2f%%)\n", total_ips, vars.success, ((double)vars.success/total_ips) * 100.0);
		fprintf(ofile, "No DNS: %d (%.2f%%)\n", vars.noDNS, ((double)vars.noDNS/total_ips) * 100.0);
		fprintf(ofile, "No Auth: %d (%.2f%%)\n", vars.noAuth, ((double)vars.noAuth/total_ips) * 100.0);
		fprintf(ofile, "Timeouts: %d (%.2f%%)\n", vars.timeout, ((double)vars.timeout/total_ips) * 100.0);
		fprintf(ofile, "Errors: %d (%.2f%%)\n", vars.error, ((double)vars.error/total_ips) * 100.0);
		fprintf(ofile, "Total Time: %.2f seconds (avg. delay %.2fms)\n", (double)(finish-start) / CLOCKS_PER_SEC, (double)(finish-start)/total_ips);
		vector<int>::iterator it;
		fprintf(ofile, "\nconnects:\n");
		for ( it=vars.connects.begin() ; it < vars.connects.end(); it++ )
			fprintf(ofile, "%d\t", *it);
		fprintf(ofile, "\n");
		fprintf(ofile, "times:\n");
		for ( it=vars.times.begin() ; it < vars.times.end(); it++ )
			fprintf(ofile, "%d\t", *it);
	}	
	fclose(ofile);

	printf("\nQuit.\n");
	return 0;
}

void ThreadRun(LPVOID thread_vars){
	char* current_ip;
	int result;
	int attempts;
	double time;
	char* answer;

	Shared_Vars *vars = ((Shared_Vars*)thread_vars);	
	while (true){
		WaitForSingleObject(vars->mutex, INFINITE);
		if (vars->ip_list.empty() || vars->count < 0){
			ReleaseMutex(vars->mutex);
			return;
		}
		current_ip = (char*)vars->ip_list[vars->count].c_str();	
		if (vars->count >= 0) vars->count -= 1;
		ReleaseMutex(vars->mutex);

		// Do Lookup			
		result = DNSRequest(current_ip, true, &attempts, &time, &answer);
		
		WaitForSingleObject(vars->mutex, INFINITE);		
		if (result == 0) vars->error++;
		if (result == 1){
			vars->out_list.push_back(answer);
			vars->success++;			
			vars->connects[attempts-1]++;			
			int time_taken = (int)time/100;
			if (time_taken > 10) time_taken = 10;			
			vars->times[time_taken]++;
		}
		if (result == 2) vars->noDNS++;
		if (result == 3) vars->noAuth++;
		if (result == 4) vars->timeout++;

		if (vars->ip_list.empty()){
			ReleaseMutex(vars->mutex);
			return;
		}
		vars->ip_list.pop_back();
		ReleaseMutex(vars->mutex);
	}
}
