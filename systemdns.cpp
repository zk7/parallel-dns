// DNS.cpp 

#pragma comment(lib, "Iphlpapi.lib")
#include <Windows.h>
#include <Iphlpapi.h>
#include <stdio.h>

// NOTE: link with Iphlpapi.lib; prints primary/second DNS server info

char* getDNSServer(void)
{
	// MSDN sample code
	FIXED_INFO *FixedInfo;
	ULONG    ulOutBufLen;
	DWORD    dwRetVal;

	ulOutBufLen = sizeof(FIXED_INFO);
	FixedInfo = (FIXED_INFO *) GlobalAlloc( GPTR, sizeof( FIXED_INFO ) );
	ulOutBufLen = sizeof( FIXED_INFO );

	if(ERROR_BUFFER_OVERFLOW == GetNetworkParams(FixedInfo, &ulOutBufLen)) {
		GlobalFree( FixedInfo );
		FixedInfo = (FIXED_INFO *)GlobalAlloc( GPTR, ulOutBufLen );
	}

	if ( dwRetVal = GetNetworkParams( FixedInfo, &ulOutBufLen ) ) {
		printf( "Call to GetNetworkParams failed. Return Value: %08x\n", dwRetVal );
		return "";
	}
	else {
		return FixedInfo->DnsServerList.IpAddress.String;
	}

	GlobalFree (FixedInfo);
}
