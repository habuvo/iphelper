//#define WINVER 0x0500 // Windows 2000
//#define WINVER 0x0501 // Windows XP
//#define WINVER 0x0502 // Windows Server 2003
//#define WINVER 0x0600 // Windows Vista, Windows Server 2008
//#define WINVER 0x0601 // Windows 7
//#define WINVER 0x0602 // Windows 8
//#define WINVER 0x0603 // Windows 8.1
#define WINVER 0x0A00 // Windows 10
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

int getTable(PMIB_TCPTABLE_OWNER_PID *ref)
{
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    int i;

        *ref = (MIB_TCPTABLE_OWNER_PID *) MALLOC(sizeof (MIB_TCPTABLE_OWNER_PID));
        if (*ref == NULL) {
            printf("Error allocating memory\n");
            return 1;
        }

        dwSize = sizeof (MIB_TCPTABLE_OWNER_PID);
        // Make an initial call to GetExtendedTcpTable to
        // get the necessary size into the dwSize variable
        if ((dwRetVal = GetExtendedTcpTable(*ref, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) ==
            ERROR_INSUFFICIENT_BUFFER) {
            FREE(*ref);
            *ref = (MIB_TCPTABLE_OWNER_PID *) MALLOC(dwSize);
            if (*ref == NULL) {
                printf("Error allocating memory\n");
                return 1;
            }
        }
            // Make a second call to GetExtendedTcpTable to get
            // the actual data we require
           if ((dwRetVal = GetExtendedTcpTable(*ref, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR) {
                   return 0;
           } else {
                   printf("\tGetTcpTable failed with %d\n", dwRetVal);
                   FREE(*ref);
                   return 1;
           }

            if (*ref != NULL) {
                   FREE(*ref);
                   *ref = NULL;
            }

            return 0;
}
