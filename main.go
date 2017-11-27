package main

//#cgo LDFLAGS: -liphlpapi
//#include "gettable.c"
import "C"
import (
	"reflect"
	"net"
	"os"
	"fmt"
	"strconv"
	"time"
	"unsafe"
	"golang.org/x/sys/windows/registry"
)

/*
DWORD dwState;
DWORD dwLocalAddr;
DWORD dwLocalPort;
DWORD dwRemoteAddr;
DWORD dwRemotePort;
DWORD dwOwningPid;
*/

func main() {

	type TcpInfo struct {
		State      int
		LocalIP    net.IP
		LocalPort  int
		RemoteIP   net.IP
		RemotePort int
		ProcessID  int
	}

	var pmib C.PMIB_TCPTABLE_OWNER_PID


	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(2)
	}

	dumpFile, err := os.Create(strconv.FormatInt(time.Now().Unix(),10)+".txt")
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(2)
	}
	defer dumpFile.Close()

	if err := C.getTable(&pmib); err != 0 {
		print("Error WinAPIHelperr call")
		os.Exit(2)
	}

	length := getIntfromDWORD(pmib.dwNumEntries)

	tcptable := (*[1 << 10]C.MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&pmib.table))[:length:length]

	tbl := make([]TcpInfo, length, length)

	dumpFile.WriteString(hostname+"\n")

	for i := 0; i < length; i++ {

		tbl[i].State = getIntfromDWORD(tcptable[i].dwState)
		tbl[i].LocalIP = getIPfromDWORD(tcptable[i].dwLocalAddr)
		tbl[i].LocalPort = getPortfromDWORD(tcptable[i].dwLocalPort)
		tbl[i].RemoteIP = getIPfromDWORD(tcptable[i].dwRemoteAddr)
		tbl[i].RemotePort = getPortfromDWORD(tcptable[i].dwRemotePort)
		tbl[i].ProcessID = getIntfromDWORD(tcptable[i].dwOwningPid)

		dumpFile.WriteString(fmt.Sprintf("%v\n", tbl[i]))

	}
}

func getIPfromDWORD(in C.DWORD) (out net.IP) {
	hdr := reflect.SliceHeader{Data: uintptr(unsafe.Pointer(&in)), Len: registry.DWORD, Cap: registry.DWORD}
	out = *(*[]byte)(unsafe.Pointer(&hdr))
	return
}

func getPortfromDWORD(in C.DWORD) (out int) {
	bytes := getIPfromDWORD(in)
	return int(bytes[0])<<8 | int(bytes[1])
}

func getIntfromDWORD(in C.DWORD) (out int) {
	bytes := getIPfromDWORD(in)
	return int(bytes[3])<<8 | int(bytes[2]) | int(bytes[1])<<8 | int(bytes[0])
}
