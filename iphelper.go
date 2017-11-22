package main

/*
1 dword - number of entries
MIB_TCPROW_OWNER_PID
1 The state of the TCP connection.
2 The local IPv4 address for the TCP connection on the local computer. A value of zero indicates the listener can accept a connection on any interface.
3 The local port number in network byte order for the TCP connection on the local computer
4 The IPv4 address for the TCP connection on the remote computer. When the State member is MIB_TCP_STATE_LISTEN, this value has no meaning.
5 The remote port number in network byte order for the TCP connection on the remote computer. When the State member is MIB_TCP_STATE_LISTEN, this member has no meaning.
6 The PID of the process that issued a context bind for this TCP connection.
 */

import (
	"fmt"
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows/registry"
	"net"
	"github.com/StackExchange/wmi"
	"bufio"
	"os"
)

type endpoint struct {
	State      string
	LocalIP    net.IP
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	Process    string
}

type tcptable struct {
	Counter int
	Netinfo []endpoint
}

type Win32_Process struct {
	Name      string
	ProcessID uint32
}

//state
const (
	TCP_TABLE_BASIC_LISTENER           = iota
	TCP_TABLE_BASIC_CONNECTIONS
	TCP_TABLE_BASIC_ALL
	TCP_TABLE_OWNER_PID_LISTENER
	TCP_TABLE_OWNER_PID_CONNECTIONS
	TCP_TABLE_OWNER_PID_ALL
	TCP_TABLE_OWNER_MODULE_LISTENER
	TCP_TABLE_OWNER_MODULE_CONNECTIONS
	TCP_TABLE_OWNER_MODULE_ALL
)

/*states := make(map[int]string)
states[1] = "closed"  //The TCP connection is in the CLOSED state that represents no connection state at all.
states[2] = "listen"  //The TCP connection is in the LISTEN state waiting for a connection request from any remote TCP and port.
states[3] = "syn-sent" //The TCP connection is in the SYN-SENT state waiting for a matching connection request after having sent a connection request (SYN packet).
states[4] = "syn-recieved"  //The TCP connection is in the SYN-RECEIVED state waiting for a confirming connection request acknowledgment after having both received and sent a connection request (SYN packet).
states[5] = "established"  //The TCP connection is in the ESTABLISHED state that represents an open connection, data received can be delivered to the user. This is the normal state for the data transfer phase of the TCP connection.
states[6] = "wait for termination remote or acknoledgment"  //The TCP connection is FIN-WAIT-1 state waiting for a connection termination request from the remote TCP, or an acknowledgment of the connection termination request previously sent.
states[7] = "wait for termination remote"  //The TCP connection is FIN-WAIT-2 state waiting for a connection termination request from the remote TCP.
states[8] = "wait for termination local" //The TCP connection is in the CLOSE-WAIT state waiting for a connection termination request from the local user.
states[9] = "closing" //The TCP connection is in the CLOSING state waiting for a connection termination request acknowledgment from the remote TCP.
states[10] = "wait acknoledgment of termination" //The TCP connection is in the LAST-ACK state waiting for an acknowledgment of the connection termination request previously sent to the remote TCP (which includes an acknowledgment of its connection termination request).
states[11] = "time wait"//The TCP connection is in the TIME-WAIT state waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connection termination request.
states[12] = "delete TCB" //The TCP connection is in the delete TCB state that represents the deletion of the Transmission Control Block (TCB), a data structure used to maintain information on each TCP entry.
*/

func main() {
	var table [2000]byte
	var length int = 2000
	var errcode error

	iphelp := syscall.NewLazyDLL("iphlpapi.dll")
	tcptable := iphelp.NewProc("GetExtendedTcpTable")

	r0, _, _ := tcptable.Call(
		uintptr(unsafe.Pointer(&table)),
		uintptr(unsafe.Pointer(&length)),
		1,
		syscall.AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if r0 != 0 {
		errcode = syscall.Errno(r0)
		fmt.Errorf(errcode.Error())
	}

	if TCPtable, err := parseTable(table[:length]); err != nil {
		fmt.Errorf("error %s", err.Error())
		return
	} else {
		fmt.Println("Entries: ", TCPtable.Counter)
		for i, en := range TCPtable.Netinfo {
			if en.State == "established" {
				fmt.Println(i, " State  ",
					en.State, " Local  ", en.LocalIP, ":", en.LocalPort,
					" Remote ", en.RemoteIP, ":", en.RemotePort,
					" Process ", en.Process)
			}
		}
	}
	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func parseTable(table []byte) (tcpt tcptable, err error) {

	states := make(map[int]string)
	states[1] = "closed"                                       //The TCP connection is in the CLOSED state that represents no connection state at all.
	states[2] = "listen"                                       //The TCP connection is in the LISTEN state waiting for a connection request from any remote TCP and port.
	states[3] = "syn-sent"                                     //The TCP connection is in the SYN-SENT state waiting for a matching connection request after having sent a connection request (SYN packet).
	states[4] = "syn-recieved"                                 //The TCP connection is in the SYN-RECEIVED state waiting for a confirming connection request acknowledgment after having both received and sent a connection request (SYN packet).
	states[5] = "established"                                  //The TCP connection is in the ESTABLISHED state that represents an open connection, data received can be delivered to the user. This is the normal state for the data transfer phase of the TCP connection.
	states[6] = "wait for termination remote or acknoledgment" //The TCP connection is FIN-WAIT-1 state waiting for a connection termination request from the remote TCP, or an acknowledgment of the connection termination request previously sent.
	states[7] = "wait for termination remote"                  //The TCP connection is FIN-WAIT-2 state waiting for a connection termination request from the remote TCP.
	states[8] = "wait for termination local"                   //The TCP connection is in the CLOSE-WAIT state waiting for a connection termination request from the local user.
	states[9] = "closing"                                      //The TCP connection is in the CLOSING state waiting for a connection termination request acknowledgment from the remote TCP.
	states[10] = "wait acknoledgment of termination"           //The TCP connection is in the LAST-ACK state waiting for an acknowledgment of the connection termination request previously sent to the remote TCP (which includes an acknowledgment of its connection termination request).
	states[11] = "time wait"                                   //The TCP connection is in the TIME-WAIT state waiting for enough time to pass to be sure the remote TCP received the acknowledgment of its connection termination request.
	states[12] = "delete TCB"                                  //The TCP connection is in the delete TCB state that represents the deletion of the Transmission Control Block (TCB), a data structure used to maintain information on each TCP entry.

	proc, err := getWin32Procs()
	procmap := make(map[int]string)
	for _, p := range proc {
		procmap[int(p.ProcessID)] = p.Name
	}

	counter := registry.DWORD

	//get counter
	tcpt.Counter = bytes2intLE(table[:counter])

	//check if it is enough data to fill table
	if tcpt.Counter*registry.DWORD*6 > len(table)-registry.DWORD {
		err = fmt.Errorf("Error table length, expected %d get %d", tcpt.Counter*24, len(table)-4)
		return
	}

	//parse endpoint
	for counter+registry.DWORD*6 <= len(table) {

		row := endpoint{}
		var ok bool
		if row.State, ok = states[bytes2intLE(table[counter:counter+registry.DWORD])]; !ok {
			err = fmt.Errorf("No such state code: %d", bytes2intLE(table[counter:counter+4]))
		}
		row.LocalIP = table[counter+registry.DWORD:counter+2*registry.DWORD]
		row.LocalPort = bytes2port(table[counter+2*registry.DWORD:counter+3*registry.DWORD])
		row.RemoteIP = table[counter+3*registry.DWORD:counter+4*registry.DWORD]
		row.RemotePort = bytes2port(table[counter+4*registry.DWORD:counter+5*registry.DWORD])
		if row.Process, ok = procmap[bytes2intLE(table[counter+5*registry.DWORD:counter+6*registry.DWORD])]; !ok {
			err = fmt.Errorf("No such PID : %d", bytes2intLE(table[counter+5*registry.DWORD:counter+6*registry.DWORD]))
		}

		tcpt.Netinfo = append(tcpt.Netinfo, row)

		counter += 6 * registry.DWORD

	}

	return
}

func bytes2intBE(b []byte) (ret int) {
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}

func bytes2intLE(b []byte) (ret int) {
	return int(b[3])<<24 | int(b[2])<<16 | int(b[1])<<8 | int(b[0])
}

func bytes2port(b []byte) (ret int) {
	return int(b[0])<<8 | int(b[1])
}

func getWin32Procs() ([]Win32_Process, error) {
	var dst []Win32_Process
	q := wmi.CreateQuery(&dst, "")

	if err := wmi.Query(q, &dst); err != nil {
		return []Win32_Process{}, fmt.Errorf("could not get win32Proc: %s", err)
	}

	if len(dst) == 0 {
		return []Win32_Process{}, fmt.Errorf("could not get win32Proc: empty")
	}

	return dst, nil
}
