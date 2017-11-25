package main

//#cgo LDFLAGS: -liphlpapi
//#include "gettable.c"
import "C"
import (
	"fmt"
	"unsafe"
)

func main() {

	var info C.PMIB_TCPTABLE_OWNER_PID

	err := C.getTable(&info)

	length := info.dwNumEntries
	slice := (*[1 << 30]C.MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&info.table))[:length:length]

	fmt.Println("Error : ",err)
	fmt.Println("Length : ",length)
	fmt.Println(slice)


}
