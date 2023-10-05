package misc

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

func Stdin() chan string {
	outchan := make(chan string, 1)
	scan := bufio.NewScanner(os.Stdin)
	go func() {
		for scan.Scan() {
			if scan.Err() != nil {
				fmt.Println("Error reading stdin:", scan.Err())
				return
			}
			outchan <- scan.Text()
		}
		close(outchan)
	}()
	return outchan
}

func FreeUDPPort() int {
	addr, err := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	if err != nil {
		return -1
	}
	l, err := net.ListenUDP("udp", addr)
	if err != nil {
		return -1
	}
	port := l.LocalAddr().(*net.UDPAddr).Port
	l.Close()
	return port
}
