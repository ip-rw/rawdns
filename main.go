package main

import (
	"fmt"
	"github.com/ip-rw/rawdns/pkg/dns"
	"github.com/ip-rw/rawdns/pkg/misc"
	"github.com/sirupsen/logrus"
	"go.uber.org/ratelimit"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	rdns := dns.NewRawDNS()

	// this needs to be nigh on a second's worth to be sure, otherwise things can break
	var nsChan = make(chan string, 1)
	var responseChan = make(chan *dns.Msg, 50)

	// could make this better (response chan is broken or something iirc - take 5 mins) instead of a waitgroup/timeout
	go rdns.Run(nsChan, responseChan)
	wg := &sync.WaitGroup{}
	var pps uint64
	var rpps uint64
	go func() {
		var lastPps uint64
		var lastRpps uint64

		for {
			logrus.Infof("%d pps. %drpps. %d/%d", pps-lastPps, rpps-lastRpps, pps, rpps)
			lastPps = pps
			lastRpps = rpps
			time.Sleep(1 * time.Second)
		}
	}()

	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
		}()
		for {
			select {
			case resp := <-responseChan:
				atomic.AddUint64(&rpps, 1)

				// hostname is hardcoded somewhere in there. good luck.
				if len(resp.DnsAnswer) > 0 {
					fmt.Println(resp.SourceIP, resp.DnsAnswer)
				}
			case <-time.After(5 * time.Second):
				return
			}
		}
	}()

	rl := ratelimit.New(8000, ratelimit.WithSlack(500))
	for line := range misc.Stdin() {
		if !strings.Contains(line, ":") {
			line = strings.TrimSpace(line) + ":53"
		}
		rl.Take()
		atomic.AddUint64(&pps, 1)
		// instead pass DNS msg but better - can pass questions + servers and just let the user deal with it.
		// for now we test dnsservers against a hostname that belongs out here but isnt...
		nsChan <- line
	}
	wg.Wait()
}
