package dns

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/ip-rw/rawdns/pkg/misc"
	"github.com/mostlygeek/arp"
	"github.com/sirupsen/logrus"
	"net"
	"time"

	"strconv"
)

type Msg struct {
	Timestamp       string
	SourceIP        string
	DestinationIP   string
	DnsQuery        string
	DnsAnswer       []string
	DnsAnswerTTL    []string
	NumberOfAnswers string
	DnsResponseCode string
	DnsOpCode       string
}

type RawDNS struct {
	Interface        *net.Interface
	SrcPort          layers.UDPPort
	Gateway, SrcAddr net.IP
	GatewayMac       net.HardwareAddr

	Handle *pcap.Handle
	//RecvHandle *pcap.Handle // tested when things were broken - wasn't the cure.
}

func NewRawDNS() *RawDNS {
	router, err := routing.New()
	if err != nil {
		logrus.Fatal(err)
	}
	iface, gw, src, err := router.Route(net.IP{1, 1, 1, 1})
	if err != nil {
		logrus.Fatal(err)
	}
	// where am i.
	gwMac, err := net.ParseMAC(arp.Search(gw.To4().String()))
	port := misc.FreeUDPPort()
	handle, err := pcap.OpenLive(iface.Name, 1024, false, pcap.BlockForever)
	if err != nil {
		logrus.Fatal(err)
	}
	return &RawDNS{
		Interface:  iface,
		SrcPort:    layers.UDPPort(port),
		Gateway:    gw,
		GatewayMac: gwMac,
		SrcAddr:    src,
		Handle:     handle,
	}
}

func (d *RawDNS) Run(nsChan chan string, responseChan chan *Msg) {
	go d.ListenForDMS(responseChan)

	logrus.Infof("Using source port %d", d.SrcPort)
	var dest net.IP
	for ns := range nsChan {
		host, port, err := net.SplitHostPort(ns)
		if err != nil {
			logrus.Warn("SplitHostPort", host, port, ns, err)
			continue
		}
		dest = net.ParseIP(host)
		portInt, err := strconv.Atoi(port)
		if err != nil {
			logrus.Warn("ParseIPAtoi", host, port, ns, err)
			continue
		}

		// Should really be passed by the user... just let people send a DNS packet.
		pac, err := d.MakeDNSPacket(dest, layers.UDPPort(portInt), "test-34.56.78.90.nip.io")
		if err != nil {
			logrus.Warn("MakeDNSPacket", host, port, ns, err)
			continue
		}
		err = d.Handle.WritePacketData(pac)
		if err != nil {
			logrus.Warn("WritePacketData", host, port, ns, err)
		}
	}
}

func (d *RawDNS) ListenForDMS(responseChan chan *Msg) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	// lies i don't support v6. blame privatelayer.
	var ip6 layers.IPv6
	var udp layers.UDP
	var dns layers.DNS
	var payload gopacket.Payload
	var SrcIP, DstIP string
	var err error
	var data []byte
	var filter = fmt.Sprintf("udp and dst port %d", d.SrcPort)
	err = d.Handle.SetBPFFilter(filter)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.Infof("Set filter: %s", filter)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &udp, &dns, &payload)
	decoded := make([]gopacket.LayerType, 0, 6)

	// should actually close this
	for {
		data, _, err = d.Handle.ZeroCopyReadPacketData()
		if err != nil {
			logrus.Warn("error getting packet: %v", err)
			continue
		}
		err = parser.DecodeLayers(data, &decoded)
		if err != nil {
			continue
		}
		for _, typ := range decoded {
			switch typ {
			case layers.LayerTypeIPv4:
				SrcIP = ip4.SrcIP.String()
				DstIP = ip4.DstIP.String()
			case layers.LayerTypeIPv6:
				SrcIP = ip6.SrcIP.String()
				DstIP = ip6.DstIP.String()
			case layers.LayerTypeDNS:
				dnsOpCode := int(dns.OpCode)
				dnsResponseCode := int(dns.ResponseCode)
				dnsANCount := int(dns.ANCount)
				for _, dnsQuestion := range dns.Questions {

					t := time.Now()
					timestamp := t.Format(time.RFC3339)

					msg := &Msg{
						Timestamp:       timestamp,
						SourceIP:        SrcIP,
						DestinationIP:   DstIP,
						DnsQuery:        string(dnsQuestion.Name),
						DnsOpCode:       strconv.Itoa(dnsOpCode),
						DnsResponseCode: strconv.Itoa(dnsResponseCode),
						NumberOfAnswers: strconv.Itoa(dnsANCount)}

					if dnsANCount > 0 {
						for _, dnsAnswer := range dns.Answers {
							msg.DnsAnswerTTL = append(msg.DnsAnswerTTL, fmt.Sprint(dnsAnswer.TTL))
							if dnsAnswer.IP != nil {
								msg.DnsAnswer = append(msg.DnsAnswer, dnsAnswer.IP.String())
							}
						}
					}
					responseChan <- msg
				}
			}
		}
	}
}

var (
	buff = gopacket.NewSerializeBuffer()
	eth  = layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 = layers.IPv4{
		Version:  4,
		TOS:      0,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}
	udp = layers.UDP{
		//SrcPort: d.SrcPort,
		//DstPort: dport,
	}
	dns = layers.DNS{}
)

// if this is called from lots of places, then it will explode.
func (d *RawDNS) MakeDNSPacket(ip net.IP, dport layers.UDPPort, hostname string) ([]byte, error) {
	err := buff.Clear()
	if err != nil {
		return nil, err // wut
	}

	eth.DstMAC = d.GatewayMac
	eth.SrcMAC = d.Interface.HardwareAddr
	udp.DstPort = dport
	udp.SrcPort = d.SrcPort
	ip4.DstIP = ip
	ip4.SrcIP = d.SrcAddr
	dns = layers.DNS{
		Questions: []layers.DNSQuestion{
			{
				Name:  []byte(hostname),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			},
		},
	}

	err = udp.SetNetworkLayerForChecksum(&ip4)
	if err != nil {
		return nil, err
	}
	err = gopacket.SerializeLayers(buff, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, &eth, &ip4, &udp, &dns)
	if err != nil {
		return nil, err
	}
	return buff.Bytes(), nil
}
