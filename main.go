package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/praserx/ipconv"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" dns ./ebpf/dns.c -- -I./headers

func main() {
	ifname := flag.String("interface", "eth0", "The interface to watch network traffic on")
	blocklist := flag.String("blocklist", "blocklist.txt", "The blocklist file")

	flag.Parse()

	slog.Info("Starting eBPF Adblocker...", "interface", *ifname)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	devID, err := net.InterfaceByName(*ifname)
	if err != nil {
		slog.Error("lookup network iface failed", "iface", *ifname, "err", err)
	}

	dns := dnsObjects{}
	if err := loadDnsObjects(&dns, nil); err != nil {
		slog.Error("loading objects failed", "err", err)
	}

	defer dns.Close()

	file, err := os.Open(*blocklist)
	if err != nil {
		slog.Error("could not open blocklist file", "err", err)
		os.Exit(1)
	}
	reader := bufio.NewReader(file)
	line, err := readLine(reader)
	for err == nil {
		// ignore if line start with #
		if !strings.HasPrefix(line, "#") {
			parts := strings.Split(line, " ")
			if len(parts) != 2 {
				slog.Error("invalid blocklist rule", "rule", line)
				os.Exit(1)
			}

			ip := parts[0]
			domain := parts[1]

			// Parse the URL Path
			var dnsName [256]uint8
			var convertedName [256]uint8

			copy(dnsName[:], domain)

			ipAddr, _ := ipconv.IPv4ToInt(net.ParseIP(ip))
			arecord := htonl(ipAddr)
			copy(convertedName[:], convertDomain(domain))
			err = dns.DnsMap.Put(convertedName, dnsDnsReplace{dnsName, arecord})
			if err != nil {
				slog.Error("add to map failed", "domain", domain, "err", err)
			} else {
				slog.Info("added to map", "domain", domain, "ip", ip)
			}
		}

		line, err = readLine(reader)
	}

	slog.Info("blocklist loaded from", "file", *blocklist)

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_INGRESS,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		slog.Error("failed to replace qdisc:", "err", err)
	}
	slog.Info("qdisc replaced")

	filterIngress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           dns.TcIngress.FD(),
		Name:         dns.TcIngress.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filterIngress); err != nil {
		slog.Error("failed to replace tc filter", "err", err)
	}

	filterEgress := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           dns.TcEgress.FD(),
		Name:         dns.TcEgress.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filterEgress); err != nil {
		slog.Error("failed to replace tc filter", "err", err)
	}

	slog.Info("Press Ctrl-C to exit and remove the program")

	// Drop the logs
	go cat()
	<-ctx.Done()
	slog.Info("Removing eBPF programs")

	cleanup(ifname)
}

func cleanup(ifname *string) error {
	link, err := netlink.LinkByName(*ifname)
	if err != nil {
		slog.Error("could not find iface: %v", err)
	}

	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		slog.Error("could not list filters", "err", err)
	}

	if len(filters) == 0 {
		slog.Error("unable to clean any filters")
	}
	for x := range filters {
		err = netlink.FilterDel(filters[x])
		if err != nil {
			slog.Error("could not get remove filter", "err", err)
		}
	}

	filters, err = netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		slog.Error("could not list filters", "err", err)
	}

	if len(filters) == 0 {
		slog.Error("unable to clean any filters")
	}
	for i := range filters {
		err = netlink.FilterDel(filters[i])
		if err != nil {
			slog.Error("could not get remove filter", "err", err)
		}
	}

	return nil
}

func readLine(r *bufio.Reader) (string, error) {
	var (
		isPrefix bool  = true
		err      error = nil
		line, ln []byte
	)
	for isPrefix && err == nil {
		line, isPrefix, err = r.ReadLine()
		ln = append(ln, line...)
	}
	return string(ln), err
}

func cat() {
	file, err := os.Open("/sys/kernel/tracing/trace_pipe")
	if err != nil {
		slog.Error("could not read trace_pipe", "err", err)
	}
	defer file.Close()

	rd := bufio.NewReader(file)
	for {
		line, err := rd.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			slog.Error("error while reading line", "err", err)
		}

		fmt.Printf("%s", line)

	}
}

// htonl converts a 32-bit integer from host to network byte order
// https://linux.die.net/man/3/htonl
func htonl(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}

func convertDomain(name string) []byte {
	var convertedName []byte
	parts := strings.Split(name, ".")
	for x := range parts {
		convertedName = append(convertedName, uint8(len(parts[x])))
		convertedName = append(convertedName, parts[x]...)
	}
	return convertedName
}
