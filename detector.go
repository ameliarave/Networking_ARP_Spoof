/*
EECS 388 Project 3
Part 2. Anomaly Detection

detector.go
When completed and compiled, this program will:
- Open a .pcap file supplied as a command-line argument, and analyze
the TCP, IP, Ethernet, and ARP layers.
- Print the IP addresses that: 1) sent more than 3 times as many SYN packets
as the number of SYN+ACK packets they received, and 2) sent more than 5 SYN
packets in total.
- Print the MAC addresses that send more than 5 unsolicited ARP replies.
*/

package main

import (
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type host struct {
	synSent int
	synAck  int
}

func main() {
	if len(os.Args) != 2 {
		panic("Invalid command-line arguments")
	}
	pcapFile := os.Args[1]

	// Attempt to open file
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var host_map = make(map[string]*host)
	var request_map = make(map[string][]string)
	var bad_replies = make(map[string]int)

	// Loop through packets in file
	for packet := range packetSource.Packets() {
		el := packet.Layer(layers.LayerTypeEthernet)
		al := packet.Layer(layers.LayerTypeARP)
		il := packet.Layer(layers.LayerTypeIPv4)
		tl := packet.Layer(layers.LayerTypeTCP)

		validARP := el != nil && al != nil
		validTCP := el != nil && il != nil && tl != nil

		// If the packet doesn't appear to be a valid ARP or TCP packet, skip it.
		if !(validARP || validTCP) {
			continue
		}

		// Extract the actual information from the Ethernet layer.
		// See the definition of layers.Ethernet for more information.
		// (The ethernet layer is valid for both ARP and TCP packets.)

		switch {
		case validARP: 					// Extract the information from the ARP layer.
			arp := al.(*layers.ARP)
			arpWork(arp, request_map, bad_replies)
		case validTCP: 					// Extract the information from the IP and TCP layers.
			ip := il.(*layers.IPv4)
			tcp := tl.(*layers.TCP)
			Src_IP_str := ip.SrcIP.String()
			Dst_IP_str := ip.DstIP.String()
			keyCheckCreate(host_map, Src_IP_str) 	// Checks if key,val exists and creates it if not
			keyCheckCreate(host_map, Dst_IP_str)
			if tcp.SYN && tcp.ACK { 		// SYN-ACK received by IP Addr
				host_map[Dst_IP_str].synAck++
			} else if tcp.SYN && !tcp.ACK { 	// SYN sent by IP Addre
				host_map[Src_IP_str].synSent++
			}
		}
	}
	fmt.Println("Unauthorized SYN scanners:")
	for key, elt := range host_map {
		if elt.synSent > 5 && (elt.synSent > (3 * elt.synAck)) {
			fmt.Println(key)
		}
	}
	fmt.Println("Unauthorized ARP spoofers:")
	for key, elt := range bad_replies {
		if elt > 5 {
			fmt.Println(key)
		}
	}
} // end main

func unsolicitedReply(replies map[string]int, reply_MAC string) { 	// Handles an unsolicited reply by incrementing a count or adding MAC to keys
	if _, exists := replies[reply_MAC]; !exists { 			// Key doesn't exist yet
		replies[reply_MAC] = 1 					// This MAC has 1 unsolicited ARP replies
	} else {
		replies[reply_MAC]++ 					// Increment MAC address's #unsolicited replies
	}
}

func keyCheckCreate(host_map map[string]*host, ipAddr string) { 	// Checks if key exists, creates key,val if doesn't
	if _, check := host_map[ipAddr]; !check {
		temp := &host{0, 0}
		host_map[ipAddr] = temp
		temp = nil
	}
}

func arpWork(arp *layers.ARP, request_map map[string][]string, bad_replies map[string]int) {
	Src_MAC_str := net.HardwareAddr(arp.SourceHwAddress).String()
	Src_IP_str := net.IP(arp.SourceProtAddress).String()
	Dst_MAC_str := net.HardwareAddr(arp.DstHwAddress).String()
	Dst_IP_str := net.IP(arp.DstProtAddress).String()
	switch arp.Operation {
	case 2: // Received a reply arp packet
		if arr, check := request_map[Src_IP_str]; check { 	// Checking if there's a pending request for this IP address
			flag := true              			// Unsolicited reply flag. Set false if a matching request found.
			for i, MAC := range arr { 			// Searching for MAC in arr matching reply's destination
				if MAC == Dst_MAC_str {
					if len(arr) > 1 { 		// Multiple hosts requested this IP addr, only delete one we fulfilled
						arr[i] = arr[len(arr)-1]                   // copy last element to index i
						arr[len(arr)-1] = ""                       // write empty value
						request_map[Src_IP_str] = arr[:len(arr)-1] // truncate slice: cut off empty value
					} else { 			// Request fulfilled, delete the key,val pair
						delete(request_map, Src_IP_str)
					}
					flag = false 			// Disable flag b/c found a match. If still true after loop, no match.
					break        			// Exit for loop, one reply fulfils one request
				}
			}
			if flag { 					// Mark this reply as unsolicited.
				unsolicitedReply(bad_replies, Src_MAC_str)
			}
		} else { 						// Unsolicited reply.
			unsolicitedReply(bad_replies, Src_MAC_str)
		}
	case 1: 							// Received an arp request packet
		if _, check := request_map[Dst_IP_str]; !check { 	// If no request for this IP exists, create it & add sender's MAC to inner array
			temp := []string{Src_MAC_str}
			request_map[Dst_IP_str] = temp
			temp = nil
		} else { 						// Request for this IP already exists, append sender's MAC address
			MAC_arr := request_map[Dst_IP_str] 		// Maybe optimize this for less copying
			MAC_arr = append(MAC_arr, Src_MAC_str)
			request_map[Dst_IP_str] = MAC_arr
		}
	}
}

/*
Hints and Links to Documentation:

https://github.com/google/gopacket/blob/master/layers/tcp.go Lines 20-35
https://github.com/google/gopacket/blob/master/layers/ip4.go Lines 43-59
https://github.com/google/gopacket/blob/master/layers/arp.go Lines 18-36
In arp.go, HwAddress is the MAC address, and
ProtAddress is the IP address in this case. Both are []byte variables.
*/
