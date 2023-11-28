package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	getInterfaces()

	if socket, err := pcap.OpenLive("\\Device\\NPF_{10D5C58A-4A88-4F1A-A31C-11C7A7C74857}", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else {
		socket.SetBPFFilter("tcp dst port 80 or 443")
		packetSource := gopacket.NewPacketSource(socket, socket.LinkType())
		for packet := range packetSource.Packets() {
			fmt.Printf("Here is a packet \n: %s", packet.String())
		}

	}

}

func getInterfaces() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("error retrieving devices - %v", err)
	}

	for _, device := range devices {
		fmt.Printf("Device Name: %s\n", device.Name)
		fmt.Printf("Device Description: %s\n", device.Description)
		fmt.Printf("Device Flags: %d\n", device.Flags)
		for _, iaddress := range device.Addresses {
			fmt.Printf("\tInterface IP: %s\n", iaddress.IP)
			fmt.Printf("\tInterface NetMask: %s\n", iaddress.Netmask)
		}
	}
}
