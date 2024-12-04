package main

import (
	"bufio"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var c *icmp.PacketConn
var srvr net.Addr

func RunClient(srvrAddr *net.IP, usr string){
	srvr = &net.IPAddr{IP: *srvrAddr}
	var err error;
	c, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
  if err != nil {
    log.Panicf("Error in sniffing ICMP packets: %s", err)
  }
  defer c.Close()
  log.Println("Listening to incoming ICMP packets")
  
  err = sendMsg("register " + usr)
  if err != nil {
    log.Panicln("Couldn't register")
  }

  
	go readNewMessages()
  for {
    p := make([]byte, 1500)
    _, _, err := c.ReadFrom(p)
		if err != nil {
      log.Panicf("Error in reading an ICMP packet: %s", err)
    }
		
    msg, err := icmp.ParseMessage(1, p)
		if err != nil {
      log.Panicf("Error in parsing an ICMP packet: %s", err)
		}
		
    prsd := msg.Body.(*icmp.Echo)
    log.Println(strings.TrimSpace(string(prsd.Data)))
  }

}

func readNewMessages(){
	for {
		in := bufio.NewReader(os.Stdin)
		line, err := in.ReadString('\n')
		if err == nil {
			go sendMsg(line)
		}
	}
}

func sendMsg(m string) error{
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 1,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff,
			Seq: 1,
			Data: []byte(m),
		},
	}

	mb, _ := msg.Marshal(nil)
	_, err := c.WriteTo(mb, srvr)
	if err != nil {
		log.Println(err)
    return err
	}
  return nil
}
