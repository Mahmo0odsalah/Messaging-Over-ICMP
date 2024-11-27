package main

import (
	"bufio"
	"log"
	"net"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var c *icmp.PacketConn
var srvr net.Addr

func RunClient(srvrAddr string){
	srvr = &net.IPAddr{IP: net.ParseIP(srvrAddr)}
	var err error;
	c, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
  if err != nil {
    log.Panicf("Error in sniffing ICMP packets: %s", err)
  }
  defer c.Close()
  log.Println("Listening to incoming ICMP packets")
 
  p := make([]byte, 1500)

	go readNewMessages()
  for {
    _, _, err := c.ReadFrom(p)
		if err != nil {
			log.Panicf("Error in reading an ICMP packet: %s", err)
    }
		
    msg, err := icmp.ParseMessage(1, p)
		if err != nil {
			log.Panicf("Error in parsing an ICMP packet: %s", err)
		}
		
		log.Println(msg)
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

func sendMsg(cnt string){
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 1,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff,
			Seq: 1,
			Data: []byte(cnt),
		},
	}

	mb, _ := msg.Marshal(nil)
	_, err := c.WriteTo(mb, srvr)
	if err != nil {
		log.Println(err)
	}
}

func handleClientMsg(msg *icmp.Message, n int, pn *icmp.PacketConn, addr net.Addr) {
  // assume everyone is sending msgs now
  body := msg.Body.(*icmp.Echo)
  us := gs[addr.String()]
  d := body.Data[:n-8]
  us.append(d)
  mode := 's' // TODO: Calculate mode based on the msg content (d), a special code should mean receive, anything else is send
  msg.Type = ipv4.ICMPTypeEchoReply;
  var rd []byte
  if mode == 's' {
     rd = d
     
  } else {
    rd = []byte("received")
  }
  msg.Body = &icmp.Echo{
    ID: body.ID,
    Seq: body.Seq,
    Data: rd,
  }
  b, _ := msg.Marshal(nil)
  pn.WriteTo(b, addr)
}
