package main

// sudo iptables -A INPUT -p icmp --icmp-type 8 -j DROP
import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main(){
  sigCh := make(chan os.Signal,10)
  signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
  go func() {
    select {
    case <-sigCh:
      log.Println("Interrupted")
      enableEcho()
      os.Exit(0)
    }
  }()

	pn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
  if err != nil {
    log.Panicf("Error in sniffing ICMP packets: %s", err)
  }
  defer pn.Close()
  log.Println("Listening to incoming ICMP packets")
  f, err := os.Create("/proc/sys/net/ipv4/icmp_echo_ignore_all")
  if err != nil {
    log.Panicf("Cannot disable system echo replies: %s", err)
  }
  f.WriteString("1")
  f.Close()
  defer enableEcho()
  log.Println("Disabled echo replies")

  p := make([]byte, 5000)
  for true {
    _, addr, err := pn.ReadFrom(p)
    if err != nil {
      log.Panicf("Error in reading an ICMP packet: %s", err)
    }

  
    msg, err := icmp.ParseMessage(1, p)
    if err != nil {
      log.Panicf("Error in parsing an ICMP packet: %s", err)
    }
  
    if(msg.Type == ipv4.ICMPTypeEcho){
      go handleMessage(msg, pn, addr)
    }
  }

}

func handleMessage(msg *icmp.Message, pn *icmp.PacketConn, addr net.Addr) {
  body := msg.Body.(*icmp.Echo)
      msg.Type = ipv4.ICMPTypeEchoReply;
      msg.Body = &icmp.Echo{
        ID: body.ID,
        Seq: body.Seq,
        Data: []byte("Testing 123"),
      }
      b, _ := msg.Marshal(nil)
      pn.WriteTo(b, addr)
}

func enableEcho() {
  f, err := os.Create("/proc/sys/net/ipv4/icmp_echo_ignore_all")
  if err != nil {
    log.Panicf("Cannot re-enable system echo replies: %s", err)
  }
  log.Println("Re-enabled echo replies")
  f.WriteString("0")
}
