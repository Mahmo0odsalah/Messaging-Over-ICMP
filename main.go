package main

// sudo iptables -A INPUT -p icmp --icmp-type 8 -j DROP
import (
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type state map[string]userState

type userState struct {
  data [][]byte
  ptr int
  lock *sync.Mutex
}

func (us userState) getNext()[]byte {
  us.lock.Lock()
  defer us.lock.Unlock()

  if us.ptr >= len(us.data) {
    return make([]byte, 0)
  }
  us.ptr += 1
  return us.data[us.ptr]
}

func (us userState) append(msg []byte) {
  us.lock.Lock()
  defer us.lock.Unlock()

  us.data = append(us.data, msg)
  us.ptr +=1
  return
}

var gs state = make(state, 1000)


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

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
  if err != nil {
    log.Panicf("Error in sniffing ICMP packets: %s", err)
  }
  defer c.Close()
  log.Println("Listening to incoming ICMP packets")
  f, err := os.Create("/proc/sys/net/ipv4/icmp_echo_ignore_all")
  if err != nil {
    log.Panicf("Cannot disable system echo replies: %s", err)
  }
  f.WriteString("1")
  f.Close()
  defer enableEcho()
  log.Println("Disabled echo replies")
 
  p := make([]byte, 1500)
  for true {
    n, addr, err := c.ReadFrom(p)
    // Creating entries for first time users needs to happen sync to avoid overriding when the same new user sends multiple packets in quick succession
    _, fnd := gs[addr.String()]
    if fnd == false {
      us := userState{
        make([][]byte, 10),
        0,
        &sync.Mutex{},
      }
      gs[addr.String()] = us
      log.Println(gs)
    }

    if err != nil {
      log.Panicf("Error in reading an ICMP packet: %s", err)
    }
  
    msg, err := icmp.ParseMessage(1, p)
    if err != nil {
      log.Panicf("Error in parsing an ICMP packet: %s", err)
    }
  
    if(msg.Type == ipv4.ICMPTypeEcho){
      go handleMessage(msg, n, c, addr)
    }
  }

}
// 1472 bytes is the maximum payload size for ICMP

func handleMessage(msg *icmp.Message, n int, pn *icmp.PacketConn, addr net.Addr) {
  // assume everyone is sending msgs now:
  body := msg.Body.(*icmp.Echo)
  us := gs[addr.String()]
  d := body.Data[:n-8]
  log.Println(d)
  us.append(d)
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
