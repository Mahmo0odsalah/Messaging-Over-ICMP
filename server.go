package main

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


func RunServer(){
	disableOSEchoReplies();

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
  if err != nil {
    log.Panicf("Error in sniffing ICMP packets: %s", err)
  }
  defer c.Close()
  log.Println("Listening to incoming ICMP packets")
 
  p := make([]byte, 1500)
  for {
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
    }

    if err != nil {
      log.Panicf("Error in reading an ICMP packet: %s", err)
    }
  
    msg, err := icmp.ParseMessage(1, p)
    if err != nil {
      log.Panicf("Error in parsing an ICMP packet: %s", err)
    }
  
    if msg.Type == ipv4.ICMPTypeEcho{
      go handleServerMsg(msg, n, c, addr)
    }
  }

}


func handleServerMsg(msg *icmp.Message, n int, pn *icmp.PacketConn, addr net.Addr) {
  // assume everyone is sending msgs now
  body := msg.Body.(*icmp.Echo)
  us := gs[addr.String()]
  d := body.Data[:n-8]
	log.Println(string(d))
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


func disableOSEchoReplies(){
	sigCh := make(chan os.Signal,10)
  signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
  go func() {
    select {
    case <-sigCh:
      log.Println("Interrupted")
      enableOSEchoReplies()
      os.Exit(0)
    }
  }()

  f, err := os.Create("/proc/sys/net/ipv4/icmp_echo_ignore_all")
  if err != nil {
    log.Panicf("Cannot disable system echo replies: %s", err)
  }
  f.WriteString("1")
  f.Close()
  defer enableOSEchoReplies()
  log.Println("Disabled echo replies")
}

func enableOSEchoReplies() {
  f, err := os.Create("/proc/sys/net/ipv4/icmp_echo_ignore_all")
  if err != nil {
    log.Panicf("Cannot re-enable system echo replies: %s", err)
  }
  log.Println("Re-enabled echo replies")
  f.WriteString("0")
}
