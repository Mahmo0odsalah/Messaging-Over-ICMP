package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)


type state map[string]*userState

func (s state) String() string{
	res := "{\n"
	for u, us := range s {
		res += u
		res += ": [\n"
		for i, msg := range us.data {
      if i > us.ptr {
        res += ", "
      }
      if i >= us.ptr {
        res += string(msg)
      }
		}
		res += "]\n"
	}
	res += "}"
	return res
}

type userState struct {
  data [][]byte
  ptr int
  lock *sync.Mutex
}

func (us *userState) getNext()([]byte, int) {
  us.lock.Lock()
  defer us.lock.Unlock()
  if us.ptr >= len(us.data) {
    return make([]byte, 0), 0
  }
	msg := us.data[us.ptr]
  us.ptr += 1
  return msg, len(msg)
}

func (us *userState) append(msg []byte) {
  us.lock.Lock()
  defer us.lock.Unlock()

  us.data = append(us.data, msg)
  return
}

var gs state = make(state, 1000)

var rgsRgx, _ = regexp.Compile("register ([^ ]+)");
var sndRgx, _ = regexp.Compile("^([^ :]+):(.+)")
var rcvRgx, _ = regexp.Compile("receive:([^ :]+)")


func RunServer(){
	disableOSEchoReplies();

	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
  if err != nil {
    log.Panicf("Error in sniffing ICMP packets: %s", err)
  }
  defer c.Close()
  log.Println("Listening to incoming ICMP packets")
 

  for {
    p := make([]byte, 1500)
    n, addr, err := c.ReadFrom(p)

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
  body := msg.Body.(*icmp.Echo)
  d := body.Data[:n-8]
  sd := strings.TrimSpace(string(d))

  var rd []byte
	switch {
	case rgsRgx.Match(d):
		// TODO: Handle registering already existing user
		u := rgsRgx.FindStringSubmatch(string(d))[1]
		us := userState{
			make([][]byte, 0),
			0,
			&sync.Mutex{},
		}
		gs[u] = &us

		rd = d
  case rcvRgx.Match(d):
		u := rcvRgx.FindStringSubmatch(sd)[1]
		us, exs := gs[u]
		if exs {
			mb, nm := us.getNext()
			if nm == 0 {
				rd = []byte("No new messages")
			} else {
        rd = mb
      }
		} else {
      rd = []byte("User doesn't exist")
    }
  case sndRgx.Match(d):
    ms := sndRgx.FindStringSubmatch(sd)
    uname := ms[1]
    nm := ms[2]
    us, uex := gs[uname]
    if uex {
			us.append([]byte(nm))
			rd = d
    } else {
			rd = []byte("Target user not found")
    }
  default:
    rd = []byte("To send a new msg, username:msg. To receive, receive:username")
	}
	
	msg.Type = ipv4.ICMPTypeEchoReply;
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
