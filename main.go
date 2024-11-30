package main

// sudo iptables -A INPUT -p icmp --icmp-type 8 -j DROP
import (
	"log"
	"os"
)


func main(){
  if len(os.Args) < 2 {
    log.Panic("Please specify the mode to run.")
  }
  // TODO: Better command-line args validations, maybe use flags
  if os.Args[1] == "s" {
    log.Println("Running in Server mode")
    RunServer()
  } else {
    log.Println("Running in Client mode")
    RunClient(os.Args[2], os.Args[3])
  }
}
