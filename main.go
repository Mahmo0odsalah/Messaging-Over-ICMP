package main

// sudo iptables -A INPUT -p icmp --icmp-type 8 -j DROP
import (
	"flag"
	"log"
	"net"
	"os"
)


func main(){
	hostName, err := os.Hostname()
	if (err != nil){
		hostName = "default"
	}

	serverFlag := flag.Bool("server", false, "run in server mode")
	clientFlag := flag.Bool("client", false, "run in client mode")
	serverIPFlag := flag.String("server-ip", "127.0.0.1", "Server IP (only when running in client mode)")
	usernameFlag := flag.String("username", hostName, "Username (only when running in client mode)")
	helpFlag := flag.Bool("help", false, "Show Command Usage")
	hFlag := flag.Bool("h", false, "alias to --help")

	flag.Parse()

	if *hFlag || *helpFlag {
		flag.PrintDefaults()
		os.Exit(0)
	}
	if *serverFlag && *clientFlag {
		log.Panicln("Cannot specify both server and client")
	}	else if !*serverFlag && !*clientFlag {
		log.Panicln("Must specify mode using --server or --client")
	}

  // TODO: Better command-line args validations, maybe use flags
  if *serverFlag {
    log.Println("Running in Server mode")
    RunServer()
  } else {
		srvrAddr := net.ParseIP(*serverIPFlag)
		if (srvrAddr == nil){
			log.Panicln("Provided Server IP is not a valid IP")
		}
    log.Printf("Running in Client mode, connecting to server %s with username %s", *serverIPFlag, *usernameFlag)

    RunClient(&srvrAddr, *usernameFlag)
  }
}
