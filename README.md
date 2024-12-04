# Messaging Over ICMP

A centralized messaging solution for very restrictive networks over [ICMP](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) written in Go. If your client device can perform a simple `ping google.com`, it can use this.

# Basic Idea

[The ICMP RFC](https://datatracker.ietf.org/doc/html/rfc792) allows for sending a payload as part of the message. The protocol also has built-in acknowledgments without the need for transport level acknowledgments (An Echo Request is replied to with An Echo Reply containing the same ID). The client sends their messages as ICMP Echo Requests to the centralized Server, which responds with an Echo Reply, acknowledging the message was successfully delivered. For receiving messages, the client sends an Echo Request containing a special payload, and the server responds with an Echo Reply containing the next available message addressed to the user, or with a message indicating there are no more messages left. This approach means the client can [receive messages behind a NAT](https://superuser.com/questions/135094/how-does-a-nat-server-forward-ping-icmp-echo-reply-packets-to-users)

# NAT, IPv4 and IPv6

One of the major advantages of the Client Server approach is sending messages to clients behind NAT. Also, since ICMP is a port-less protocol, port forwarding is not an option .A simpler, safer P2P design can be implemented if both peers use IPv6.

# Usage

The program can run in either client or server mode. It needs root permissions in both cases in order to sniff ICMP packets.

## Server Mode

To run the program in server mode.
`./icmp-chat --server`

There is no limit to clients using the same server.

## Client Mode

`./icmp-chat --client --server-ip=SERVER_IP --username=USERNAME`

Once in client mode, you can:

- Send a new message, using `username:message`
- Request incoming messages, using `receive:username`
