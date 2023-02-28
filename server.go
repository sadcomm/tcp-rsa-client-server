package main

import (
	"fmt"
	"github.com/sadcomm/tcp-server-client/ciphers"
	"log"
	"net"
)

type Message struct {
	from             string
	payload          []byte
	decryptedMessage string
}

type Server struct {
	listenAddr string
	ln         net.Listener
	quitch     chan struct{}
	msgch      chan Message
}

func NewServer(listenAddr string) *Server {
	return &Server{
		listenAddr: listenAddr,
		quitch:     make(chan struct{}),
		msgch:      make(chan Message, 10),
	}
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()
	s.ln = ln

	go s.acceptLoop()

	<-s.quitch
	close(s.msgch)

	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			fmt.Println("accept error:", err)
			continue
		}

		fmt.Println("new connection from:", conn.RemoteAddr())

		go s.readLoop(conn)
	}
}

func (s *Server) readLoop(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 2048)
	privKey, pubKey := ciphers.GenerateKeyPair(2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Println("read error:", err)
			return
		}
		var answer []byte
		if string(buf[:n]) == "key\n" {
			answer = []byte(ciphers.PublicKeyToBytes(pubKey))
		} else {
			s.msgch <- Message{
				from:             conn.RemoteAddr().String(),
				payload:          buf[:n],
				decryptedMessage: string(ciphers.DecryptWithPrivateKey(buf[:n], privKey)),
			}
		}
		conn.Write(answer)
	}
}

func main() {
	server := NewServer(":3000")

	go func() {
		for msg := range server.msgch {
			if msg.decryptedMessage == "" {
				continue
			}
			fmt.Printf("\033[92mreceived decrypted message from connection (%s):\033[0m %s", msg.from, msg.decryptedMessage)
			fmt.Print("\033[92mencryption:\033[0m ")
			fmt.Println(msg.payload)
		}
	}()

	log.Fatal(server.Start())
}
