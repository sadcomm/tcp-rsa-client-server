package main

import (
	"bufio"
	"crypto/rsa"
	"fmt"
	"github.com/sadcomm/tcp-server-client/ciphers"
	"net"
	"os"
	"strings"
)

const (
	CONN_HOST = "localhost"
	CONN_PORT = "3000"
	CONN_TYPE = "tcp"
)

func Start(conn_type string, conn_host string, conn_port string) {

	c, err := net.Dial(conn_type, conn_host+":"+conn_port)
	if err != nil {
		fmt.Println(err)
		return
	}

	buf := make([]byte, 2048)
	pubKey := &rsa.PublicKey{}
	n := 0
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("\033[92m>> \033[0m")
		text, _ := reader.ReadString('\n')
		if pubKey.N == nil {
			fmt.Println("pubKey received")
			fmt.Fprintf(c, text)
			n, _ = c.Read(buf)
			pubKey = ciphers.BytesToPublicKey(buf[:n])
		} else {
			encryptedText := ciphers.EncryptWithPublicKey([]byte(text), pubKey)
			fmt.Print("\033[92mEncryptedText:\033[0m ")
			fmt.Println(encryptedText)
			c.Write(encryptedText)
		}

		if strings.TrimSpace(string(text)) == "STOP" {
			fmt.Println("Отключение TCP клиента...")
			return
		}
	}
}

func main() {
	Start(CONN_TYPE, CONN_HOST, CONN_PORT)
}
