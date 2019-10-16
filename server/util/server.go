package server

import (
	"io"
	"log"
	"net"

	"github.com/luckypoem/spleen/service"
)

type server struct {
	*service.Service
}

func NewServer(localIP string, localPort int) *server {
	return &server{
		&service.Service{
			ServerIP:   localIP,
			ServerPort: localPort,
		},
	}
}

func (s *server) Listen() error {
	log.Printf("Server local address: %s:%d", s.ServerIP, s.ServerPort)

	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(s.ServerIP), Port: s.ServerPort})
	if err != nil {
		return err
	} else {
		log.Printf("Server listen at %s:%d successed.", s.ServerIP, s.ServerPort)
	}
	defer tcpListener.Close()

	for {
		userConn, err := tcpListener.AcceptTCP()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		_ = userConn.SetLinger(0)
		go s.handleTCPConn(userConn)
	}

}

func (s *server) handleTCPConn(userConn *net.TCPConn) {
	defer userConn.Close()

	dstAddr, errParse := s.ParseSOCKS5(userConn)
	if errParse == io.EOF {
		log.Printf("Connection closed.")
		return
	}
	if errParse != nil{
		log.Printf("%s", errParse.Error())
		return
	}

	/* Server should direct connect to the destination address. */
	serverConn, err := net.DialTCP("tcp", nil, dstAddr)
	if err != nil {
		log.Printf("Connect to %s:%d failed.", dstAddr.IP.String(), dstAddr.Port)
		return
	} else {
		log.Printf("Server connect to the destination address success %s:%d.", dstAddr.IP, dstAddr.Port)
	}
	defer serverConn.Close()
	_ = serverConn.SetLinger(0)

	/* If connect success, we also need to reply to the client success. */
	err = s.TCPWrite(userConn, []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 10)
	if err != nil {
		log.Println("Server reply the SOCKS5 procotol failed at the second stage.")
		return
	}

	go func() {
		err := s.ForwardTCPData(userConn, serverConn)
		if err != nil {
			_ = userConn.Close()
			_ = serverConn.Close()
		}
	}()
	err = s.ForwardTCPData(serverConn, userConn)
}
