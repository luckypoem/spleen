package service

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
)

const BUFFERSIZE = 1024 * 4
const UDPBUFFERSIZE = 65536

type Service struct {
	ServerIP   string
	ServerPort int
}

func (s *Service) TCPRead(conn *net.TCPConn, buf []byte) (int, error) {
	readCount, errRead := conn.Read(buf)
	return readCount, errRead
}

func (s *Service) TCPWrite(conn *net.TCPConn, buf []byte, bufLen int) error {
	writeCount, errWrite := conn.Write(buf)
	if errWrite != nil {
		return errWrite
	}
	if bufLen != writeCount {
		return io.ErrShortWrite
	}
	return nil
}

func IPString2Long(ip string) (uint, error) {
	b := net.ParseIP(ip).To4()
	if b == nil {
		return 0, errors.New("invalid ipv4 format")
	}

	return uint(b[3]) | uint(b[2])<<8 | uint(b[1])<<16 | uint(b[0])<<24, nil
}

func (s *Service) ParseSOCKS5(userConn *net.TCPConn) (*net.TCPAddr, error, bool) {
	buf := make([]byte, BUFFERSIZE)

	readCount, errRead := s.TCPRead(userConn, buf)

	if readCount > 0 && errRead == nil {
		if buf[0] != 0x05 {
			/* Version Number */
			return &net.TCPAddr{}, errors.New("Only Support SOCKS5."), false
		} else {
			/* [SOCKS5, NO AUTHENTICATION REQUIRED]  */
			errWrite := s.TCPWrite(userConn, []byte{0x05, 0x00}, 2)
			if errWrite != nil {
				return &net.TCPAddr{}, errors.New("Response SOCKS5 failed at the first stage."), false
			}
		}
	}

	readCount, errRead = s.TCPRead(userConn, buf)
	if readCount > 0 && errRead == nil {
		if buf[1] != 0x01 && buf[1] != 0x03 {
			/* Only support CONNECT and UDP ASSOCIATE */
			return &net.TCPAddr{}, errors.New("Only support CONNECT and UDP ASSOCIATE method."), false
		}

		var dstIP []byte
		switch buf[3] { /* checking ATYPE */
		case 0x01: /* IPv4 */
			dstIP = buf[4 : 4+net.IPv4len]
		case 0x03: /* DOMAINNAME */
			ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:readCount-2]))
			if err != nil {
				return &net.TCPAddr{}, errors.New("Parse IP failed"), false
			}
			dstIP = ipAddr.IP
		case 0x04: /* IPV6 */
			dstIP = buf[4 : 4+net.IPv6len]
		default:
			return &net.TCPAddr{}, errors.New("Wrong DST.ADDR and DST.PORT"), false
		}
		dstPort := buf[readCount-2 : readCount]

		if buf[1] == 0x01 {
			/* TCP over SOCKS5 */
			dstAddr := &net.TCPAddr{
				IP:   dstIP,
				Port: int(binary.BigEndian.Uint16(dstPort)),
			}
			return dstAddr, errRead, false
		} else if buf[1] == 0x03 {
			/* UDP over SOCKS5 */
			header := []byte{0x05, 0x00, 0x00, 0x01}
			var respContent bytes.Buffer
			respContent.Write(header)
			/* Construct IP */
			uLocalIP, _ := IPString2Long(s.ServerIP)
			byteLocalIP := make([]byte, 4)
			binary.BigEndian.PutUint32(byteLocalIP, uint32(uLocalIP))
			respContent.Write(byteLocalIP)
			/* Construct Port */
			var randomPort int
			var udpListener *net.UDPConn
			var errListen error
			for {
				randomPort = rand.Int() % 1024
				udpListener, errListen = net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(s.ServerIP), Port: randomPort})
				if errListen != nil {
					continue
				} else {
					break
				}
			}
			uLocalPort := uint16(randomPort)
			byteLocalPort := make([]byte, 2)
			binary.BigEndian.PutUint16(byteLocalPort, uLocalPort)
			respContent.Write(byteLocalPort)
			/* [SOCKS5, succeeded, RSV, ATYP, BND.ADDR, BND.PORT] */
			err := s.TCPWrite(userConn, respContent.Bytes(), len(respContent.Bytes()))
			if err != nil {
				return &net.TCPAddr{}, errors.New("Response SOCKS5 failed at the UDP stage."), false
			}

			cliPort, _ := strconv.Atoi(string(buf[readCount-2 : readCount]))
			go s.HandleUDPData(udpListener, dstIP, cliPort)
			return &net.TCPAddr{}, nil, true

		} else {
			log.Println("Only support CONNECT and UDP ASSOCIATE method.")
			return &net.TCPAddr{}, errRead, false
		}
	}
	return &net.TCPAddr{}, errRead, false
}

func (s *Service) ForwardTCPData(srcConn *net.TCPConn, dstConn *net.TCPConn) error {
	buf := make([]byte, BUFFERSIZE)
	for {
		readCount, err := s.TCPRead(srcConn, buf)
		if err != nil {
			if err != io.EOF {
				return err
			} else {
				return nil
			}
		}
		if readCount > 0 {
			err = s.TCPWrite(dstConn, buf[0:readCount], readCount)
			if err != nil {
				return err
			}
		}
	}
}

func (s *Service) HandleUDPData(udpListener *net.UDPConn, cliIP []byte, cliPort int) error {
	for {
		buf := make([]byte, UDPBUFFERSIZE)
		readCount, remoteAddr, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read data over UDP failed.")
			return err
		}
		if readCount > 0 {
			if buf[2] != 0x00 {
				/* Discard fragment udp data package. */
				return errors.New("Discard fragment UDP data garam.")
			}

			var dstIP []byte
			dataIndex := 0
			switch buf[3] { /* verify ATYPE */
			case 0x01: /* IPv4 */
				dstIP = buf[4 : 4+net.IPv4len]
				dataIndex = 4 + net.IPv4len
			case 0x03: /* DOMAINNAME */
				domainLen := int(buf[5])
				ipAddr, err := net.ResolveIPAddr("ip", string(buf[6:6+domainLen]))
				if err != nil {
					return errors.New("Parse UDP address failed.")
				}
				dstIP = ipAddr.IP
			case 0x04: /* IPV6 */
				dstIP = buf[4 : 4+net.IPv6len]
				dataIndex = 4 + net.IPv6len
			default:
				return errors.New("Wrong DST.ADDR and DST.PORT in UDP")
			}

			dstPort := buf[dataIndex : dataIndex+2]
			dataIndex += 2
			/* Verify the source address */
			sourceIP := remoteAddr.IP.String()
			sourcePort := remoteAddr.Port

			if (sourceIP == string(cliIP) && cliPort == sourcePort) ||
				cliPort == 0 {
				srcAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
				dstAddr := &net.UDPAddr{IP: dstIP, Port: int(binary.BigEndian.Uint16(dstPort))}
				conn, err := net.DialUDP("udp", srcAddr, dstAddr)
				if err != nil {
					return errors.New("Dial UDP failed.")
				}
				defer conn.Close()

				/* Server forward UDP data gram to the destination address*/
				/* TODO verify writeCount */
				_, err = conn.Write(buf[dataIndex:readCount])
				if err != nil {
					return errors.New("Write UDP data garam failed.")
				}
				log.Printf("Server send the UDP data garam to %s:%d successed.", dstAddr.IP.String(), dstAddr.Port)

				resp := make([]byte, UDPBUFFERSIZE)
				readCount, _ = conn.Read(resp)

				/* TODO: verify writeCount */
				var respContent bytes.Buffer
				respContent.Write(buf[0:dataIndex])
				respContent.Write(resp[0:readCount])
				_, err = udpListener.WriteToUDP(respContent.Bytes(), remoteAddr)
				if err != nil {
					log.Println("Write UDP packet to client failed.")
					return err
				}
			}
		}
	}
}
