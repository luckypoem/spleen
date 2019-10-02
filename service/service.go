package service

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
  "net"
)

const BUFFERSIZE = 1024 * 4

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

func (s *Service) ParseSOCKS5(userConn *net.TCPConn) (*net.TCPAddr, error) {
	buf := make([]byte, BUFFERSIZE)

	readCount, errRead := s.TCPRead(userConn, buf)
	if errRead == io.EOF {
		return &net.TCPAddr{}, errRead
	}
	if readCount > 0 && errRead == nil {
		if buf[0] != 0x05 {
			/* Version Number */
			return &net.TCPAddr{}, errors.New("Only Support SOCKS5.")
		} else {
			/* [SOCKS5, NO AUTHENTICATION REQUIRED]  */
			errWrite := s.TCPWrite(userConn, []byte{0x05, 0x00}, 2)
			if errWrite != nil {
				return &net.TCPAddr{}, errors.New("Response SOCKS5 failed at the first stage.")
			}
		}
	}

	readCount, errRead = s.TCPRead(userConn, buf)
	if errRead == io.EOF {
		return &net.TCPAddr{}, errRead
	}
	if readCount > 0 && errRead == nil {
		if buf[1] != 0x01 {
			/* Only support CONNECT method */
			return &net.TCPAddr{}, errors.New("Only support CONNECT method.")
		}

		var dstIP []byte
		switch buf[3] { /* checking ATYPE */
		case 0x01: /* IPv4 */
			dstIP = buf[4 : 4+net.IPv4len]
		case 0x03: /* DOMAINNAME */
			ipAddr, err := net.ResolveIPAddr("ip", string(buf[5:readCount-2]))
			if err != nil {
				return &net.TCPAddr{}, errors.New("Parse IP failed")
			}
			dstIP = ipAddr.IP
		case 0x04: /* IPV6 */
			dstIP = buf[4 : 4+net.IPv6len]
		default:
			return &net.TCPAddr{}, errors.New("Wrong DST.ADDR and DST.PORT")
		}
		dstPort := buf[readCount-2 : readCount]

		if buf[1] == 0x01 {
			/* TCP over SOCKS5 */
			dstAddr := &net.TCPAddr{
				IP:   dstIP,
				Port: int(binary.BigEndian.Uint16(dstPort)),
			}
			return dstAddr, errRead
		} else {
			log.Println("Only support CONNECT method.")
			return &net.TCPAddr{}, errRead
		}
	}
	return &net.TCPAddr{}, errRead
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
