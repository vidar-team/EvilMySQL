package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"net"
)

func NewClient(dsn string) (net.Conn, error) {
	conf, err := mysql.ParseDSN(dsn)
	if err != nil {
		fmt.Errorf("invalid dsn format:%s\n", dsn)
		return nil, errors.New("invalid dsn format")
	}
	conn, err := net.Dial("tcp", conf.Addr)
	if err != nil {
		return nil, err
	}

	greeting := readOnePacket(conn)
	part1 := greeting[16:24]
	part2 := greeting[43:55]
	salt := append(part1, part2...)
	hash := GetNativePwdHash(conf.Passwd, salt)

	packet := make([]byte, 0)
	// client capabilities
	packet = binary.LittleEndian.AppendUint16(packet, 0xa685)
	// extended client capabilities
	packet = binary.LittleEndian.AppendUint16(packet, 0x20ff)
	// max packet
	packet = binary.LittleEndian.AppendUint32(packet, 16777216)
	// charset
	packet = append(packet, 0x21)
	// unused
	packet = append(packet, make([]byte, 23, 23)...)
	// username
	packet = append(packet, []byte(conf.User+"\u0000")...)
	// password length
	packet = append(packet, uint8(len(hash)))
	// password
	packet = append(packet, hash...)
	// auth plugin
	packet = append(packet, []byte("mysql_native_password\u0000")...)

	// attribute
	attr := make(map[string]string)
	attr["_os"] = "linux"
	attr["_client_name"] = "libmariadb"
	attr["_pid"] = "177733"
	attr["_client_version"] = "3.3.2"
	attr["_platform"] = "x86_64"
	attr["program_name"] = "mysql"
	attr["_server_host"] = "127.0.0.1"
	tmp := make([]byte, 0)
	for k, v := range attr {
		tmp = append(tmp, uint8(len(k)))
		tmp = append(tmp, []byte(k)...)
		tmp = append(tmp, uint8(len(v)))
		tmp = append(tmp, []byte(v)...)
	}
	packet = append(packet, uint8(len(tmp)))
	packet = append(packet, tmp...)

	buf := addMysqlHeader(packet, 1)

	writeBody(conn, buf)
	readOnePacket(conn)
	return conn, nil
}
