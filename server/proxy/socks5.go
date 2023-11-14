package proxy

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"ehang.io/nps/lib/common"

	"ehang.io/nps/lib/conn"
	"ehang.io/nps/lib/file"
	localUser "ehang.io/nps/user"
	"github.com/astaxie/beego/logs"
)

const (
	ipV4            = 1
	domainName      = 3
	ipV6            = 4
	connectMethod   = 1
	bindMethod      = 2
	associateMethod = 3
	// The maximum packet size of any udp Associate packet, based on ethernet's max size,
	// minus the IP and UDP headers. IPv4 has a 20 byte header, UDP adds an
	// additional 4 bytes.  This is a total overhead of 24 bytes.  Ethernet's
	// max packet size is 1500 bytes,  1500 - 24 = 1476.
	maxUDPPacketSize = 1476
)

const (
	succeeded uint8 = iota
	serverFailure
	notAllowed
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

const (
	UserPassAuth    = uint8(2)
	userAuthVersion = uint8(1)
	authSuccess     = uint8(0)
	authFailure     = uint8(1)
)

type Sock5ModeServer struct {
	BaseServer
	listener net.Listener
	AuthUser *file.GlobalAccount
}

// req
func (s *Sock5ModeServer) handleRequest(c net.Conn, userFlow *file.Flow) {
	/*
		The SOCKS request is formed as follows:
		+----+-----+-------+------+----------+----------+
		|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+
	*/
	header := make([]byte, 3)

	_, err := io.ReadFull(c, header)

	if err != nil {
		logs.Warn("illegal request", err)
		c.Close()
		return
	}

	switch header[1] {
	case connectMethod:
		s.handleConnect(c, userFlow)
	case bindMethod:
		s.handleBind(c)
	case associateMethod:
		s.handleUDP(c)
	default:
		s.sendReply(c, commandNotSupported)
		c.Close()
	}
}

// reply
func (s *Sock5ModeServer) sendReply(c net.Conn, rep uint8) {
	reply := []byte{
		5,
		rep,
		0,
		1,
	}

	localAddr := c.LocalAddr().String()
	localHost, localPort, _ := net.SplitHostPort(localAddr)
	ipBytes := net.ParseIP(localHost).To4()
	nPort, _ := strconv.Atoi(localPort)
	reply = append(reply, ipBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(nPort))
	reply = append(reply, portBytes...)

	c.Write(reply)
}

// do conn
func (s *Sock5ModeServer) doConnect(c net.Conn, command uint8, userFlow *file.Flow) {
	addrType := make([]byte, 1)
	c.Read(addrType)
	var host string
	switch addrType[0] {
	case ipV4:
		ipv4 := make(net.IP, net.IPv4len)
		c.Read(ipv4)
		host = ipv4.String()
	case ipV6:
		ipv6 := make(net.IP, net.IPv6len)
		c.Read(ipv6)
		host = ipv6.String()
	case domainName:
		var domainLen uint8
		binary.Read(c, binary.BigEndian, &domainLen)
		domain := make([]byte, domainLen)
		c.Read(domain)
		host = string(domain)
	default:
		s.sendReply(c, addrTypeNotSupported)
		return
	}

	var port uint16
	binary.Read(c, binary.BigEndian, &port)
	// connect to host
	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	var ltype string
	if command == associateMethod {
		ltype = common.CONN_UDP
	} else {
		ltype = common.CONN_TCP
	}
	s.DealClient(conn.NewConn(c), s.task.Client, addr, nil, ltype, func() {
		s.sendReply(c, succeeded)
	}, userFlow, s.task.Target.LocalProxy)
	return
}

// conn
func (s *Sock5ModeServer) handleConnect(c net.Conn, userFlow *file.Flow) {
	s.doConnect(c, connectMethod, userFlow)
}

// passive mode
func (s *Sock5ModeServer) handleBind(c net.Conn) {
}
func (s *Sock5ModeServer) sendUdpReply(writeConn net.Conn, c net.Conn, rep uint8, serverIp string) {
	reply := []byte{
		5,
		rep,
		0,
		1,
	}
	localHost, localPort, _ := net.SplitHostPort(c.LocalAddr().String())
	localHost = serverIp
	ipBytes := net.ParseIP(localHost).To4()
	nPort, _ := strconv.Atoi(localPort)
	reply = append(reply, ipBytes...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(nPort))
	reply = append(reply, portBytes...)
	writeConn.Write(reply)

}

func (s *Sock5ModeServer) handleUDP(c net.Conn) {
	defer c.Close()
	addrType := make([]byte, 1)
	c.Read(addrType)
	var host string
	switch addrType[0] {
	case ipV4:
		ipv4 := make(net.IP, net.IPv4len)
		c.Read(ipv4)
		host = ipv4.String()
	case ipV6:
		ipv6 := make(net.IP, net.IPv6len)
		c.Read(ipv6)
		host = ipv6.String()
	case domainName:
		var domainLen uint8
		binary.Read(c, binary.BigEndian, &domainLen)
		domain := make([]byte, domainLen)
		c.Read(domain)
		host = string(domain)
	default:
		s.sendReply(c, addrTypeNotSupported)
		return
	}
	//读取端口
	var port uint16
	binary.Read(c, binary.BigEndian, &port)
	logs.Warn(host, string(port))
	replyAddr, err := net.ResolveUDPAddr("udp", s.task.ServerIp+":0")
	if err != nil {
		logs.Error("build local reply addr error", err)
		return
	}
	reply, err := net.ListenUDP("udp", replyAddr)
	if err != nil {
		s.sendReply(c, addrTypeNotSupported)
		logs.Error("listen local reply udp port error")
		return
	}
	// reply the local addr
	s.sendUdpReply(c, reply, succeeded, common.GetServerIpByClientIp(c.RemoteAddr().(*net.TCPAddr).IP))
	defer reply.Close()
	// new a tunnel to client
	link := conn.NewLink("udp5", "", s.task.Client.Cnf.Crypt, s.task.Client.Cnf.Compress, c.RemoteAddr().String(), false)
	target, err := s.bridge.SendLinkInfo(s.task.Client.Id, link, s.task)
	if err != nil {
		logs.Warn("get connection from client id %d  error %s", s.task.Client.Id, err.Error())
		return
	}

	var clientAddr net.Addr
	// copy buffer
	go func() {
		b := common.BufPoolUdp.Get().([]byte)
		defer common.BufPoolUdp.Put(b)
		defer c.Close()

		for {
			n, laddr, err := reply.ReadFrom(b)
			if err != nil {
				logs.Error("read data from %s err %s", reply.LocalAddr().String(), err.Error())
				return
			}
			if clientAddr == nil {
				clientAddr = laddr
			}
			if _, err := target.Write(b[:n]); err != nil {
				logs.Error("write data to client error", err.Error())
				return
			}
		}
	}()

	go func() {
		var l int32
		b := common.BufPoolUdp.Get().([]byte)
		defer common.BufPoolUdp.Put(b)
		defer c.Close()
		for {
			if err := binary.Read(target, binary.LittleEndian, &l); err != nil || l >= common.PoolSizeUdp || l <= 0 {
				logs.Warn("read len bytes error", err.Error())
				return
			}
			binary.Read(target, binary.LittleEndian, b[:l])
			if err != nil {
				logs.Warn("read data form client error", err.Error())
				return
			}
			if _, err := reply.WriteTo(b[:l], clientAddr); err != nil {
				logs.Warn("write data to user ", err.Error())
				return
			}
		}
	}()

	b := common.BufPoolUdp.Get().([]byte)
	defer common.BufPoolUdp.Put(b)
	defer target.Close()
	for {
		_, err := c.Read(b)
		if err != nil {
			c.Close()
			return
		}
	}
}

// new conn
func (s *Sock5ModeServer) handleConn(c net.Conn) {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		logs.Warn("negotiation err", err)
		c.Close()
		return
	}

	if version := buf[0]; version != 5 {
		logs.Warn("only support socks5, request from: ", c.RemoteAddr())
		c.Close()
		return
	}
	nMethods := buf[1]

	methods := make([]byte, nMethods)
	if len, err := c.Read(methods); len != int(nMethods) || err != nil {
		logs.Warn("wrong method")
		c.Close()
		return
	}
	/*
		if (s.task.Client.Cnf.U != "" && s.task.Client.Cnf.P != "") || (s.task.MultiAccount != nil && len(s.task.MultiAccount.AccountMap) > 0) {
			buf[1] = UserPassAuth
			c.Write(buf)
			if err := s.Auth(c); err != nil {
				c.Close()
				logs.Warn("Validation failed:", err)
				return
			}
		} else {
			buf[1] = 0
			c.Write(buf)
		}
	*/
	buf[1] = UserPassAuth
	c.Write(buf)
	userFlow := new(file.Flow)
	var err error
	if err, userFlow = s.Auth(c); err != nil {
		c.Close()
		logs.Warn("Validation failed:", err)
		return
	}
	s.handleRequest(c, userFlow)
}

// socks5 auth
func (s *Sock5ModeServer) Auth(c net.Conn) (error, *file.Flow) {
	header := []byte{0, 0}
	if _, err := io.ReadAtLeast(c, header, 2); err != nil {
		return err, nil
	}
	if header[0] != userAuthVersion {
		return errors.New("验证方式不被支持"), nil
	}
	userLen := int(header[1])
	user := make([]byte, userLen)
	if _, err := io.ReadAtLeast(c, user, userLen); err != nil {
		return err, nil
	}
	if _, err := c.Read(header[:1]); err != nil {
		return errors.New("密码长度获取错误"), nil
	}
	passLen := int(header[0])
	pass := make([]byte, passLen)
	if _, err := io.ReadAtLeast(c, pass, passLen); err != nil {
		return err, nil
	}

	var U string
	//if s.task.MultiAccount != nil {
	//	// enable multi user auth
	//	U = string(user)
	//	var ok bool
	//	P, ok = s.task.MultiAccount.AccountMap[U]
	//	if !ok {
	//		return errors.New("验证不通过")
	//	}
	//} else {
	//	U = s.task.Client.Cnf.U
	//	P = s.task.Client.Cnf.P
	//}
	U = string(user)
	//var ok bool
	var aInfo *file.GlobalAccount
	for _, account := range localUser.GlobalUserList {
		if account.Username == U {
			aInfo = account
		}
	}
	//aInfo, ok := s.task.MultiAccount.AccountMap[U]
	if aInfo == nil || len(aInfo.Username) <= 0 {
		return errors.New("验证不通过"), nil
	}
	/*
		1、校验用户有效期
		2、校验用户连接数
		3、校验用户流量
		4、账号是否停用
	*/
	if aInfo.Status != 1 || aInfo.IsDel == 2 {
		return errors.New("账号已停用"), nil
	}
	if aInfo.IsAuth == 0 {
		return nil, nil
	}
	if len(aInfo.ExpireTime) > 0 {
		if time.Now().Format("2006-01-02 15:04:05") > aInfo.ExpireTime {
			return errors.New("账号已过有效期"), nil
		}
	}
	if aInfo.DeviceLimit > 0 {
		if aInfo.NowConnCount > aInfo.DeviceLimit {
			return errors.New("已超过最大连接数"), nil
		}
	}
	if aInfo.TotalFlow > 0 {
		if aInfo.UsedFlow > aInfo.TotalFlow {
			return errors.New("流量已超"), nil
		}
	}
	remoteIp := c.RemoteAddr().String()
	ipArr := strings.Split(remoteIp, ":")
	if len(ipArr) >= 2 {
		remoteIp = ipArr[0]
	}
	nowIpArr := make(map[string]int64)
	json.Unmarshal([]byte(aInfo.LoginIps), &nowIpArr)
	if _, okIp := nowIpArr[remoteIp]; !okIp {
		if aInfo.DeviceLimit > 0 && len(nowIpArr) > aInfo.DeviceLimit {
			return errors.New("连接数超过限制"), nil
		}
	}
	nowIpArr[remoteIp] = time.Now().Unix()
	ipBytes, _ := json.Marshal(nowIpArr)
	aInfo.LoginIps = string(ipBytes)
	if string(user) == U && string(pass) == aInfo.Password {
		if _, err := c.Write([]byte{userAuthVersion, authSuccess}); err != nil {
			return err, nil
		}
		return nil, aInfo.Flow
	} else {
		if _, err := c.Write([]byte{userAuthVersion, authFailure}); err != nil {
			return err, nil
		}
		return errors.New("验证不通过"), nil
	}
}

// start
func (s *Sock5ModeServer) Start() error {
	return conn.NewTcpListenerAndProcess(s.task.ServerIp+":"+strconv.Itoa(s.task.Port), func(c net.Conn) {
		if err := s.CheckFlowAndConnNum(s.task.Client); err != nil {
			logs.Warn("client id %d, task id %d, error %s, when socks5 connection", s.task.Client.Id, s.task.Id, err.Error())
			c.Close()
			return
		}
		logs.Trace("New socks5 connection,client %d,remote address %s", s.task.Client.Id, c.RemoteAddr())
		s.handleConn(c)
		s.task.Client.AddConn()
	}, &s.listener)
}

// new
func NewSock5ModeServer(bridge NetBridge, task *file.Tunnel) *Sock5ModeServer {
	s := new(Sock5ModeServer)
	s.bridge = bridge
	s.task = task
	return s
}

// close
func (s *Sock5ModeServer) Close() error {
	return s.listener.Close()
}
