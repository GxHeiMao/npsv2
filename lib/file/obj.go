package file

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ehang.io/nps/lib/rate"
	"github.com/pkg/errors"
)

type Flow struct {
	ExportFlow int64
	InletFlow  int64
	FlowLimit  int64
	sync.RWMutex
}

func (s *Flow) Add(in, out int64) {
	s.Lock()
	defer s.Unlock()
	s.InletFlow += int64(in)
	s.ExportFlow += int64(out)
}

type Config struct {
	U        string
	P        string
	Compress bool
	Crypt    bool
}

type Client struct {
	Cnf             *Config
	Id              int        //id
	VerifyKey       string     //verify key
	Addr            string     //the ip of client
	Remark          string     //remark
	Status          bool       //is allow connect
	IsConnect       bool       //is the client connect
	RateLimit       int        //rate /kb
	Flow            *Flow      //flow setting
	Rate            *rate.Rate //rate limit
	NoStore         bool       //no store to file
	NoDisplay       bool       //no display on web
	MaxConn         int        //the max connection num of client allow
	NowConn         int32      //the connection num of now
	WebUserName     string     //the username of web login
	WebPassword     string     //the password of web login
	ConfigConnAllow bool       //is allow connected by config file
	MaxTunnelNum    int
	Version         string
	sync.RWMutex
}

func NewClient(vKey string, noStore bool, noDisplay bool) *Client {
	return &Client{
		Cnf:       new(Config),
		Id:        0,
		VerifyKey: vKey,
		Addr:      "",
		Remark:    "",
		Status:    true,
		IsConnect: false,
		RateLimit: 0,
		Flow:      new(Flow),
		Rate:      nil,
		NoStore:   noStore,
		RWMutex:   sync.RWMutex{},
		NoDisplay: noDisplay,
	}
}

func (s *Client) CutConn() {
	atomic.AddInt32(&s.NowConn, 1)
}

func (s *Client) AddConn() {
	atomic.AddInt32(&s.NowConn, -1)
}

func (s *Client) GetConn() bool {
	if s.MaxConn == 0 || int(s.NowConn) < s.MaxConn {
		s.CutConn()
		return true
	}
	return false
}

func (s *Client) HasTunnel(t *Tunnel) (exist bool) {
	GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		v := value.(*Tunnel)
		if v.Client.Id == s.Id && v.Port == t.Port && t.Port != 0 {
			exist = true
			return false
		}
		return true
	})
	return
}

func (s *Client) GetTunnelNum() (num int) {
	GetDb().JsonDb.Tasks.Range(func(key, value interface{}) bool {
		v := value.(*Tunnel)
		if v.Client.Id == s.Id {
			num++
		}
		return true
	})
	return
}

func (s *Client) HasHost(h *Host) bool {
	var has bool
	GetDb().JsonDb.Hosts.Range(func(key, value interface{}) bool {
		v := value.(*Host)
		if v.Client.Id == s.Id && v.Host == h.Host && h.Location == v.Location {
			has = true
			return false
		}
		return true
	})
	return has
}

type Tunnel struct {
	Id           int
	Port         int
	S5User       string
	CreateTime   string
	ExpireTime   string
	ServerIp     string
	Mode         string
	Status       bool
	RunStatus    bool
	Client       *Client
	Ports        string
	Flow         *Flow
	Password     string
	Remark       string
	TargetAddr   string
	NoStore      bool
	LocalPath    string
	StripPre     string
	Target       *Target
	MultiAccount *MultiAccount
	Health
	sync.RWMutex
}

type GlobalAccountSort []*GlobalAccount

func (a GlobalAccountSort) Len() int { // 重写 Len() 方法
	return len(a)
}
func (a GlobalAccountSort) Swap(i, j int) { // 重写 Swap() 方法
	a[i], a[j] = a[j], a[i]
}
func (a GlobalAccountSort) Less(i, j int) bool { // 重写 Less() 方法， 从大到小排序
	return a[i].Id < a[j].Id
}

type GlobalAccount struct {
	Id              int    `json:"id"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	Status          int    `json:"status"`
	IsAuth          int    `json:"is_auth"`
	Udp             int    `json:"udp"`
	AutoReset       int    `json:"auto_reset"`
	DeviceWarning   int    `json:"device_warning"`
	Remark          string `json:"remark"`
	ListenIp        string `json:"listen_ip"`
	Mode            string `json:"mode"`
	ExpireTime      string `json:"expire_time"`
	TotalFlow       int    `json:"total_flow"`
	DeviceLimit     int    `json:"device_limit"`
	InletFlow       int    `json:"inlet_flow"`
	ExportFlow      int    `json:"export_flow"`
	UsedFlow        int    `json:"used_flow"`
	LoginIps        string `json:"login_ips"`
	HistoryLoginIps string `json:"history_login_ips"`
	NowConnCount    int    `json:"now_conn_count"`
	UpdatedAt       int    `json:"updated_at"`
	IsDel           int    `json:"is_del"`
	Flow            *Flow
}

type Health struct {
	HealthCheckTimeout  int
	HealthMaxFail       int
	HealthCheckInterval int
	HealthNextTime      time.Time
	HealthMap           map[string]int
	HttpHealthUrl       string
	HealthRemoveArr     []string
	HealthCheckType     string
	HealthCheckTarget   string
	sync.RWMutex
}

type Host struct {
	Id           int
	Host         string //host
	HeaderChange string //header change
	HostChange   string //host change
	Location     string //url router
	Remark       string //remark
	Scheme       string //http https all
	CertFilePath string
	KeyFilePath  string
	NoStore      bool
	IsClose      bool
	Flow         *Flow
	Client       *Client
	Target       *Target //目标
	Health       `json:"-"`
	sync.RWMutex
}

type Target struct {
	nowIndex   int
	TargetStr  string
	TargetArr  []string
	LocalProxy bool
	sync.RWMutex
}

type MultiAccount struct {
	AccountMap map[string]*GlobalAccount // multi account and pwd
}

func (s *Target) GetRandomTarget() (string, error) {
	if s.TargetArr == nil {
		s.TargetArr = strings.Split(s.TargetStr, "\n")
	}
	if len(s.TargetArr) == 1 {
		return s.TargetArr[0], nil
	}
	if len(s.TargetArr) == 0 {
		return "", errors.New("all inward-bending targets are offline")
	}
	s.Lock()
	defer s.Unlock()
	if s.nowIndex >= len(s.TargetArr)-1 {
		s.nowIndex = -1
	}
	s.nowIndex++
	return s.TargetArr[s.nowIndex], nil
}
