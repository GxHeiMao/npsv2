package controllers

import (
	"sort"

	"ehang.io/nps/user"

	"ehang.io/nps/lib/file"
)

type UserController struct {
	BaseController
}

// 获取用户列表
func (s *UserController) List() {
	username := s.getEscapeString("user")
	page := s.GetIntNoErr("page")
	limit := s.GetIntNoErr("limit")
	start := (page - 1) * limit
	state := s.GetIntNoErr("state")
	//listService, _ := server.GetTunnel(0, 1, "socks5", 0, "")
	//var userList []*file.GlobalAccount
	//for _, value := range listService {
	//	if value.MultiAccount != nil {
	//		for _, s2 := range value.MultiAccount.AccountMap {
	//			userList = append(userList, s2)
	//		}
	//		break
	//	}
	//}
	result := make(map[string]interface{})
	result["code"] = 0
	result["icon"] = "1"
	result["count"] = 0
	//result["data"] = []*file.GlobalAccount{}
	var resultUserList file.GlobalAccountSort
	count := 0
	sort.Sort(user.GlobalUserList)
	for _, v := range user.GlobalUserList {
		if len(username) > 0 {
			if v.Username != username {
				continue
			}
		}
		if state != 0 {
			if v.IsDel != state {
				continue
			}
		}
		count++
		resultUserList = append(resultUserList, v)
	}

	result["count"] = count
	end := start + limit
	if end > count {
		end = count
	}
	if start >= count {
		start = count
	}
	result["data"] = resultUserList[start:end]
	s.Data["json"] = result
	s.ServeJSON()
	s.StopRun()
}

// 用户数据同步
func (s *UserController) SyncUser() {
	var userInfo file.GlobalAccount
	userInfo.Id = s.GetIntNoErr("id")
	userInfo.Status = s.GetIntNoErr("status")
	userInfo.IsAuth = s.GetIntNoErr("is_auth")
	userInfo.Udp = s.GetIntNoErr("udp")
	userInfo.AutoReset = s.GetIntNoErr("auto_reset")
	userInfo.DeviceWarning = s.GetIntNoErr("device_warning")
	userInfo.TotalFlow = s.GetIntNoErr("total_flow")
	userInfo.DeviceLimit = s.GetIntNoErr("device_limit")
	userInfo.InletFlow = s.GetIntNoErr("inlet_flow")
	userInfo.ExportFlow = s.GetIntNoErr("export_flow")
	userInfo.UsedFlow = s.GetIntNoErr("used_flow")
	userInfo.NowConnCount = s.GetIntNoErr("now_conn_count")
	userInfo.UpdatedAt = s.GetIntNoErr("updated_at")
	userInfo.IsDel = s.GetIntNoErr("is_del")
	userInfo.Username = s.getEscapeString("username")
	userInfo.Password = s.getEscapeString("password")
	userInfo.Remark = s.getEscapeString("remark")
	userInfo.ListenIp = s.getEscapeString("listen_ip")
	userInfo.Mode = s.getEscapeString("mode")
	userInfo.ExpireTime = s.getEscapeString("expire_time")
	if len(userInfo.Username) <= 0 || len(userInfo.Password) <= 0 {
		s.AjaxErr("同步失败,数据错误")
	}
	if userInfo.Id > 0 {
		//代表修改
		var oldInfo *file.GlobalAccount
		for _, account := range user.GlobalUserList {
			if account.Id == userInfo.Id {
				oldInfo = account
			}
		}
		if userInfo.Username != oldInfo.Username {
			//修改了用户名
			for _, account := range user.GlobalUserList {
				if account.Username == userInfo.Username {
					s.AjaxErr("更新失败,用户名已经存在")
				}
			}
		}
		userInfo.Flow = oldInfo.Flow
		for k, account := range user.GlobalUserList {
			if account.Id == userInfo.Id {
				user.GlobalUserList[k] = &userInfo
			}
		}
	} else {
		//代表新增
		for _, account := range user.GlobalUserList {
			if account.Username == userInfo.Username {
				s.AjaxErr("添加失败,用户名已经存在")
			}
		}
		userInfo.Id = len(user.GlobalUserList) + 1
		userInfo.Flow = new(file.Flow)
		user.GlobalUserList = append(user.GlobalUserList, &userInfo)
		//if v.MultiAccount != nil {
		//	if _, ok := v.MultiAccount.AccountMap[userInfo.Username]; ok {
		//
		//	} else {
		//
		//	}
		//	v.MultiAccount.AccountMap[userInfo.Username] = &userInfo
		//} else {
		//	userInfo.Flow = new(file.Flow)
		//	userInfo.Id = 1
		//	v.MultiAccount = new(file.MultiAccount)
		//	v.MultiAccount.AccountMap = make(map[string]*file.GlobalAccount)
		//	v.MultiAccount.AccountMap[userInfo.Username] = &userInfo
		//}
	}
	s.AjaxOk("add success")
}

// 用户数据删除
func (s *UserController) DelUser() {
	username := s.getEscapeString("username")
	if len(username) <= 0 {
		s.AjaxErr("删除失败,数据错误")
	}
	//用户数据删除到所有的端口中
	for _, account := range user.GlobalUserList {
		if account.Username == username {
			account.IsDel = 2
		}
	}
	//taskType := "socks5"
	//clientId := 0
	//list, _ := server.GetTunnel(0, 10000, taskType, clientId, "")
	//for _, v := range list {
	//	if v.MultiAccount != nil {
	//		if value, ok := v.MultiAccount.AccountMap[username]; ok {
	//			value.IsDel = 2
	//			v.MultiAccount.AccountMap[username] = value
	//		} else {
	//			s.AjaxErr("删除失败,用户不存在")
	//		}
	//	}
	//}
	s.AjaxOk("delete success")
}

// 用户状态改变
func (s *UserController) UpdateStatus() {
	username := s.getEscapeString("username")
	status := s.GetIntNoErr("status")
	if len(username) <= 0 {
		s.AjaxErr("更新失败,数据错误")
	}
	//用户数据删除到所有的端口中
	for _, account := range user.GlobalUserList {
		if account.Username == username {
			account.Status = status
		}
	}
	//taskType := "socks5"
	//clientId := 0
	//list, _ := server.GetTunnel(0, 10000, taskType, clientId, "")
	//for _, v := range list {
	//	if v.MultiAccount != nil {
	//		if value, ok := v.MultiAccount.AccountMap[username]; ok {
	//			value.Status = status
	//			v.MultiAccount.AccountMap[username] = value
	//		} else {
	//			s.AjaxErr("更新失败,用户不存在")
	//		}
	//	}
	//}
	s.AjaxOk("update success")
}

// 获取单个用户
func (s *UserController) Query() {
	username := s.getEscapeString("username")
	if len(username) <= 0 {
		s.AjaxErr("更新失败,数据错误")
	}
	//用户数据删除到所有的端口中
	var userInfo *file.GlobalAccount
	for _, account := range user.GlobalUserList {
		if account.Username == username {
			userInfo = account
		}
	}
	result := make(map[string]interface{})
	result["status"] = 1
	result["msg"] = "获取成功"
	result["data"] = userInfo
	s.Data["json"] = result
	s.ServeJSON()
	s.StopRun()
}

// 用户套餐兑换
func (s *UserController) Buy() {
	username := s.getEscapeString("username")
	totalFlow := s.GetIntNoErr("total_flow")
	expireTime := s.getEscapeString("expire_time")
	if len(username) <= 0 {
		s.AjaxErr("兑换失败,数据错误")
	}
	//用户数据删除到所有的端口中
	var userInfo *file.GlobalAccount
	for k, account := range user.GlobalUserList {
		if account.Username == username {
			userInfo = account
			userInfo.TotalFlow = totalFlow
			if len(expireTime) > 0 {
				userInfo.ExpireTime = expireTime
			}
			user.GlobalUserList[k] = userInfo
		}
	}
	if len(userInfo.Username) <= 0 {
		s.AjaxErr("兑换失败,用户不存在")
	}
	result := make(map[string]interface{})
	result["status"] = 1
	result["msg"] = "兑换成功"
	s.Data["json"] = result
	s.ServeJSON()
	s.StopRun()
}
