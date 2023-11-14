package user

import (
	"encoding/json"
	"path/filepath"

	"ehang.io/nps/lib/common"

	"ehang.io/nps/lib/file"
)

var GlobalUserList file.GlobalAccountSort

func InitUserList() {
	path := filepath.Join(common.GetRunPath(), "conf", "user.json")
	fromFile, err := common.ReadAllFromFile(path)
	if err != nil {
		panic("初始化用户数据失败,json文件获取失败,err=" + err.Error())
	}
	if len(fromFile) > 0 {
		err = json.Unmarshal(fromFile, &GlobalUserList)
		if err != nil {
			panic("初始化用户数据失败,json文件解析错误,err=" + err.Error())
		}
	}
}
