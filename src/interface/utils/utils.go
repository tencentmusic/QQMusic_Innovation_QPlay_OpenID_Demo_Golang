package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	MISERVER_ERR_BAD_PARAMS = 400
	MISERVER_ERR_INTERNAL   = 500
	MISERVER_ERR_RESULT_NIL = 500
)

const (
	MISERVER_PIECE_STATUS_VALID     = 0x0  //正常
	MISERVER_PIECE_STATUS_REMOVED   = 0x01 //本地文件被删（文件所在分区在线，但文件不在）
	MISERVER_PIECE_STATUS_TIMEOUT   = 0x02 //本地文件所在分区掉线，超过一定时间认为文件丢失
	MISERVER_PIECE_STATUS_OWNERDEL  = 0x04 //被owner拥有者标记为需要删除
	MISERVER_PIECE_STATUS_NOTIFYDEL = 0x08 //已通知storer删除
)

type RespHeader struct {
	Errno  int    `json:"errno"`
	Errmsg string `json:"errmsg"`
}

func DoHttpResponseJson(w *http.ResponseWriter, data interface{}) {
	body, err := json.Marshal(data)
	if err != nil {
		fmt.Errorf("marshal response data fail, err:%v\n", err.Error())
		return
	}

	(*w).Write(body)
}

func DoHttpResponseBytes(w *http.ResponseWriter, data []byte) {
	(*w).Write(data)
}
