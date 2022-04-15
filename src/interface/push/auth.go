package auth

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
)

const (
	MISERVER_ERR_BAD_PARAMS = 400
	MISERVER_ERR_INTERNAL   = 500
	MISERVER_ERR_RESULT_NIL = 500
)

type RespHeader struct {
	Errno  int    `json:"errno"`
	Errmsg string `json:"errmsg"`
}

type AuthImpl struct {
}

type tomlConfig struct {
	OpenID_AppID   		string
	OpenID_PackageName  string
	OpenID_PrivateKey  	string
	OpenAPI_AppID 		string
	OpenAPI_AppKey 		string
	OpenAPI_AppPrivateKey	string
}

//QQ音乐公钥
var QQMusicPublicKey1_1 = []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrp4sMcJjY9hb2J3sHWlwIEBrJ
lw2Cimv+rZAQmR8V3EI+0PUK14pL8OcG7CY79li30IHwYGWwUapADKA01nKgNeq7
+rSciMYZv6ByVq+ocxKY8az78HwIppwxKWpQ+ziqYavvfE5+iHIzAc8RvGj9lL6x
x1zhoPkdaA0agAyuMQIDAQAB
-----END PUBLIC KEY-----
`)

var g_EncryptMap map[string]string = make(map[string]string)

type EncryptRequest struct {
	EncryptString string `json:"encryptString"`
}
type reqEncryptContent struct {
	Nonce      string `json:"nonce"` //加密种子
	Sign       string `json:"sign"`  //签名
	OpenId     string `json:"openId"`
	OpenToken  string `json:"openToken"`
	ExpireTime int64  `json:"expireTime"`
}

type QrCodeResponse = struct {
	Code         int    `json:"ret"`
	msg          string `json:"msg"`
	QRCodeString string `json:"sdk_qr_code"`
	Sub_ret      int    `json:"sub_ret"`
}

func (impl *AuthImpl) AuthInfoSet(w http.ResponseWriter, r *http.Request) {
	result := struct {
		RespHeader
	}{}
	result.Errno = 0
	result.Errmsg = "success"

	defer func() {
		data, err := json.Marshal(result)
		if err != nil {
			fmt.Errorf("marshal result fail[%v]\n", err.Error())
			return
		}
		w.Write(data)
	}()

	err := r.ParseForm()
	if err != nil {
		fmt.Errorf("parse form fail:%v\n", err.Error())
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "parse form fail"
		return
	}
	fmt.Printf("request method[%s]\n", r.Method)
	clientid := r.FormValue("clientid")
	if len(clientid) == 0 {
		fmt.Errorf("clientid is nil\n")
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "clientid is nil"
		return
	}
	ret, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()
	fmt.Printf("authinfoset json:%s\n", ret)
	postForm := &EncryptRequest{}
	err = json.Unmarshal(ret, &postForm)
	if err != nil {
		fmt.Errorf("json unmarshal occur err[%v]\n", err.Error())
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "unmarsha1 fail"
		return
	}

	encryptStr := postForm.EncryptString
	if len(encryptStr) == 0 {
		fmt.Errorf("post encryptString is nil\n")
		result.Errno = MISERVER_ERR_BAD_PARAMS
		result.Errmsg = "post encryptString is nil\n"
		return
	}
	g_EncryptMap[clientid] = encryptStr
	fmt.Printf("post encryptString success\n")
}

func (impl *AuthImpl) AuthInfoGet(w http.ResponseWriter, r *http.Request) {
	result := struct {
		RespHeader
		OpenId    string `json:"openId"`
		OpenToken string `json:"openToken"`
	}{}
	result.Errno = 0
	result.Errmsg = "success"

	defer func() {
		data, err := json.Marshal(result)
		if err != nil {
			fmt.Errorf("marshal response fail[%v]\n", err.Error())
			return
		}
		w.Write(data)
	}()
	err := r.ParseForm()
	if err != nil {
		fmt.Errorf("parse form fail:%v\n", err.Error())
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "parse form fail"
		return
	}
	fmt.Printf("request method[%s]\n", r.Method)
	clientid := r.FormValue("clientid")
	if len(clientid) == 0 {
		fmt.Errorf("clientid is nil\n")
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "clientid is nil"
		return
	}
	encryptStr, ok := g_EncryptMap[clientid]
	if !ok {
		fmt.Errorf("clientid is nil\n")
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "encryptString is nil"
		return
	}

	var config tomlConfig
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		fmt.Println(err)
		return
	}
	decryptJson, err := decryptWithPrivateKey(encryptStr, config.OpenID_PrivateKey)
	if err != nil {
		fmt.Printf("decrypt fail:[%s]\n", err.Error())
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "decrypt fail"
		return
	}

	fmt.Printf("decrypt success:[%s]\n", decryptJson)
	encryptParam := reqEncryptContent{}
	err = json.Unmarshal([]byte(decryptJson), &encryptParam)
	if err != nil {
		fmt.Errorf("parse json error:[%s]\n", err.Error())
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "parse json fail"
		return
	}
	if len(encryptParam.Nonce) == 0 || len(encryptParam.Sign) == 0 {
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "Nonce or Sign is nil"
		return
	}

	err = rsaVerySignWithSha256(encryptParam.Nonce, encryptParam.Sign, QQMusicPublicKey1_1)
	if err != nil {
		fmt.Errorf("verify App signature fail[%s]\n", err.Error())
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "verify sign failed"
		return
	}

	if len(encryptParam.OpenId) == 0 || len(encryptParam.OpenToken) == 0 {
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "openId or openToken is nil"
		return
	}
	result.OpenId = encryptParam.OpenId
	result.OpenToken = encryptParam.OpenToken
	fmt.Printf("get openId[%s] openToken[%s] success\n", result.OpenId, result.OpenToken)

}

func (impl *AuthImpl) GetQrcodeString(w http.ResponseWriter, r *http.Request) {
	result := struct {
		RespHeader
		QrCode string `json:"qrcode"`
	}{}
	result.Errno = 0
	result.Errmsg = "success"

	defer func() {
		data, err := json.Marshal(result)
		if err != nil {
			fmt.Errorf("marshal response fail[%v]\n", err.Error())
			return
		}
		w.Write(data)
	}()

	err := r.ParseForm()
	if err != nil {
		fmt.Errorf("ParseForm fail[%v]\n", err.Error())
		result.Errno = -1
		result.Errmsg = "failed"
		return
	}

	//生成加密串
	timestamp := time.Now().Unix()
	nonce := strconv.FormatInt(timestamp, 10)
	var config tomlConfig
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		fmt.Println(err)
		return
	}
	appSign, err := rsaSignWithSha256(nonce, []byte(config.OpenID_PrivateKey))
	callbackUrl := fmt.Sprintf("http://%s/qm/auth/set?clientid=%s", r.Host, r.FormValue("clientid"))

	encryptMap := make(map[string]interface{})
	encryptMap["nonce"] = nonce
	encryptMap["sign"] = appSign
	encryptMap["callbackUrl"] = callbackUrl
	resultJson, err := json.Marshal(encryptMap)
	encryptString, err := encryptWithPublicKey(string(resultJson), string(QQMusicPublicKey1_1))
	encryptString = url.QueryEscape(encryptString)
	//访问OpenAPI获取二维码字符串
	opiSource := "OpitrtqeGzopIlwxs_" + config.OpenAPI_AppID + "_" + config.OpenAPI_AppKey + "_" + config.OpenAPI_AppPrivateKey + "_" + nonce
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(opiSource))
	opiSign := hex.EncodeToString(md5Ctx.Sum(nil))//cd.y.qq.com/ext-internal   openrpc.music.qq.com/rpc_proxy
	qrcodeUrl := fmt.Sprintf("http://openrpc.music.qq.com/rpc_proxy/fcgi-bin/music_open_api.fcg?opi_cmd=fcg_music_custom_sdk_get_qr_code.fcg&sign=%s&app_id=%s&timestamp=%s&app_key=%s&qqmusic_open_appid=%s&qqmusic_package_name=%s&qqmusic_dev_name=%s&qqmusic_encrypt_auth=%s", opiSign, config.OpenAPI_AppID, nonce, config.OpenAPI_AppKey, config.OpenID_AppID, config.OpenID_PackageName, "Web", encryptString)
	req, err := http.NewRequest("GET", qrcodeUrl, nil)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	rspContent := string(body)
	fmt.Println("response Body:", rspContent)

	serverRsp := QrCodeResponse{}

	err = json.Unmarshal([]byte(rspContent), &serverRsp)
	if err != nil {
		fmt.Errorf("parse rso json error:[%s]\n", err.Error())
		result.Errno = MISERVER_ERR_INTERNAL
		result.Errmsg = "parse json fail"
		return
	}

	result.QrCode = "failed"
	if serverRsp.Code == 0 && serverRsp.Sub_ret == 0 {
		result.QrCode = serverRsp.QRCodeString
	}
}
