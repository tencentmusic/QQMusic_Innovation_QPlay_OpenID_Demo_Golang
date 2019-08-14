package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"

	"github.com/wenzhenxi/gorsa"
)

//公钥加密
func encryptWithPublicKey(originalString, publicKey string) (string, error) {
	return gorsa.PublicEncrypt(originalString, publicKey)
}

//私钥解密
func decryptWithPrivateKey(encryptString, privateKey string) (string, error) {
	return gorsa.PriKeyDecrypt(encryptString, privateKey)
}

//使用公钥验证签名
func rsaVerySignWithSha256(originalData, signData string, pubKey []byte) error {
	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(pubKey)
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	hash := sha256.New()
	hash.Write([]byte(originalData))
	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hash.Sum(nil), sign)
}

//签名：采用sha256算法进行签名（私钥PKCS8格式）
func rsaSignWithSha256(data string, priKey []byte) (string, error) {
	block, _ := pem.Decode(priKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("ParsePKCS8PrivateKey err", err)
		return "", err
	}
	h := sha256.New()
	h.Write([]byte([]byte(data)))
	hash := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA256, hash[:])
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		return "", err
	}
	out := base64.StdEncoding.EncodeToString(signature)
	return out, nil
}

/*
生成公私钥，并以字符串形式返回
返回：私钥、公钥、Error
*/
func generateRSAKeyString() (string, string, error) {

	privateKeyBytes, publicKeyBytes, err := generateRSAKeyByte()
	if err != nil {
		return "", "", err
	}
	privateKeyString := string(privateKeyBytes)
	publicKeyString := string(publicKeyBytes)
	return privateKeyString, publicKeyString, nil
}

/*
生成公私钥，并以byte形式返回
返回：私钥、公钥、Error
*/
func generateRSAKeyByte() ([]byte, []byte, error) {
	privateKey, publicKey, err := generateRSAKey()
	if err != nil {
		return nil, nil, err
	}
	privateKeyBytes := marshalPKCS8PrivateKey(privateKey) //PKCS1->PKCS8
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}

	//私钥pem编码
	privateBlock := &pem.Block{
		Type:  "PRIVATE KEY", //按照惯例PKCS8->PRIVATE KEY  PKCS1->RSA PRIVATE KEY
		Bytes: privateKeyBytes,
	}
	privatePem := pem.EncodeToMemory(privateBlock)

	//公钥pem编码
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY", //按照惯例PKCS8->PRIVATE KEY  PKCS1->RSA PRIVATE KEY
		Bytes: publicKeyBytes,
	}
	publicPem := pem.EncodeToMemory(publicBlock)

	return privatePem, publicPem, nil
}

/*
生成公私钥，并以byte形式返回
返回：私钥、公钥、Error
*/
func generateRSAKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

//将PKCS1私钥转换为PKCS8密钥
func marshalPKCS8PrivateKey(key *rsa.PrivateKey) []byte {
	info := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{}
	info.Version = 0
	info.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	info.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	info.PrivateKey = x509.MarshalPKCS1PrivateKey(key)

	k, err := asn1.Marshal(info)
	if err != nil {
		log.Panic(err.Error())
	}
	return k
}
