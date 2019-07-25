// +build linux

package secureoverlay2

import (
	"bytes"
//	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
        //"github.com/Sirupsen/logrus"
        //"github.com/sirupsen/logrus"
)

const (
	AIKPATH = "/opt/trustagent/configuration/aik.pem"
	KMSPROXY = "http://10.242.131.202:8080"
)

func getKeyTrsUrlfromKMSforEncryption() (string) {
        cmd := "lkp  createKeyForEncryption"
        cmdResponse, err := exec.Command("/bin/bash", "-c", cmd).Output()
	logger.Debugf("getKeyTrsUrlfromKMSforEncryption: inside lkp out is => : %s", cmdResponse)
        if err != nil {
                return ""
        }
	var data lkpResponse
        newerr := json.Unmarshal(cmdResponse, &data)
        if newerr != nil {
                return ""
        }
	logger.Debugf("getKeyTrsUrlfromKMSforEncryption: ganesh transfer url is: %s", data.KeyTrsUrl)

        return data.KeyTrsUrl
}

func getKeyfromKMSforEncryption() (string, string, string, error) {
        cmd := "lkp  createKeyForEncryption"
        cmdResponse, err := exec.Command("/bin/bash", "-c", cmd).Output()
	logger.Debugf("getKeyfromKMSforEncryption: inside lkp out is => : %s", cmdResponse)
        if err != nil {
                return "", "", "", err
        }
	var data lkpResponse
        newerr := json.Unmarshal(cmdResponse, &data)
        if newerr != nil {
                return "", "", "", fmt.Errorf("Invalid Data returned by lkp command error : %s", newerr)
        }

        //Key, keytrnsurl, _ := unwrapKmsKey(data)
        return data.Auth, data.Prikey, data.KeyTrsUrl, nil
}

func getKeyfromKMSforDecryption(kmsHandle string) (string, string, error) {
        //aikbyte, erAik := getHostAikKey()
        aikstring, erAik := getHostAikKey()
	if erAik != nil {
        	logger.Debugf("getKeyfromKMSforDecryption: Error getting Key err: %s", erAik)
		return "XYZ123", "",  nil
	}
	kmsconfArray := strings.Split(aikstring, "#")
	if len(kmsconfArray) == 2 {
        	logger.Debugf("getKeyfromKMSforDecryption: Aaganya received auth: %s priKey : %s", kmsconfArray[0], kmsconfArray[1])
        	out, _ := getWrappedKeyFromKms(kmsconfArray[0], kmsHandle)
        	key, _ := decodeWrappedKey(out, kmsconfArray[1])
		return key, "", nil
	}
	//body := strings.NewReader(string(aikbyte))
	body := strings.NewReader(aikstring)
	request, _ := http.NewRequest("POST", kmsHandle, body)
	request.Header.Set("Accept", "application/x-pem-file")
        request.Header.Set("Content-Type", "application/x-pem-file")
        proxyUrl, er := url.Parse(KMSPROXY)
        if er != nil {
                return "", "", er
	}
	tr := &http.Transport{
                Proxy:           http.ProxyURL(proxyUrl),
//              TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        }
        client := &http.Client{Transport: tr}
        response, err := client.Do(request)
        if err != nil {
                return "", "", err
        }
        data, err1 := ioutil.ReadAll(response.Body)
        if err1 != nil {
                return "", "", err1
        }
        return string(data), "",  nil
}

func getWrappedKeyFromKms(auth, trsurl string) (string, error) {
        logger.Debugf("getWrappedKeyFromKms: received token: %s, trnsUrl: %s", auth, trsurl)
	var buffer bytes.Buffer
	request, _ := http.NewRequest("POST", trsurl, bytes.NewBuffer(nil))
	request.Header.Set("Accept", "application/json")
	buffer.WriteString("Token ")
	buffer.WriteString(auth)

	request.Header.Set("Authorization", buffer.String())
	tr := &http.Transport{
//		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}

	data, err1 := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", err1
	}
	buf := map[string]interface{}{}
	er := json.Unmarshal(data, &buf)
	if er != nil {
		return "", er
	}

	logger.Debugf("getWrappedKeyFromKms: sending wrapped key: %s ", buf["key"].(string))

        return buf["key"].(string), nil
}

func decodeWrappedKey(wrappedkey, prikeypath string) (string, error) {
        logger.Debugf("decodeWrappedKey: received wrapped key: %s prikey path: %s ", wrappedkey, prikeypath)
        return "XYZ123", nil
}

func getKMSKeyonDev(kmsconf lkpResponse) (string, string, error) {
        logger.Debugf("getKMSKeyonDev: received token: %s, prikey: %s, trnsUrl: %s", kmsconf.Auth, kmsconf.Prikey, kmsconf.KeyTrsUrl)
        out, _ := getWrappedKeyFromKms(kmsconf.Auth, kmsconf.KeyTrsUrl)
        key, _ := decodeWrappedKey(out, kmsconf.Prikey)

        return key, kmsconf.KeyTrsUrl, nil
}


func getHostAikKey() (string, error) {
	if _, err := os.Stat(AIKPATH); os.IsNotExist(err) {
  		logger.Debugf("AIK does not exists for this host, checking if its a developer machine: %s", err)
		cmd := "lkp getKmsConfig"
		cmdResponse, newerr := exec.Command("/bin/bash", "-c", cmd).Output()
        	if newerr != nil {
  			logger.Debugf("Its not a developer machine and AIK also does not exists for this host err: %s ", err)
                	return "", err
        	} 
  		logger.Debugf("This is a developer machine sending KMS conf for getting key %s ", cmdResponse)
		var data lkpResponse
        	unmarsherr := json.Unmarshal(cmdResponse, &data)
        	if unmarsherr != nil {
			return "", unmarsherr
		}
		newstr := data.Auth + "#" + data.Prikey
		return  newstr, nil
	}
        logger.Debugf("getHostAikKey: reading key from: %s ", AIKPATH)
	aik, _ := ioutil.ReadFile(AIKPATH)
	return string(aik), nil
}
