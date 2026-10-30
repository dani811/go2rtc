package dreame

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
)

const bootstrapHost = "cn-shanghai.api-iot.aliyuncs.com"

// --- Firma del API Gateway de Aliyun IoT (x-ca), port de signing.py ---

const (
	gwAccept      = "application/json; charset=utf-8"
	gwContentType = "application/octet-stream; charset=utf-8"
	gwSignHeaders = "x-ca-nonce,x-ca-timestamp,x-ca-key,x-ca-signature-method"
)

func httpDate() string { return time.Now().UTC().Format(http.TimeFormat) }

func gatewaySign(method, pathWithQuery string, body []byte, appKey, appSecret, sigMethod string) map[string]string {
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	nonce := uuid.NewString()
	date := httpDate()
	cmd5sum := md5.Sum(body)
	contentMD5 := base64.StdEncoding.EncodeToString(cmd5sum[:])
	sts := method + "\n" + gwAccept + "\n" + contentMD5 + "\n" + gwContentType + "\n" + date + "\n" +
		"x-ca-key:" + appKey + "\n" +
		"x-ca-nonce:" + nonce + "\n" +
		"x-ca-signature-method:" + sigMethod + "\n" +
		"x-ca-timestamp:" + ts + "\n" +
		pathWithQuery
	var h func() hash.Hash
	if sigMethod == "HmacSHA256" {
		h = sha256.New
	} else {
		h = sha1.New
	}
	mac := hmac.New(h, []byte(appSecret))
	mac.Write([]byte(sts))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return map[string]string{
		"accept": gwAccept, "content-type": gwContentType, "content-md5": contentMD5,
		"date": date, "ca_version": "1", "x-ca-key": appKey, "x-ca-nonce": nonce,
		"x-ca-timestamp": ts, "x-ca-signature-method": sigMethod,
		"x-ca-signature-headers": gwSignHeaders, "x-ca-signature": sig,
	}
}

// Creds del gateway (appKey/appSecret/region) — se pasan desde la config.
type GWCreds struct{ AppKey, AppSecret, Region string }

// gatewayCall hace una llamada "envelope" al IoT API Gateway (region/get,
// createSessionByAuthCode, stream/query). sigMethod: HmacSHA1 por defecto.
func gatewayCall(host, path, apiVer string, params map[string]any, iotToken string, gw GWCreds, sigMethod string) (map[string]any, error) {
	req := map[string]any{"apiVer": apiVer, "language": "es-ES"}
	if iotToken != "" {
		req["iotToken"] = iotToken
	}
	envelope := map[string]any{
		"id": uuid.NewString(), "version": "1.0", "params": params, "request": req,
	}
	body, _ := json.Marshal(envelope)
	headers := gatewaySign("POST", path, body, gw.AppKey, gw.AppSecret, sigMethod)
	r, _ := http.NewRequest("POST", "https://"+host+path, bytes.NewReader(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	raw, status, err := doHTTP(r)
	if err != nil {
		return nil, err
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("%s HTTP %d: %s", path, status, trunc(raw, 200))
	}
	return d, nil
}

// --- Firma OpenAccount (connect.json / loginbyoauth.json), HmacSHA256 ---

func oaBody(body map[string]any, wire bool) string {
	// Orden de inserción no determinista en Go; OA no exige orden alfabético,
	// pero para estabilidad firmamos y enviamos EL MISMO string.
	var parts []string
	for k, v := range body {
		enc, _ := json.Marshal(v)
		s := string(enc)
		if wire {
			s = url.QueryEscape(s)
		}
		parts = append(parts, k+"="+s)
	}
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "&"
		}
		out += p
	}
	return out
}

func oaCall(host, path string, body map[string]any, extra map[string]string, gw GWCreds) (map[string]any, error) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := uuid.NewString()
	date := httpDate()
	// firmamos y enviamos el MISMO orden de pares (construimos una sola vez)
	var kv [][2]string
	for k, v := range body {
		enc, _ := json.Marshal(v)
		kv = append(kv, [2]string{k, string(enc)})
	}
	signBody := ""
	wireBody := ""
	for i, p := range kv {
		if i > 0 {
			signBody += "&"
			wireBody += "&"
		}
		signBody += p[0] + "=" + p[1]
		wireBody += p[0] + "=" + url.QueryEscape(p[1])
	}
	sts := "POST\napplication/json\n\napplication/x-www-form-urlencoded\n" + date + "\n" +
		"x-ca-key:" + gw.AppKey + "\nx-ca-nonce:" + nonce + "\nx-ca-signature-method:HmacSHA256\n" +
		"x-ca-timestamp:" + ts + "\n" + path + "?" + signBody
	mac := hmac.New(sha256.New, []byte(gw.AppSecret))
	mac.Write([]byte(sts))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	r, _ := http.NewRequest("POST", "https://"+host+path, bytes.NewReader([]byte(wireBody)))
	r.Header.Set("accept", "application/json")
	r.Header.Set("content-type", "application/x-www-form-urlencoded")
	r.Header.Set("date", date)
	r.Header.Set("x-ca-key", gw.AppKey)
	r.Header.Set("x-ca-nonce", nonce)
	r.Header.Set("x-ca-signature", sig)
	r.Header.Set("x-ca-signature-headers", gwSignHeaders)
	r.Header.Set("x-ca-signature-method", "HmacSHA256")
	r.Header.Set("x-ca-timestamp", ts)
	for k, v := range extra {
		r.Header.Set(k, v)
	}
	raw, status, err := doHTTP(r)
	if err != nil {
		return nil, err
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("%s HTTP %d: %s", path, status, trunc(raw, 200))
	}
	return d, nil
}

// RegionGet valida la firma del gateway (primer paso del handshake).
func RegionGet(authCode string, gw GWCreds, sigMethod string) (map[string]any, error) {
	d, err := gatewayCall(bootstrapHost, "/living/account/region/get", "1.0.2",
		map[string]any{"authCode": authCode, "type": "THIRD_AUTHCODE"}, "", gw, sigMethod)
	if err != nil {
		return nil, err
	}
	return d, nil
}

var _ = md5.Sum // keep import if unused later

// Exchange hace el handshake OA completo: authCode -> (iotToken, apiEndpoint).
func Exchange(authCode string, gw GWCreds, oauthPlateform int) (iotToken, apiEndpoint string, err error) {
	reg, err := RegionGet(authCode, gw, "HmacSHA1")
	if err != nil {
		return "", "", err
	}
	data, _ := reg["data"].(map[string]any)
	oaEP, _ := data["oaApiGatewayEndpoint"].(string)
	apiEP, _ := data["apiGatewayEndpoint"].(string)
	if oaEP == "" || apiEP == "" {
		return "", "", fmt.Errorf("region/get sin endpoints")
	}

	// 2) connect.json -> vid
	conn, err := oaCall(oaEP, "/api/prd/connect.json", map[string]any{
		"request": map[string]any{
			"context": map[string]any{"appKey": gw.AppKey},
			"config":  map[string]any{"version": 0, "lastModify": 0},
			"device":  map[string]any{},
		}}, nil, gw)
	if err != nil {
		return "", "", fmt.Errorf("connect.json: %w", err)
	}
	cd, _ := conn["data"].(map[string]any)
	vid, _ := cd["vid"].(string)
	if vid == "" {
		return "", "", fmt.Errorf("connect.json sin vid: %v", trunc([]byte(fmt.Sprint(conn)), 150))
	}

	// 3) loginbyoauth.json -> sid (header vid)
	login, err := oaCall(oaEP, "/api/prd/loginbyoauth.json", map[string]any{
		"loginByOauthRequest": map[string]any{
			"authCode": authCode, "oauthPlateform": oauthPlateform,
			"oauthAppKey": gw.AppKey, "riskControlInfo": map[string]any{},
		}}, map[string]string{"vid": vid}, gw)
	if err != nil {
		return "", "", fmt.Errorf("loginbyoauth: %w", err)
	}
	sid := findSid(login)
	if sid == "" {
		return "", "", fmt.Errorf("loginbyoauth sin sid: %v", trunc([]byte(fmt.Sprint(login)), 200))
	}

	// 4) createSessionByAuthCode -> iotToken
	sess, err := gatewayCall(apiEP, "/account/createSessionByAuthCode", "1.0.4",
		map[string]any{"request": map[string]any{"authCode": sid, "accountType": "OA_SESSION", "appKey": gw.AppKey}},
		"", gw, "HmacSHA1")
	if err != nil {
		return "", "", fmt.Errorf("createSession: %w", err)
	}
	sd, _ := sess["data"].(map[string]any)
	iotToken, _ = sd["iotToken"].(string)
	if iotToken == "" {
		return "", "", fmt.Errorf("createSession sin iotToken: %v", trunc([]byte(fmt.Sprint(sess)), 150))
	}
	return iotToken, apiEP, nil
}

func findSid(m map[string]any) string { return findKey(m, "sid") }

// findKey busca recursivamente la primera string no vacía bajo `key`.
func findKey(v any, key string) string {
	switch t := v.(type) {
	case map[string]any:
		if s, ok := t[key].(string); ok && s != "" {
			return s
		}
		for _, vv := range t {
			if s := findKey(vv, key); s != "" {
				return s
			}
		}
	case []any:
		for _, vv := range t {
			if s := findKey(vv, key); s != "" {
				return s
			}
		}
	}
	return ""
}

// GatewayCallExported expone gatewayCall para sondas (stream/query con params libres).
func GatewayCallExported(host, path, apiVer string, params map[string]any, iotToken string, gw GWCreds) (map[string]any, error) {
	return gatewayCall(host, path, apiVer, params, iotToken, gw, "HmacSHA1")
}
