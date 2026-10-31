// Package dreame implementa el protocolo de nube Dreame + LinkVisual para el
// directo del robot (login -> iotToken -> activacion MIoT -> stream/query ->
// relayUrl RTMP en claro). Port fiel de tools/linkvisual/ (Python, [PROVEN]).
package dreame

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	port        = 13267
	hostSuffix  = ".iot.dreame.tech"
	loginPath   = "/dreame-auth/oauth/token"
	salt        = "RAylYC%fmSKp7%Tq"
	clientBasic = "Basic ZHJlYW1lX2FwcHYxOkFQXmR2QHpAU1FZVnhOODg="
	cid         = "EETjszu*XI5znHsI"
	vid         = "102060300"
	userAgent   = "Dart/3.9 (dart:io)"
)

// Session es el resultado del login (capa 1 Dreame).
type Session struct {
	AccessToken string
	UID         string
	TenantID    string
	Host        string // {region}.iot.dreame.tech:PORT
}

func md5hex(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }

func meta(username string) string {
	r := make([]byte, 16)
	rand.Read(r)
	c := md5hex([]byte(username + "c"))[:8]
	w := md5hex([]byte(username + "w"))[:8]
	return fmt.Sprintf("cv=a_%s;canvasHash=%s;webglHash=%s;visitorIdHash=%s", vid, c, w, md5hex(r))
}

func doHTTP(req *http.Request) ([]byte, int, error) {
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.Header.Get("content-encoding") == "gzip" {
		if zr, e := gzip.NewReader(bytes.NewReader(raw)); e == nil {
			if d, e2 := io.ReadAll(zr); e2 == nil {
				raw = d
			}
		}
	}
	return raw, res.StatusCode, nil
}

// Login hace el login Dreame (md5(password+SALT), Basic, form) -> access_token.
func Login(username, password, regionPrefix string) (*Session, error) {
	host := fmt.Sprintf("%s%s:%d", regionPrefix, hostSuffix, port)
	pw := md5hex([]byte(password + salt))
	body := strings.NewReader(
		"grant_type=password&scope=all&platform=ANDROID&type=account" +
			"&username=" + url.QueryEscape(username) + "&password=" + pw)
	req, _ := http.NewRequest("POST", "https://"+host+loginPath, body)
	req.Header.Set("user-agent", userAgent)
	req.Header.Set("dreame-meta", meta(username))
	req.Header.Set("accept-encoding", "gzip")
	req.Header.Set("tenant-id", "000000")
	req.Header.Set("authorization", clientBasic)
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	raw, status, err := doHTTP(req)
	if err != nil {
		return nil, err
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("login HTTP %d: %s", status, trunc(raw, 200))
	}
	tok, _ := d["access_token"].(string)
	if tok == "" {
		return nil, fmt.Errorf("login sin access_token (HTTP %d): %s", status, trunc(raw, 200))
	}
	s := &Session{AccessToken: tok, Host: host, TenantID: "000000"}
	if v, ok := d["uid"].(string); ok {
		s.UID = v
	}
	if v, ok := d["tenant_id"].(string); ok && v != "" {
		s.TenantID = v
	}
	return s, nil
}

// signed firma el body como Tasshack: sign = md5(spliced(params)+ms+CID).
func signed(params map[string]any) map[string]any {
	ms := time.Now().UnixMilli()
	base := spliced(params, true) + strconv.FormatInt(ms, 10) + cid
	out := make(map[string]any, len(params)+2)
	for k, v := range params {
		out[k] = v
	}
	out["sign"] = md5hex([]byte(base))
	out["timestamp"] = ms
	return out
}

// spliced replica el serializado ordenado de Tasshack para la firma (ver Python).
func spliced(obj map[string]any, top bool) string {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		switch v := obj[k].(type) {
		case map[string]any:
			inner := spliced(v, false)
			if inner != "" {
				parts = append(parts, k+"=["+inner+"]")
			} else {
				parts = append(parts, k+"=]")
			}
		case []any:
			if top {
				b, _ := json.Marshal(v) // Go ordena claves de mapas; compacto
				parts = append(parts, k+"="+string(b))
			}
		case bool:
			if v {
				parts = append(parts, k+"=true")
			} else {
				parts = append(parts, k+"=false")
			}
		case nil:
			parts = append(parts, k+"=null")
		default:
			if top {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			} else {
				b, _ := json.Marshal(v)
				parts = append(parts, k+"="+string(b))
			}
		}
	}
	return strings.Join(parts, "&")
}

// APICall hace una llamada autenticada a la nube Dreame (dreame-auth + body firmado).
func (s *Session) APICall(path string, params map[string]any) (map[string]any, error) {
	if params == nil {
		params = map[string]any{}
	}
	bodyBytes, _ := json.Marshal(signed(params))
	req, _ := http.NewRequest("POST", "https://"+s.Host+"/"+path, bytes.NewReader(bodyBytes))
	req.Header.Set("user-agent", userAgent)
	req.Header.Set("dreame-meta", meta(s.UID))
	req.Header.Set("accept-encoding", "gzip")
	req.Header.Set("tenant-id", s.TenantID)
	req.Header.Set("authorization", clientBasic)
	req.Header.Set("content-type", "application/json")
	req.Header.Set("dreame-auth", s.AccessToken)
	raw, status, err := doHTTP(req)
	if err != nil {
		return nil, err
	}
	var d map[string]any
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("apiCall %s HTTP %d: %s", path, status, trunc(raw, 200))
	}
	return d, nil
}

func trunc(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
