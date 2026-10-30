package dreame

// register.go — REGISTRO DINÁMICO mobile (免预注册) de la app, replicado.
// Portado de la sonda de laboratorio (signalprobe) tras resolver HABLAR. Fuente: captura
// de memoria (authInfo + sign reales) + fórmula verificada por fuerza bruta + confirmación
// cruzada con PyMammotion cloud_gateway.py (aep_handle -> /app/aepauth/handle).
//
// Endpoint: POST {region}.api-iot.aliyuncs.com/app/aepauth/handle  apiVer 1.0.0  (firma x-ca).
// params: {authInfo:{clientId, sign, deviceSn, timestamp}}
//   sign = HMAC-SHA1(appSecret, "appKey"+appKey+"clientId"+cid+"deviceSn"+sn+"timestamp"+ts) hex MINÚS
//   (= SignUtils.getToSignString: sorted(key+value), excl "sign"; VERIFICADO contra el sign capturado)
// Respuesta: {code:200, data:{deviceSecret, deviceName, productKey}}.
// clientId(8)/deviceSn(32) deterministas por cuenta (estables entre arranques).

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// genHW deriva clientId(8) y deviceSn(32) deterministas de la cuenta (estable entre runs).
func genHW(account string) (clientID, deviceSn string) {
	h := sha1.Sum([]byte("dreame-cam-bridge|" + account))
	full := hex.EncodeToString(h[:]) // 40 hex
	clientID = full[:8]
	h2 := sha1.Sum([]byte(full + "|sn"))
	deviceSn = (hex.EncodeToString(h2[:]) + full)[:32]
	return
}

// aepSign = HMAC-SHA1(appSecret, sorted(key+value) de los params), hex minúsculas (SignUtils).
func aepSign(params map[string]string, appSecret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k != "sign" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(params[k])
	}
	m := hmac.New(sha1.New, []byte(appSecret))
	m.Write([]byte(sb.String()))
	return hex.EncodeToString(m.Sum(nil))
}

// RegisteredClientID: el clientId(8) con el que nos registramos en el aep.
var RegisteredClientID string

// PresenceClientID = dn&pk, la identidad REAL de la presencia itls en el cable.
var PresenceClientID string

// AepHandle registra el cliente mobile y devuelve el triple fresco (deviceSecret/deviceName/productKey).
func AepHandle(apiEP string, gw GWCreds, iotToken, account string) (dn, pk, sec string, err error) {
	cid, sn := genHW(account)
	RegisteredClientID = cid
	ts := fmt.Sprint(time.Now().UnixMilli())
	signParams := map[string]string{
		"appKey": gw.AppKey, "clientId": cid, "deviceSn": sn, "timestamp": ts,
	}
	sign := aepSign(signParams, gw.AppSecret)
	params := map[string]any{
		"authInfo": map[string]any{
			"clientId": cid, "sign": sign, "deviceSn": sn, "timestamp": ts,
		},
	}
	d, err := gatewayCall(apiEP, "/app/aepauth/handle", "1.0.0", params, iotToken, gw, "HmacSHA1")
	if err != nil {
		return "", "", "", fmt.Errorf("aepauth/handle: %w", err)
	}
	if fmt.Sprint(d["code"]) != "200" {
		return "", "", "", fmt.Errorf("aepauth/handle code=%v msg=%v", d["code"], d["message"])
	}
	data, _ := d["data"].(map[string]any)
	dn, _ = data["deviceName"].(string)
	pk, _ = data["productKey"].(string)
	sec, _ = data["deviceSecret"].(string)
	if sec == "" || dn == "" {
		return "", "", "", fmt.Errorf("aepauth/handle sin deviceSecret/deviceName (data keys: %v)", keysOf(data))
	}
	log.Info().Msgf("[dreame] AEP registro OK deviceName(len=%d) productKey=%s deviceSecret(len=%d)", len(dn), pk, len(sec))
	return dn, pk, sec, nil
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
