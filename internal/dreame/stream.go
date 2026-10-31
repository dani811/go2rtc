package dreame

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const streamQueryPath = "/vision/customer/stream/query"

// Robot: datos del dispositivo extraídos de device/listV2.
type Robot struct {
	DID        string
	IotID      string
	BindDomain string
}

// ExtractRobot busca el L40 (model r2579a) en la respuesta de listV2.
func ExtractRobot(dev map[string]any) (*Robot, error) {
	data, _ := dev["data"].(map[string]any)
	page, _ := data["page"].(map[string]any)
	recs, _ := page["records"].([]any)
	for _, r := range recs {
		rec, _ := r.(map[string]any)
		model, _ := rec["model"].(string)
		if !strings.HasSuffix(model, "r2579a") {
			continue
		}
		rb := &Robot{}
		if did, ok := rec["did"].(string); ok {
			rb.DID = did
		} else if didf, ok := rec["did"].(float64); ok {
			rb.DID = fmt.Sprintf("%.0f", didf)
		}
		if bd, ok := rec["bindDomain"].(string); ok {
			rb.BindDomain = bd
		}
		var prop map[string]any
		if ps, ok := rec["property"].(string); ok {
			json.Unmarshal([]byte(ps), &prop)
		}
		if prop != nil {
			if iid, ok := prop["iotId"].(string); ok {
				rb.IotID = iid
			}
			if rb.BindDomain == "" {
				if bd, ok := prop["bindDomain"].(string); ok {
					rb.BindDomain = bd
				}
			}
		}
		if rb.IotID != "" && rb.BindDomain != "" {
			return rb, nil
		}
	}
	return nil, fmt.Errorf("robot r2579a no encontrado (o sin iotId/bindDomain)")
}

// miotAction manda una acción MIoT (siid 10001) por la nube Dreame.
func (s *Session) miotAction(rb *Robot, aiid, piid int, value string, mid int) (map[string]any, error) {
	prefix := strings.SplitN(rb.BindDomain, ".", 2)[0]
	path := "dreame-iot-com-" + prefix + "/device/sendCommand"
	params := map[string]any{
		"did": rb.DID, "siid": 10001, "aiid": aiid,
		"in": []any{map[string]any{"piid": piid, "value": value}},
	}
	payload := map[string]any{
		"did": rb.DID, "id": mid,
		"data": map[string]any{"did": rb.DID, "id": mid, "method": "action", "params": params},
	}
	return s.APICall(path, payload)
}

// Activate despierta la cámara: verifyAccessCode + startMonitor + un keep_alive.
// Devuelve la session de vídeo usada (hex32).
func (s *Session) Activate(rb *Robot, region, pin string) (string, error) {
	sess := randHex(16)
	oc := sha256.Sum256([]byte(pin))
	oldcode := hex.EncodeToString(oc[:])

	v1, _ := json.Marshal(map[string]any{"oldcode": oldcode, "lazymode": 0, "session": sess})
	if _, err := s.miotAction(rb, 4, 1102, string(v1), 10); err != nil {
		return "", fmt.Errorf("verifyAccessCode: %w", err)
	}
	v2, _ := json.Marshal(map[string]any{
		"token": "alify", "channelId": rb.IotID, "area": region,
		"operType": "monitor", "operation": "start", "session": sess})
	mon, err := s.miotAction(rb, 1, 1, string(v2), 11)
	if err != nil {
		return "", fmt.Errorf("startMonitor: %w", err)
	}
	if c := resultCode(mon); c != 0 {
		return "", fmt.Errorf("startMonitor result code=%v", c)
	}
	s.KeepAlive(rb, sess, 12)
	return sess, nil
}

// StartIntercom le dice al robot por MIoT que active el modo intercom (abrir altavoz
// y suscribirse al canal de voz del relay). Mismo patrón que startMonitor pero
// operType:intercom.
//
// [PROVEN 2026-10-19, por el oído del dueño] La pieza que faltaba es
// **need_record_sound:true**. Sin ese flag, el relay da TalkReady pero el robot NO
// entra al canal (no reproduce). CON el flag, el robot anuncia "llamadas habilitadas"
// y REPRODUCE el audio que enviamos por /talk. El relay NO devuelve Play.Start al
// cliente (por eso el diagnóstico previo lo daba por fallido); el oráculo es el altavoz.
func (s *Session) StartIntercom(rb *Robot, region, sess string, mid int) error {
	// [FIX 2026-10-20, PROVEN en vivo] la app manda el intercom por aiid 2 (VOICE_OPERATE)
	// / piid 2 (PropMonitorAudioStatus), sin token/channelId/area (eso es startMonitor).
	_ = region
	v, _ := json.Marshal(map[string]any{
		"need_record_sound": true, "operType": "intercom",
		"operation": "start", "session": sess})
	_, err := s.miotAction(rb, 2, 2, string(v), mid)
	return err
}

// AudioStatusProp lee el prop 10001.2 (estado del intercom) como la app.
func (s *Session) AudioStatusProp(rb *Robot) (map[string]any, error) {
	return s.APICall("dreame-user-iot/iotstatus/props", map[string]any{"did": rb.DID, "keys": "10001.2"})
}

// KeepAlive manda un keep_alive (llamar cada ~20s mientras haya espectador).
func (s *Session) KeepAlive(rb *Robot, sess string, mid int) error {
	v, _ := json.Marshal(map[string]any{"operType": "keep_alive", "videoStatus": "opened", "session": sess})
	_, err := s.miotAction(rb, 1, 6, string(v), mid)
	return err
}

// QueryStream pide la URL del directo (shouldEncrypt:false -> relay EN CLARO).
func QueryStream(iotToken, iotID string, gw GWCreds) (relayURL string, err error) {
	d, err := gatewayCall(gw.Region+".api-iot.aliyuncs.com", streamQueryPath, "2.2.0",
		map[string]any{"iotId": iotID, "streamType": 1, "scheme": 1, "shouldEncrypt": false},
		iotToken, gw, "HmacSHA1")
	if err != nil {
		return "", err
	}
	if fmt.Sprint(d["code"]) != "200" {
		return "", fmt.Errorf("stream/query code=%v msg=%v", d["code"], d["message"])
	}
	data, _ := d["data"].(map[string]any)
	relayURL, _ = data["relayUrl"].(string)
	if relayURL == "" {
		return "", fmt.Errorf("stream/query sin relayUrl")
	}
	return relayURL, nil
}

// IntercomStart abre el canal de talk-back y devuelve la URL RTMP del /talk y la
// cryptoKey (iv/key base64) con la que hay que CIFRAR el audio.
//
// [PROVEN 2026-10-17, captura tcpdump] El 20004 anterior era por apiVer: la correcta
// es 2.0.3. La respuesta trae data.url = rtmp://<host>:8000/talk?token=<T>&session=
// <S>/<KEY> y data.cryptoKey{iv,key}. **El audio SIEMPRE va cifrado** AES-128-CBC con
// esa clave, aun con encryptType:0 (la app captura lo confirma: frames de 656 bytes
// -múltiplo de 16-, idénticos y de alta entropía = cifrado de silencio). El robot ya
// debe estar en modo monitor. El transporte es play, no publish (ver rtmp_talk.go).
func IntercomStart(iotToken, iotID string, gw GWCreds) (pushURL, ivB64, keyB64 string, err error) {
	d, err := gatewayCall(gw.Region+".api-iot.aliyuncs.com", "/vision/customer/voice/intercom/start", "2.0.3",
		map[string]any{"iotId": iotID, "enablePrePlay": false, "encryptType": 0},
		iotToken, gw, "HmacSHA1")
	if err != nil {
		return "", "", "", err
	}
	if fmt.Sprint(d["code"]) != "200" {
		return "", "", "", fmt.Errorf("intercom/start code=%v msg=%v", d["code"], d["message"])
	}
	data, _ := d["data"].(map[string]any)
	pushURL, _ = data["url"].(string)
	if pushURL == "" {
		return "", "", "", fmt.Errorf("intercom/start sin url")
	}
	if ck, ok := data["cryptoKey"].(map[string]any); ok {
		ivB64, _ = ck["iv"].(string)
		keyB64, _ = ck["key"].(string)
	}
	return pushURL, ivB64, keyB64, nil
}

func resultCode(resp map[string]any) int {
	if d, ok := resp["data"].(map[string]any); ok {
		if r, ok := d["result"].(map[string]any); ok {
			if c, ok := r["code"].(float64); ok {
				return int(c)
			}
		}
	}
	return 0
}

func randHex(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> (i % 8))
	}
	// mezcla simple; suficiente para un session id de uso efímero
	h := sha256.Sum256(append(b, byte(time.Now().UnixNano())))
	return hex.EncodeToString(h[:n])
}
