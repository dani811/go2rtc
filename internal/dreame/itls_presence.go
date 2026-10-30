package dreame

// itls_presence.go — PRESENCIA de la app en el canal 飞燕/itls de Aliyun.
// Portado de signalprobe tras resolver HABLAR. Es una de las TRES claves de la receta:
// sin presencia itls viva en paralelo, el robot ni se une al stream del /talk.
// Credencial reconstruida y VERIFICADA (2026-10-22) contra public.itls.eu-central-1:1883:
//   username = deviceName&productKey
//   clientId = deviceName&productKey|securemode=2,_v=0.8.0,lan=Android,os=13,signmethod=hmacsha1,ext=1|
//   password = HMAC-SHA1("clientId{dn&pk}deviceName{dn}productKey{pk}", deviceSecret) hex upper
// Tras conectar, publica account/bind (iotToken) para ligar la presencia a la cuenta y se
// suscribe a app/down/# (bind_reply + posible trigger). dn/pk/secret vienen de AepHandle.

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// StartItlsPresence conecta la presencia itls y publica account/bind. Devuelve el cliente
// MQTT vivo (el llamador lo mantiene conectado mientras sirva el stream; Disconnect al cerrar).
func StartItlsPresence(dn, pk, sec, host, iotToken string) (mqtt.Client, error) {
	if host == "" {
		host = "public.itls.eu-central-1.aliyuncs.com:1883"
	}
	base := dn + "&" + pk
	sign := "clientId" + base + "deviceName" + dn + "productKey" + pk
	mac := hmac.New(sha1.New, []byte(sec))
	mac.Write([]byte(sign))
	pass := strings.ToUpper(hex.EncodeToString(mac.Sum(nil)))
	clientID := base + "|securemode=2,_v=0.8.0,lan=Android,os=13,signmethod=hmacsha1,ext=1|"
	PresenceClientID = base

	opts := mqtt.NewClientOptions()
	opts.AddBroker("ssl://" + host)
	opts.SetClientID(clientID)
	opts.SetUsername(base)
	opts.SetPassword(pass)
	opts.SetTLSConfig(&tls.Config{InsecureSkipVerify: true, ServerName: strings.Split(host, ":")[0]})
	opts.SetConnectTimeout(15 * time.Second)
	opts.SetKeepAlive(60 * time.Second)
	opts.SetAutoReconnect(true)
	c := mqtt.NewClient(opts)
	t := c.Connect()
	if !t.WaitTimeout(20*time.Second) || t.Error() != nil {
		return nil, fmt.Errorf("itls connect: %v", t.Error())
	}
	log.Info().Msg("[dreame] itls: presencia conectada")

	downTopic := "/sys/" + pk + "/" + dn + "/app/down/#"
	if tk := c.Subscribe(downTopic, 0, func(_ mqtt.Client, m mqtt.Message) {
		log.Debug().Msgf("[dreame] itls ← %s : %s", m.Topic(), trunc(m.Payload(), 300))
	}); tk.WaitTimeout(8*time.Second) && tk.Error() == nil {
		log.Debug().Msgf("[dreame] itls suscrito a %s", downTopic)
	}

	bindTopic := "/sys/" + pk + "/" + dn + "/app/up/account/bind"
	// [FIX bind 2026-10-26, RE del SDK público Aliyun public-channel-mobile:1.5.1.3]
	// Envelope REAL de MqttPublishRequest: {id, system{version,time}, request{clientId}, params}.
	// Para account/bind: params = {iotToken} SOLO; request.clientId = dn&pk. (El 460 "some param
	// is blank" era por meter iotToken en request con params vacío; el server valida params.iotToken.)
	body, _ := json.Marshal(map[string]any{
		"id":      "1",
		"system":  map[string]any{"version": "1.0", "time": fmt.Sprint(time.Now().UnixMilli())},
		"request": map[string]any{"clientId": base},
		"params":  map[string]any{"iotToken": iotToken},
	})
	if tk := c.Publish(bindTopic, 0, false, body); tk.WaitTimeout(8*time.Second) && tk.Error() == nil {
		log.Info().Msg("[dreame] itls → account/bind publicado (iotToken)")
	} else {
		log.Warn().Msgf("[dreame] itls bind publish err: %v", tk.Error())
	}
	return c, nil
}
