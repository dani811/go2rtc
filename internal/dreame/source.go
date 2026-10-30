package dreame

import (
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/AlexxIT/go2rtc/internal/app"
	"github.com/AlexxIT/go2rtc/internal/streams"
	"github.com/AlexxIT/go2rtc/pkg/core"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// Init registra el source nativo. URL:
//
//	dreame://<region>?user=<u>&pass=<p>&pin=<pin>&appkey=<k>&appsecret=<s>&iotregion=<r>
//
// (user/pass/appsecret url-encoded). <region> (host) = prefijo Dreame, p.ej. eu.
func Init() {
	log = app.GetLogger("dreame")
	streams.HandleFunc("dreame", func(source string) (core.Producer, error) {
		return dial(source)
	})
}

func dial(source string) (core.Producer, error) {
	u, err := url.Parse(source)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	region := u.Host
	if region == "" {
		region = "eu"
	}
	user, pass, pin := q.Get("user"), q.Get("pass"), q.Get("pin")
	gw := GWCreds{AppKey: q.Get("appkey"), AppSecret: q.Get("appsecret"), Region: q.Get("iotregion")}
	if gw.Region == "" {
		gw.Region = "eu-central-1"
	}
	if user == "" || pass == "" || gw.AppKey == "" || gw.AppSecret == "" {
		return nil, errors.New("dreame: faltan user/pass/appkey/appsecret")
	}

	s, err := Login(user, pass, region)
	if err != nil {
		return nil, err
	}
	ac, err := s.APICall("dreame-smarthome/aliIot/getAuthCodeV3", nil)
	if err != nil {
		return nil, err
	}
	code, _ := ac["data"].(string)
	dev, err := s.APICall("dreame-user-iot/iotuserbind/device/listV2", nil)
	if err != nil {
		return nil, err
	}
	rb, err := ExtractRobot(dev)
	if err != nil {
		return nil, err
	}
	log.Info().Msgf("[dreame] robot r2579a iotId=%s region=%s", redactID(rb.IotID), gw.Region)
	tok, _, err := Exchange(code, gw, 23)
	if err != nil {
		return nil, err
	}
	sess, err := s.Activate(rb, gw.Region, pin)
	if err != nil {
		log.Error().Err(err).Msg("[dreame] activación de cámara falló")
		return nil, err
	}
	log.Debug().Msg("[dreame] cámara activada (modo monitor)")

	// [HABLAR 2026-10-28] PRESENCIA itls en paralelo — una de las tres claves para que el
	// robot se una al /talk. Registro AEP dinámico (triple dn/pk/secret) → conexión itls
	// MQTT → account/bind(iotToken). Si falla, seguimos con el vídeo (OÍR no la necesita);
	// solo HABLAR se degradaría. Cliente guardado en el producer para desconectar al cerrar.
	var itls mqtt.Client
	apiEP := gw.Region + ".api-iot.aliyuncs.com"
	itlsHost := "public.itls." + gw.Region + ".aliyuncs.com:1883"
	if dn, pk, sec, e := AepHandle(apiEP, gw, tok, user); e != nil {
		log.Warn().Err(e).Msg("[dreame] presencia itls: AEP falló (HABLAR puede no unir al robot)")
	} else if itls, e = StartItlsPresence(dn, pk, sec, itlsHost, tok); e != nil {
		log.Warn().Err(e).Msg("[dreame] presencia itls: conexión falló (HABLAR puede no unir al robot)")
		itls = nil
	}

	var relay string
	for i := 0; i < 10; i++ {
		if relay, err = QueryStream(tok, rb.IotID, gw); err == nil && relay != "" {
			log.Info().Msgf("[dreame] relay listo %s (intentos=%d)", redactURL(relay), i+1)
			break
		}
		log.Trace().Msgf("[dreame] stream/query aún no listo (intento=%d): %v", i+1, err)
		s.KeepAlive(rb, sess, 20+i)
		time.Sleep(4 * time.Second)
	}
	if relay == "" {
		if itls != nil {
			itls.Disconnect(250)
		}
		return nil, errors.New("dreame: sin relayUrl tras activar (9201)")
	}

	// Ingesta vía ffmpeg. Audio del robot → Opus (WebRTC no transporta AAC) para que HA OIGA.
	prod, err := streams.GetProducer("ffmpeg:" + relay + "#video=copy#audio=opus")
	if err != nil {
		if itls != nil {
			itls.Disconnect(250)
		}
		return nil, err
	}

	// keep-alive mientras viva el productor; s/rb/gw/tok/sess se guardan para el backchannel
	// (intercom.go), que se activa de forma perezosa en AddTrack cuando HA abre el micrófono.
	p := &producer{Producer: prod, stop: make(chan struct{}), s: s, rb: rb, gw: gw, tok: tok, sess: sess, itls: itls}
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		mid := 100
		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				mid++
				_ = s.KeepAlive(rb, sess, mid)
			}
		}
	}()
	return p, nil
}

// producer envuelve el productor de vídeo (ffmpeg) para (a) parar el keep-alive y la
// presencia itls al cerrar y (b) añadir el backchannel de intercom (audio hacia el robot).
// Satisface core.Producer (vídeo, vía embedding) y core.Consumer (GetMedias + AddTrack).
type producer struct {
	core.Producer
	stop chan struct{}
	done bool

	s    *Session
	rb   *Robot
	gw   GWCreds
	tok  string
	sess string
	itls mqtt.Client // presencia itls viva (nil si falló); se desconecta en Stop

	mu        sync.Mutex
	talkOn    bool
	talkWrite func([]byte) // empuja alaw al publish RTMP del /talk
	talkClose func()       // cierra el canal /talk
}

func (p *producer) Stop() error {
	p.mu.Lock()
	if p.talkClose != nil {
		p.talkClose()
		p.talkClose = nil
		p.talkOn = false
	}
	p.mu.Unlock()
	if !p.done {
		p.done = true
		close(p.stop)
		if p.itls != nil {
			p.itls.Disconnect(250)
		}
	}
	return p.Producer.Stop()
}
