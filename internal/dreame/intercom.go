package dreame

import (
	"sync/atomic"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/pcm"
	"github.com/pion/rtp"
)

// Backchannel (intercom / talk-back) del source dreame://.
//
// Modelo go2rtc estándar (igual que pkg/tapo): el productor anuncia una pista de
// audio **sendonly** y, cuando HA abre el micrófono, el router de streams le llama
// AddTrack con el *core.Receiver del micro. Nosotros abrimos el canal de voz del
// robot (IntercomStart → URL RTMP de publish a /talk) y empujamos ahí el audio
// como **G.711a 8 kHz mono**.
//
// [PROVEN] señalización (IntercomStart, apiVer 2.0.3). [OPEN] validación del media
// contra el robot vivo: requiere OK del propietario + credenciales al día. El push
// va por ffmpeg (misma decisión que la ingesta de vídeo: ffmpeg acierta el framing
// FLV/RTMP del relay LinkVisual, que el cliente nativo mal-parsea).
//
// Trazabilidad: todo el camino de audio está logueado bajo el módulo "dreame"
// (apertura del micro, codec, apertura del canal, arranque de ffmpeg, stderr de
// ffmpeg, marcas de uso cada 5 s con paquetes/bytes empujados, y cierre con el
// total). Secretos redactados (ver log.go). Sube el nivel con `log: { dreame: debug }`.

// backchannelMedia: lo que anunciamos a HA. PCMA (alaw) 8 kHz mono.
var backchannelMedia = &core.Media{
	Kind:      core.KindAudio,
	Direction: core.DirectionSendonly,
	Codecs: []*core.Codec{
		{Name: core.CodecPCMA, ClockRate: 8000, Channels: 1, PayloadType: 8},
	},
}

// GetMedias añade el backchannel a las pistas de vídeo/audio del productor de vídeo.
func (p *producer) GetMedias() []*core.Media {
	ms := p.Producer.GetMedias()
	out := make([]*core.Media, 0, len(ms)+1)
	out = append(out, ms...)
	out = append(out, backchannelMedia)
	return out
}

// AddTrack conecta el micrófono entrante de HA al canal de voz del robot. El router
// de streams lo invoca para la media sendonly (ver internal/streams/add_consumer.go).
func (p *producer) AddTrack(media *core.Media, _ *core.Codec, track *core.Receiver) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info().Msgf("[dreame] intercom: micrófono HA abierto codec=%s/%d", track.Codec.Name, track.Codec.ClockRate)

	// Abre el canal de voz una sola vez (primer micrófono que se enchufa).
	if !p.talkOn {
		// [PROVEN 2026-10-19] Activar el modo intercom en el robot con need_record_sound,
		// en la MISMA sesión que sirve el stream (el robot solo admite una sesión a la
		// vez). Sin esto el relay da TalkReady pero el robot no entra al canal; con esto
		// el robot anuncia "llamadas habilitadas" y reproduce nuestro audio (verificado
		// por el oído del dueño). Ver StartIntercom en stream.go (need_record_sound:true).
		if err := p.s.StartIntercom(p.rb, p.gw.Region, p.sess, 500); err != nil {
			log.Warn().Err(err).Msg("[dreame] intercom: StartIntercom (operType:intercom) falló")
		}
		pushURL, iv, key, err := IntercomStart(p.tok, p.rb.IotID, p.gw)
		if err != nil {
			log.Error().Err(err).Msg("[dreame] intercom/start falló")
			return err
		}
		log.Info().Msgf("[dreame] intercom: canal de voz abierto push=%s cifrado=%t", redactURL(pushURL), key != "")
		if err = p.startTalk(pushURL, iv, key); err != nil {
			log.Error().Err(err).Msg("[dreame] intercom: no se pudo abrir el canal RTMP")
			return err
		}
		p.talkOn = true
	}

	sender := core.NewSender(media, track.Codec)
	write := func(pkt *rtp.Packet) {
		if p.talkWrite != nil {
			p.talkWrite(processTalk(pkt.Payload))
		}
	}
	// HA suele ofrecer PCMA ya (vía WithResampling); si llega PCM/PCML, transcodifica
	// en Go puro a PCMA 8 kHz (sin ffmpeg). Opus no se soporta aquí (requeriría ffmpeg).
	if track.Codec.Name == core.CodecPCMA {
		sender.Handler = write
	} else {
		log.Debug().Msgf("[dreame] intercom: transcodificando %s→PCMA 8k", track.Codec.Name)
		dst := &core.Codec{Name: core.CodecPCMA, ClockRate: 8000, Channels: 1}
		sender.Handler = pcm.TranscodeHandler(dst, track.Codec, write)
	}
	sender.HandleRTP(track)
	return nil
}

// startTalk abre el canal RTMP a medida (connect+play, réplica del SDK) y monta el
// envío de audio + keepalive + trazabilidad. Sustituye al publish por ffmpeg, que el
// relay rechazaba (ver rtmp_talk.go y docs/intercom-rtmp-protocol.md).
func (p *producer) startTalk(pushURL, iv, key string) error {
	tc, err := DialTalk(pushURL, iv, key)
	if err != nil {
		return err
	}
	log.Debug().Msg("[dreame] intercom: canal RTMP abierto (connect+play)")

	var pkts, bytesN int64
	done := make(chan struct{})
	p.talkWrite = func(b []byte) {
		if err := tc.SendAudio(b); err != nil {
			return
		}
		atomic.AddInt64(&pkts, 1)
		atomic.AddInt64(&bytesN, int64(len(b)))
	}

	// Keepalive: cada 5 s Ping RTMP Y RE-ASENTAR el intercom por MIoT (aiid 2/piid 2).
	// [PROVEN en vivo 2026-10-20] el robot auto-cierra el intercom a los segundos; sin
	// re-asentarlo el canal queda abierto pero el robot deja de RENDERIZAR y el micro cae
	// en el vacio. Re-asentarlo lo mantiene en modo reproducir mientras el micro este abierto.
	go func() {
		kt := time.NewTicker(5 * time.Second)
		defer kt.Stop()
		mid := 600
		for {
			select {
			case <-done:
				return
			case <-kt.C:
				_ = tc.Ping()
				mid++
				if err := p.s.StartIntercom(p.rb, p.gw.Region, p.sess, mid); err != nil {
					log.Warn().Err(err).Msg("[dreame] intercom: re-assert StartIntercom err")
				}
				if mid%3 == 0 {
					if ps, e := p.s.AudioStatusProp(p.rb); e == nil {
						log.Info().Msgf("[dreame] intercom: prop10001.2=%v", ps["data"])
					}
				}
			}
		}
	}()

	// Marca de uso de audio: cada 5 s, cuánto audio hemos empujado al robot.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		var lastP int64
		for {
			select {
			case <-done:
				return
			case <-t.C:
				pp, bb := atomic.LoadInt64(&pkts), atomic.LoadInt64(&bytesN)
				if pp != lastP {
					log.Debug().Msgf("[dreame] intercom: audio→robot pkts=%d bytes=%d", pp, bb)
					lastP = pp
				}
			}
		}
	}()

	p.talkClose = func() {
		close(done)
		_ = tc.Close()
		log.Info().Msgf("[dreame] intercom: canal de voz cerrado (enviados pkts=%d bytes=%d)",
			atomic.LoadInt64(&pkts), atomic.LoadInt64(&bytesN))
	}
	return nil
}
