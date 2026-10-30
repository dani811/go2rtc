package dreame

// Backchannel (intercom / talk-back) del source dreame://, con la RECETA GANADORA de
// HABLAR (resuelto 2026-10-28, confirmado por oído — docs/HABLAR-RESUELTO-2026-10-28.md).
//
// Modelo go2rtc estándar (igual que pkg/tapo): el productor anuncia una pista de audio
// **sendonly PCMA 8 kHz** y, cuando HA abre el micrófono, el router de streams llama a
// AddTrack. Entonces abrimos el canal de voz del robot con la secuencia completa:
//
//	intercom/start (HTTP voice/intercom/start 2.0.3, reintentos ante 9201)
//	  → DialTalk (/talk: connect → play → Ping.Start → config)
//	  → StartIntercom (MIoT startVoice aiid2/piid2, need_record_sound)
//	  → ESPERAR NetStream.Data.Start (el robot se une al stream)
//	  → REENVIAR config (72 00 80 00) ya unido el robot
//	  → audio A-law 16 kHz (640 B/40 ms) + ping/config/startVoice re-asentados
//
// Prerrequisitos que monta source.go: presencia itls viva + vídeo /live transmitiendo
// (el productor ffmpeg ya está tirando del relay cuando HA abre el micro).
//
// El micro de HA entra como PCMA **8 kHz** (G.711a fijado a 8 kHz en WebRTC); lo subimos
// a A-law **16 kHz** (upsampleAlaw8to16) antes de empujarlo, porque el robot reproduce a
// 16 kHz (confirmado de oído 2026-10-29). Trazabilidad bajo el módulo "dreame".

import (
	"sync/atomic"
	"time"

	"github.com/AlexxIT/go2rtc/pkg/core"
	"github.com/AlexxIT/go2rtc/pkg/pcm"
	"github.com/pion/rtp"
)

// backchannelMedia: lo que anunciamos a HA. PCMA (alaw) 8 kHz mono (estándar WebRTC).
var backchannelMedia = &core.Media{
	Kind:      core.KindAudio,
	Direction: core.DirectionSendonly,
	Codecs: []*core.Codec{
		{Name: core.CodecPCMA, ClockRate: 8000, Channels: 1, PayloadType: 8},
	},
}

// GetMedias añade el backchannel a las pistas del productor de vídeo.
func (p *producer) GetMedias() []*core.Media {
	ms := p.Producer.GetMedias()
	out := make([]*core.Media, 0, len(ms)+1)
	out = append(out, ms...)
	out = append(out, backchannelMedia)
	return out
}

// AddTrack conecta el micrófono entrante de HA al canal de voz del robot.
func (p *producer) AddTrack(media *core.Media, _ *core.Codec, track *core.Receiver) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info().Msgf("[dreame] intercom: micrófono HA abierto codec=%s/%d", track.Codec.Name, track.Codec.ClockRate)

	// Abre el canal de voz una sola vez (primer micrófono que se enchufa).
	if !p.talkOn {
		if err := p.openTalk(); err != nil {
			log.Error().Err(err).Msg("[dreame] intercom: no se pudo abrir el canal de voz")
			return err
		}
		p.talkOn = true
	}

	sender := core.NewSender(media, track.Codec)
	// 8 kHz (HA) → 16 kHz (robot) y empuje al /talk.
	write16 := func(alaw8 []byte) {
		if p.talkWrite != nil {
			p.talkWrite(upsampleAlaw8to16(alaw8))
		}
	}
	if track.Codec.Name == core.CodecPCMA {
		sender.Handler = func(pkt *rtp.Packet) { write16(pkt.Payload) }
	} else {
		// HA manda PCM/PCML/Opus: transcodifica a PCMA 8 kHz en Go (pkg/pcm) y luego sube a 16 kHz.
		log.Debug().Msgf("[dreame] intercom: transcodificando %s→PCMA 8k→16k", track.Codec.Name)
		dst := &core.Codec{Name: core.CodecPCMA, ClockRate: 8000, Channels: 1}
		sender.Handler = pcm.TranscodeHandler(dst, track.Codec, func(pkt *rtp.Packet) { write16(pkt.Payload) })
	}
	sender.HandleRTP(track)
	return nil
}

// openTalk abre el canal de voz con la receta ganadora y monta el envío + keepalive.
// Asume p.mu tomado por el llamador (AddTrack).
func (p *producer) openTalk() error {
	// 1) intercom/start (HTTP), con reintentos ante 9201 (robot aún no listo).
	var pushURL, iv, key string
	var err error
	for att := 0; att < 10; att++ {
		pushURL, iv, key, err = IntercomStart(p.tok, p.rb.IotID, p.gw)
		if err == nil && pushURL != "" {
			break
		}
		_ = p.s.KeepAlive(p.rb, p.sess, 260+att)
		time.Sleep(2 * time.Second)
	}
	if pushURL == "" {
		return err
	}
	log.Info().Msgf("[dreame] intercom: canal de voz abierto push=%s cifrado=%t", redactURL(pushURL), key != "")

	// 2) /talk: connect → play → Ping.Start → config inicial.
	tc, err := DialTalk(pushURL, iv, key)
	if err != nil {
		return err
	}

	// 3) MIoT startVoice (need_record_sound) en la MISMA sesión del monitor.
	if e := p.s.StartIntercom(p.rb, p.gw.Region, p.sess, 400); e != nil {
		log.Warn().Err(e).Msg("[dreame] intercom: StartIntercom (startVoice) falló")
	}

	// 4) esperar Data.Start (el robot se une) y 5) REENVIAR el config ya unido.
	joined := tc.WaitDataStart(8 * time.Second)
	_ = tc.sendAudioConfig()
	log.Info().Msgf("[dreame] intercom: canal /talk listo (Data.Start=%t, config reenviado tras join)", joined)

	var pkts, bytesN int64
	done := make(chan struct{})
	p.talkWrite = func(b []byte) {
		if e := tc.SendAudio(b); e != nil {
			return
		}
		atomic.AddInt64(&pkts, 1)
		atomic.AddInt64(&bytesN, int64(len(b)))
	}

	// Keepalive: cada 2 s Ping + REENVÍO de config + re-asiento del intercom (el robot
	// auto-cierra el modo intercom a los pocos segundos; re-asentarlo lo mantiene
	// reproduciendo mientras el micro esté abierto). mid incremental.
	go func() {
		kt := time.NewTicker(2 * time.Second)
		defer kt.Stop()
		mid := 500
		tick := 0
		for {
			select {
			case <-done:
				return
			case <-kt.C:
				tick++
				_ = tc.Ping()
				_ = tc.sendAudioConfig()
				if tick%2 == 0 { // ~cada 4 s
					mid++
					_ = p.s.StartIntercom(p.rb, p.gw.Region, p.sess, mid)
				}
				if pp := atomic.LoadInt64(&pkts); pp > 0 && tick%5 == 0 {
					log.Debug().Msgf("[dreame] intercom: audio→robot pkts=%d bytes=%d", pp, atomic.LoadInt64(&bytesN))
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
