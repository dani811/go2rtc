package dreame

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// talkFrame: bytes de alaw por frame de audio (~80 ms a 8 kHz). [PROVEN por descifrado]
// El frame plano = cabecera FLV alaw (0x72 0x01) + talkFrame bytes de alaw, luego
// padding PKCS7 y AES-128-CBC. El primer frame es un "config" = 0x72 0x00 0x80 0x00.
const talkFrame = 640

// TalkRateHz = sample-rate del A-law que espera el robot en /talk. [2026-10-28] La app
// oficial sube a 16000 Hz (640 B/40 ms, medido en pcap real); durante meses asumimos
// 8000 Hz (comentario erróneo del código) y el robot no renderizaba. Quien produce el
// A-law (talk2, go2rtc) debe generarlo a ESTE rate y marcar los frames en consecuencia.
var TalkRateHz = 16000

// Cliente RTMP mínimo a medida para el talk-back del Dreame L40.
//
// [PROVEN 2026-10-17, captura tcpdump] El relay LinkVisual NO acepta un publish
// RTMP estándar: espera que el cliente haga **play** (no publish) y envíe el audio
// como mensajes tipo 8. Réplica exacta de la secuencia del SDK (ver
// docs/intercom-rtmp-protocol.md):
//
//	handshake simple (C0C1, sin C2)
//	connect{app, tcUrl, fpad:false, capabilities:15, audioCodecs:3191, videoCodecs:252, videoFunction:1}
//	play(streamName=<KEY>) sobre msid 1, SIN createStream
//	audio = mensajes RTMP tipo 8 (alaw crudo G.711a) sobre msid 1, csid 4
//	keepalive: el cliente envía onStatus{code:NetStream.Ping.Start}
//	deleteStream al cerrar
//
// Esto sustituye al publish por ffmpeg (que hacía publish y el relay reseteaba).

// [PROVEN por captura + prueba en vivo] El SDK envía cada mensaje RTMP en UN SOLO
// chunk (connect 335 B y audio 656 B sin partir) y no anuncia Set Chunk Size; el relay
// asume chunks grandes. Partir a 128 intercala bytes de continuación que corrompen
// el ciphertext del audio (falla el PKCS7) y el relay cierra la conexión (broken pipe
// tras ~5 frames). Por eso no se trocea: chunk ≥ cualquier mensaje.
const talkChunkSize = 65536

type talkConn struct {
	conn net.Conn
	mu   sync.Mutex

	host   string
	app    string // "talk?token=...&session=..."
	stream string // <KEY>

	audioTS float64 // timestamp acumulado en ms (alaw 8 kHz: len/8 ms por frame)
	txn     int     // transaction id incremental para onStatus/deleteStream
	closed  bool

	block cipher.Block // AES-128 de la cryptoKey
	iv    []byte       // iv fijo (se reinicia por frame)
	abuf  []byte       // acumulador de alaw hasta completar talkFrame

	playStarted chan struct{} // se cierra al recibir NetStream.Play.Start del robot
	playOnce    sync.Once

	dataStarted chan struct{} // se cierra al recibir NetStream.Data.Start (el robot SE UNE)
	dataOnce    sync.Once
}

// DialTalk abre el canal de voz: TCP + handshake + connect + play. La pushURL es la
// que devuelve IntercomStart. ivB64/keyB64 son la cryptoKey (AES-128-CBC) con la que
// se cifra el audio; si vienen vacías, se envía en claro (fallback de diagnóstico).
func DialTalk(pushURL, ivB64, keyB64 string) (*talkConn, error) {
	host, app, stream, err := parseTalkURL(pushURL)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", host, 8*time.Second)
	if err != nil {
		return nil, err
	}
	t := &talkConn{conn: conn, host: host, app: app, stream: stream, txn: 2,
		playStarted: make(chan struct{}), dataStarted: make(chan struct{})}
	if keyB64 != "" && ivB64 != "" {
		key, e1 := base64.StdEncoding.DecodeString(keyB64)
		iv, e2 := base64.StdEncoding.DecodeString(ivB64)
		if e1 == nil && e2 == nil && len(iv) == aes.BlockSize {
			if blk, e3 := aes.NewCipher(key); e3 == nil {
				t.block = blk
				t.iv = iv
			}
		}
		if t.block == nil {
			log.Warn().Msg("[dreame] intercom: cryptoKey inválida, audio en claro")
		}
	}

	if err = t.handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	// Drenar DESDE YA todo lo que mande el servidor (S2 + window ack + _result), para
	// no bloquear el socket mientras pipelinamos connect/play/audio (como el SDK).
	go t.drain()
	tcURL := "rtmp://" + host + "/" + app
	if err = t.sendConnect(app, tcURL); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connect: %w", err)
	}
	// [HABLAR RESUELTO 2026-10-28, confirmado por oído — docs/HABLAR-RESUELTO-2026-10-28.md]
	// La secuencia que hace sonar el robot es connect → play → Ping.Start → config, SIN
	// NetStream.PreConnect NI NetStream.RequestAudioType: la captura del móvil real de la
	// app oficial NO los manda (eran un falso positivo del RE estático, retractado). Tampoco
	// hay pause/Listen (la app no manda Unpause). Lo que faltaba de verdad no estaba aquí en
	// el /talk (ya era byte-correcto) sino en el ORQUESTADOR: presencia itls + vídeo /live
	// transmitiendo primero + MIoT startVoice + esperar Data.Start + REENVIAR el config
	// (72 00 80 00) DESPUÉS del join. Eso lo monta el llamador (source.go/intercom.go).
	if err = t.sendPlay(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("play: %w", err)
	}
	// [PROVEN por captura] El SDK envía onStatus NetStream.Ping.Start (txn 3) JUSTO
	// tras el play y ANTES del primer audio: es la señal de arranque, no solo keepalive.
	// Sin ella el relay cierra la conexión ~0,5 s después de empezar el audio.
	if err = t.Ping(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ping start: %w", err)
	}
	// Frame de config de audio (72 00 80 00), como el SDK, antes de los datos.
	if err = t.sendAudioConfig(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("audio config: %w", err)
	}
	return t, nil
}

// parseTalkURL separa host:port, app (talk?query) y stream (<KEY>, último segmento).
func parseTalkURL(raw string) (host, app, stream string, err error) {
	u, e := url.Parse(raw)
	if e != nil {
		return "", "", "", e
	}
	host = u.Host
	if !strings.Contains(host, ":") {
		host += ":1935"
	}
	// path = /talk ; query lleva token/session y, tras el último '/', la KEY.
	appPath := strings.TrimPrefix(u.Path, "/") // "talk"
	q := u.RawQuery
	key := ""
	if i := strings.LastIndexByte(q, '/'); i >= 0 {
		key = q[i+1:]
		q = q[:i]
	}
	app = appPath
	if q != "" {
		app += "?" + q
	}
	if key == "" {
		return "", "", "", fmt.Errorf("talk url sin KEY: %s", redactURL(raw))
	}
	return host, app, key, nil
}

func (t *talkConn) handshake() error {
	// [PROVEN por captura del SDK] Solo se envía C0(0x04) + C1(ts 0 + zero + aleatorios).
	// El SDK NO envía un C2 de 1536 bytes y pipelinea connect/play justo detrás; el
	// servidor responde con S0S1 + S2 + _result, que consume el drenaje de fondo. Enviar
	// un C2 estándar hace que el servidor cierre (FIN). Las respuestas se leen en drain.
	c0c1 := make([]byte, 1+1536)
	c0c1[0] = 0x04
	_, _ = rand.Read(c0c1[9:]) // C1[0:4]=ts, C1[4:8]=zero, C1[8:]=aleatorio
	_, err := t.conn.Write(c0c1)
	return err
}

// TalkTrace, si está definido, recibe cada bloque de bytes que manda el servidor
// (diagnóstico: ver los onStatus/_error con los que el relay explica un cierre).
var TalkTrace func(b []byte)

// TalkDownlinkRaw: si no es nil, recibe TODO byte entrante crudo (sin filtrar por
// palabras clave), con un best-effort de descifrado AES-CBC usando la MISMA
// (block, iv) con la que ciframos nuestro audio saliente. [2026-10-28] Hallazgo del
// pcap de la app oficial (talkcap.yml, run 40666661266): el relay manda ~400KB en
// 10s por el mismo socket /talk durante un intercom real -- alta entropía, nunca
// analizado porque TalkTrace descarta en silencio cualquier chunk sin esas palabras
// clave. Esto da visibilidad total + un intento de descifrado inmediato la próxima
// vez que se repita la prueba en vivo. El recorte a múltiplo de 16 y el iv fijo son
// un PRIMER TANTEO (no sabemos aún si respeta los límites reales de mensaje RTMP).
var TalkDownlinkRaw func(seq int, n int, raw []byte, decryptAttempt []byte)

// drain consume lo que mande el servidor (evita bloqueos TCP) y lo pasa a TalkTrace.
func (t *talkConn) drain() {
	b := make([]byte, 4096)
	seq := 0
	for {
		n, err := t.conn.Read(b)
		if n > 0 {
			seq++
			if TalkTrace != nil {
				TalkTrace(b[:n])
			}
			if bytes.Contains(b[:n], []byte("Play.Start")) {
				t.playOnce.Do(func() { close(t.playStarted) })
			}
			if bytes.Contains(b[:n], []byte("Data.Start")) {
				t.dataOnce.Do(func() { close(t.dataStarted) })
			}
			if TalkDownlinkRaw != nil {
				raw := append([]byte(nil), b[:n]...)
				var dec []byte
				if t.block != nil && len(raw) >= aes.BlockSize {
					aligned := raw[:len(raw)-(len(raw)%aes.BlockSize)]
					if len(aligned) > 0 {
						dec = make([]byte, len(aligned))
						func() {
							defer func() { recover() }() // CBC puede paniquear si iv/len no cuadran
							cipher.NewCBCDecrypter(t.block, t.iv).CryptBlocks(dec, aligned)
						}()
					}
				}
				TalkDownlinkRaw(seq, n, raw, dec)
			}
		}
		if err != nil {
			return
		}
	}
}

func (t *talkConn) sendConnect(app, tcURL string) error {
	body := amfString("connect")
	body = append(body, amfNumber(1)...) // txn 1
	obj := amfObjStart()
	obj = amfObjProp(obj, "app", amfString(app))
	obj = amfObjProp(obj, "tcUrl", amfString(tcURL))
	obj = amfObjProp(obj, "fpad", amfBool(false))
	obj = amfObjProp(obj, "capabilities", amfNumber(15))
	obj = amfObjProp(obj, "audioCodecs", amfNumber(3191))
	obj = amfObjProp(obj, "videoCodecs", amfNumber(252))
	obj = amfObjProp(obj, "videoFunction", amfNumber(1))
	obj = amfObjEnd(obj)
	body = append(body, obj...)
	return t.writeChunk(3, 20, 0, 0, body) // csid 3, type 20 (AMF0 cmd), msid 0
}

func (t *talkConn) sendPlay() error {
	body := amfString("play")
	body = append(body, amfNumber(float64(t.txn))...) // txn 2
	body = append(body, amfNull()...)
	body = append(body, amfString(t.stream)...)
	body = append(body, amfNumber(-1000)...) // [PROVEN] start=-1000 (directo): sin este
	// argumento el servidor no manda Play.Start y el robot no recibe el audio.
	return t.writeChunk(8, 20, 1, 0, body) // csid 8, type 20, msid 1 (sin createStream)
}

// pkcs7 rellena a múltiplo de bloque AES (como la app; el byte de pad = nº de bytes).
func pkcs7(b []byte) []byte {
	pad := aes.BlockSize - len(b)%aes.BlockSize
	for i := 0; i < pad; i++ {
		b = append(b, byte(pad))
	}
	return b
}

// encFrame cifra un frame plano (ya con su cabecera FLV) en AES-128-CBC + PKCS7.
func (t *talkConn) encFrame(plain []byte) []byte {
	if t.block == nil {
		return plain // fallback sin cifrar (diagnóstico)
	}
	pt := pkcs7(plain)
	enc := make([]byte, len(pt))
	cipher.NewCBCEncrypter(t.block, t.iv).CryptBlocks(enc, pt) // iv fijo por frame
	return enc
}

// sendAudioConfig manda el frame de config inicial (72 00 80 00), como el SDK.
func (t *talkConn) sendAudioConfig() error {
	return t.writeChunk(4, 8, 1, 0, t.encFrame([]byte{0x72, 0x00, 0x80, 0x00}))
}

// SendAudio acumula alaw y, por cada 640 bytes, construye el frame plano
// (0x72 0x01 + alaw), lo cifra y lo envía como mensaje RTMP tipo 8, msid 1.
func (t *talkConn) SendAudio(alaw []byte) error {
	t.mu.Lock()
	t.abuf = append(t.abuf, alaw...)
	var frames [][]byte
	for len(t.abuf) >= talkFrame {
		f := make([]byte, talkFrame)
		copy(f, t.abuf[:talkFrame])
		frames = append(frames, f)
		t.abuf = t.abuf[talkFrame:]
	}
	t.mu.Unlock()

	for _, f := range frames {
		plain := append([]byte{0x72, 0x01}, f...) // cabecera FLV alaw (dato) + alaw
		ts := uint32(t.audioTS)
		// [2026-10-28] CORREGIDO a 16 kHz. La app oficial sube 640 B A-law con
		// timestamp +40 ms por frame (pcap real talkcap-out2: 252 frames en 10 s,
		// delta ts ~40 ms → 640 muestras/40 ms = 16000 Hz). Antes usábamos /8.0
		// (=80 ms, 8 kHz) → cadencia a mitad del ritmo que consume el decodificador
		// del robot → underrun → el robot no renderizaba. TalkRateHz ajustable.
		t.audioTS += float64(talkFrame) * 1000.0 / float64(TalkRateHz)
		if err := t.writeChunk(4, 8, 1, ts, t.encFrame(plain)); err != nil {
			return err
		}
	}
	return nil
}

// sendOnStatus replica IOT_RTMP_SendMessage del SDK (liblv_media.so 0x2332a0), el control
// de arranque del intercom que a nuestro cliente le faltaba. [PROVEN-estático 2026-10-20,
// radare2 pdc de IOT_RTMP_SendMessage + CStreamUnit::rtmp_open 0x209730] El SDK construye un
// AMF0 "onStatus" con un objeto {level:"status", code:<code>, description:"desc"} y añade
// audio_type:"1" SOLO cuando el 4º argumento es ≠0 (el valor literal es siempre "1"; el SDK
// NUNCA manda audio_type:"0" ni audio_type con el flag a 0: omite el campo). Lo envía por
// RTMP_SendPacket sobre el contexto del cliente (cliente→relay), no es una respuesta.
//
// CStreamUnit::rtmp_open lo llama DOS veces en esta secuencia exacta:
//
//	RTMP_Connect
//	IOT_RTMP_SendMessage(ctx, code@0x5e73a8, 0, 0)  → code="NetStream.PreConnect", SIN audio_type
//	RTMP_SendPlay
//	IOT_RTMP_SendMessage(ctx, code@0x5e7310, 0, 1)  → code="NetStream.RequestAudioType", audio_type:"1"
//	RTMP_ConnectStream
//
// Los dos code son std::string globales en .bss (no legibles del fichero), pero los logs
// adyacentes del SDK ("rtmp pre create request." y "request audio type g711a") más los
// únicos NetStream.* que casan (NetStream.PreConnect / NetStream.RequestAudioType, ambos
// presentes como literales en el binario) los fijan con certeza práctica. audio_type:"1" =
// g711a (A-law), justo el códec que empujamos. Es, [INFERRED] con fuerte base, la señal que
// hace al relay pedir al robot que ARRANQUE la reproducción del intercom (hasta ahora el
// relay daba TalkReady pero el robot no reproducía).
// [OPEN] (1) el valor literal "desc" de description y (2) el csid/msid exactos del paquete
// quedan por confirmar; (3) el ConnectStream final no se replica aún. Validación definitiva:
// oído del dueño con el robot (pendiente de su OK, hoy ausente).
func (t *talkConn) sendOnStatus(code string, withAudioType bool) error {
	t.txn++
	body := amfString("onStatus")
	body = append(body, amfNumber(float64(t.txn))...)
	body = append(body, amfNull()...)
	o := amfObjStart()
	o = amfObjProp(o, "level", amfString("status"))
	o = amfObjProp(o, "code", amfString(code))
	o = amfObjProp(o, "description", amfString("desc"))
	if withAudioType {
		o = amfObjProp(o, "audio_type", amfString("1"))
	}
	o = amfObjEnd(o)
	body = append(body, o...)
	return t.writeChunk(4, 20, 1, 0, body) // csid 4, type 20 (AMF0 cmd), msid 1
}

// sendPause replica RTMP_Pause del fork (liblvrtmp.so 0xc37c), el control half-duplex del
// intercom que la app invoca vía LVLiveIntercomImpl::listen → NotifyIntercomListen. Formato
// AMF0 exacto (decompilado): "pause", número(txn), null, boolean(doPause), número(pauseTime).
// [RE 2026-10-20] doPause=false = modo HABLAR (el robot reproduce nuestro audio); doPause=true
// = modo escuchar (pausa nuestro saliente). Lo mandamos por el canal del play (csid 8, msid 1).
func (t *talkConn) sendPause(doPause bool) error {
	t.txn++
	body := amfString("pause")
	body = append(body, amfNumber(float64(t.txn))...)
	body = append(body, amfNull()...)
	body = append(body, amfBool(doPause)...)
	body = append(body, amfNumber(0)...) // pauseTime=0 (reanudar desde ya)
	return t.writeChunk(8, 20, 1, 0, body)
}

// Listen pone el canal en modo HABLAR (el robot reproduce NUESTRO audio) = pause(false),
// que es lo que la app manda vía LVLiveIntercomImpl::listen → NotifyIntercomListen.
// talk2 no lo mandaba (se quitó de rtmp_open por "sobraba"); sin esto el robot NO sale
// de su modo half-duplex por defecto y no reproduce lo que enviamos.
func (t *talkConn) Listen() error { return t.sendPause(false) }

// WaitPlayStart bloquea hasta recibir NetStream.Play.Start del robot (= pipeline de
// playback listo) o timeout. La app no empuja audio hasta que el robot está "playing".
func (t *talkConn) WaitPlayStart(d time.Duration) bool {
	select {
	case <-t.playStarted:
		return true
	case <-time.After(d):
		return false
	}
}

// WaitDataStart bloquea hasta recibir NetStream.Data.Start del robot (= el robot se unió
// al stream del /talk) o timeout. La receta ganadora reenvía el config (72 00 80 00) justo
// DESPUÉS de este evento, porque el config inicial llega antes del join y el robot se lo
// pierde (sin config no sabe decodificar nuestro A-law → silencio). Ver HABLAR-RESUELTO.
func (t *talkConn) WaitDataStart(d time.Duration) bool {
	select {
	case <-t.dataStarted:
		return true
	case <-time.After(d):
		return false
	}
}

// Ping envía el keepalive onStatus NetStream.Ping.Start (el cliente lo manda).
func (t *talkConn) Ping() error {
	t.txn++
	body := amfString("onStatus")
	body = append(body, amfNumber(float64(t.txn))...)
	body = append(body, amfNull()...)
	o := amfObjStart()
	o = amfObjProp(o, "level", amfString("status"))
	o = amfObjProp(o, "code", amfString("NetStream.Ping.Start"))
	o = amfObjProp(o, "description", amfString("desc"))
	o = amfObjEnd(o)
	body = append(body, o...)
	// [PROVEN por captura] el SDK manda el Ping por csid 3 / msid 0 (canal del connect).
	return t.writeChunk(3, 20, 0, 0, body)
}

func (t *talkConn) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	t.txn++
	body := amfString("deleteStream")
	body = append(body, amfNumber(float64(t.txn))...)
	body = append(body, amfNull()...)
	body = append(body, amfNumber(1)...) // stream id 1
	_ = t.writeChunkLocked(8, 20, 1, 0, body)
	return t.conn.Close()
}

// writeChunk serializa un mensaje RTMP en chunks de 128 (fmt0 + continuaciones fmt3).
func (t *talkConn) writeChunk(csid uint8, msgType uint8, msid uint32, ts uint32, payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return io.ErrClosedPipe
	}
	return t.writeChunkLocked(csid, msgType, msid, ts, payload)
}

func (t *talkConn) writeChunkLocked(csid uint8, msgType uint8, msid uint32, ts uint32, payload []byte) error {
	var hdr []byte
	// Basic header fmt0 + message header (11 bytes): ts(3) len(3) type(1) msid(4 LE).
	hdr = append(hdr, csid&0x3f) // fmt 0
	hdr = append(hdr, byte(ts>>16), byte(ts>>8), byte(ts))
	n := len(payload)
	hdr = append(hdr, byte(n>>16), byte(n>>8), byte(n))
	hdr = append(hdr, msgType)
	var sid [4]byte
	binary.LittleEndian.PutUint32(sid[:], msid)
	hdr = append(hdr, sid[:]...)

	buf := make([]byte, 0, len(hdr)+n+n/talkChunkSize+1)
	buf = append(buf, hdr...)
	for i := 0; i < n; i += talkChunkSize {
		if i > 0 {
			buf = append(buf, 0xC0|(csid&0x3f)) // continuación fmt3
		}
		end := i + talkChunkSize
		if end > n {
			end = n
		}
		buf = append(buf, payload[i:end]...)
	}
	_, err := t.conn.Write(buf)
	return err
}

// --- AMF0 helpers ---

func amfString(s string) []byte {
	b := []byte{0x02, byte(len(s) >> 8), byte(len(s))}
	return append(b, s...)
}
func amfNumber(f float64) []byte {
	b := make([]byte, 9)
	b[0] = 0x00
	binary.BigEndian.PutUint64(b[1:], math.Float64bits(f))
	return b
}
func amfBool(v bool) []byte {
	if v {
		return []byte{0x01, 1}
	}
	return []byte{0x01, 0}
}
func amfNull() []byte           { return []byte{0x05} }
func amfObjStart() []byte       { return []byte{0x03} }
func amfObjEnd(b []byte) []byte { return append(b, 0x00, 0x00, 0x09) }
func amfObjProp(b []byte, name string, val []byte) []byte {
	b = append(b, byte(len(name)>>8), byte(len(name)))
	b = append(b, name...)
	return append(b, val...)
}
