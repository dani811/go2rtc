package dreame

// talk_alaw.go — conversión A-law ↔ PCM16 y resampleo 8 kHz → 16 kHz, en Go puro.
//
// El robot reproduce el /talk como A-law **16 kHz** (640 B/40 ms, confirmado de oído
// 2026-10-29 + pcap real). La tarjeta WebRTC de HA entrega el micro como **PCMA 8 kHz**
// (G.711a está fijado a 8 kHz en WebRTC). Así que hay que subir 8k→16k antes de reenviar:
//   alaw8 → PCM16(8k) → interpolación lineal ×2 → PCM16(16k) → alaw16 → SendAudio.
// Calidad resultante = banda telefónica (≤4 kHz) a velocidad/tono correctos; suficiente
// para intercom. Mejora futura: backchannel Opus wideband (requiere decodificar Opus).

// alaw2linear decodifica un byte G.711 A-law a PCM lineal de 16 bits (ITU-T G.711).
func alaw2linear(a byte) int16 {
	a ^= 0x55
	t := int(a&0x0f) << 4
	seg := (int(a) & 0x70) >> 4
	switch seg {
	case 0:
		t += 8
	case 1:
		t += 0x108
	default:
		t += 0x108
		t <<= uint(seg - 1)
	}
	if a&0x80 == 0 {
		return int16(-t)
	}
	return int16(t)
}

// segAendA: límites de segmento A-law (tabla exacta de la sonda de laboratorio).
var segAendA = [8]int16{0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF}

// linear2alaw codifica PCM lineal de 16 bits a G.711 A-law. COPIA EXACTA de la función
// que el dueño validó de oído (signalprobe/peer_audio.go); no tocar (es el oráculo).
func linear2alaw(pcm int16) byte {
	var mask byte
	v := pcm >> 3
	if v >= 0 {
		mask = 0xD5
	} else {
		mask = 0x55
		v = -v - 1
	}
	seg := 8
	for i, e := range segAendA {
		if v <= e {
			seg = i
			break
		}
	}
	if seg >= 8 {
		return 0x7F ^ mask
	}
	aval := byte(seg << 4)
	if seg < 2 {
		aval |= byte((v >> 1) & 0x0f)
	} else {
		aval |= byte((v >> uint(seg)) & 0x0f)
	}
	return aval ^ mask
}

// upsampleAlaw8to16 toma A-law 8 kHz y devuelve A-law 16 kHz (interpolación lineal ×2).
func upsampleAlaw8to16(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, 0, len(in)*2)
	prev := alaw2linear(in[0])
	for i := 0; i < len(in); i++ {
		cur := alaw2linear(in[i])
		mid := int32(prev)/2 + int32(cur)/2 // muestra interpolada entre prev y cur
		out = append(out, linear2alaw(int16(mid)), linear2alaw(cur))
		prev = cur
	}
	return out
}
