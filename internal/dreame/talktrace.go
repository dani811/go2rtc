package dreame

import "sync"

// Instrumentación del canal de talk: hasta ahora drain() consumía la respuesta del
// relay y la tiraba (volábamos a ciegas). Esto engancha TalkTrace para EXTRAER y LOGUEAR
// los strings AMF0 que manda el relay (onStatus/_result/_error/NetStream.*/description),
// que es lo que explica por qué el robot no renderiza. No cambia el envío; solo observa.
//
// Es un escáner tolerante (no un parser de chunks RTMP completo): busca marcadores de
// string AMF0 (0x02 len16) y longstring (0x0c len32) legibles en el flujo entrante. Es
// suficiente para ver los códigos de estado del relay en los logs del source dreame://.

var talkTraceOnce sync.Once

// enableTalkTrace instala el hook de traza una sola vez (idempotente).
func enableTalkTrace() {
	talkTraceOnce.Do(func() {
		TalkTrace = func(b []byte) {
			for _, s := range scanAMFStrings(b) {
				log.Info().Msgf("[dreame] intercom relay→cliente: %q", s)
			}
		}
	})
}

// scanAMFStrings recorre el buffer y devuelve los strings AMF0 legibles. Marca 0x02
// (string, longitud 16 bits) y 0x0c (longstring, longitud 32 bits).
func scanAMFStrings(b []byte) []string {
	var out []string
	n := len(b)
	for i := 0; i < n; {
		switch {
		case b[i] == 0x02 && i+3 <= n:
			l := int(b[i+1])<<8 | int(b[i+2])
			if l > 0 && l <= 512 && i+3+l <= n && isMostlyPrintable(b[i+3:i+3+l]) {
				out = append(out, string(b[i+3:i+3+l]))
				i += 3 + l
				continue
			}
		case b[i] == 0x0c && i+5 <= n:
			l := int(b[i+1])<<24 | int(b[i+2])<<16 | int(b[i+3])<<8 | int(b[i+4])
			if l > 0 && l <= 4096 && i+5+l <= n && isMostlyPrintable(b[i+5:i+5+l]) {
				out = append(out, string(b[i+5:i+5+l]))
				i += 5 + l
				continue
			}
		}
		i++
	}
	return out
}

// isMostlyPrintable evita que basura binaria pase por string AMF.
func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	bad := 0
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			bad++
		}
	}
	return bad*5 < len(b) // <20% no imprimible
}
