package dreame

import (
	"net/url"
	"strings"

	"github.com/rs/zerolog"
)

// log es el logger del módulo (se inicializa en Init). Trazabilidad del source y,
// sobre todo, del camino de audio del intercom, para depurar la validación contra
// el robot vivo sin reconstruir nada.
var log zerolog.Logger

// redactURL deja esquema://host:puerto/path y oculta el query (token, session,
// firma OSS, clave de stream). Regla del proyecto: nunca loguear secretos ni URLs
// firmadas. Ej: rtmp://1.2.3.4:8000/talk?token=…  ->  rtmp://1.2.3.4:8000/talk?<redacted>
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<url>"
	}
	out := u.Scheme + "://" + u.Host + u.Path
	if u.RawQuery != "" {
		out += "?<redacted>"
	}
	return out
}

// redactID muestra solo un prefijo corto de un identificador sensible (iotId, did).
func redactID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) <= 6 {
		if id == "" {
			return "<id>"
		}
		return id[:1] + "…"
	}
	return id[:6] + "…"
}
