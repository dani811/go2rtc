package dreame

import (
	"os"
	"strconv"
	"sync/atomic"
)

// talkGain: ganancia aplicada al audio del micro antes de enviarlo al robot.
// La app nativa llama a AliPlayerEngine.setGainLevel(1); por RTMP puro no podemos,
// así que amplificamos el A-law aquí. Ajustable con DREAME_TALK_GAIN (default 3).
var talkGain = func() float64 {
	if v := os.Getenv("DREAME_TALK_GAIN"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 {
			return f
		}
	}
	return 12.0
}()

var alawDecTab [256]int16
var _alawInit = func() bool {
	for i := 0; i < 256; i++ {
		alawDecTab[i] = alaw2linCompute(byte(i))
	}
	return true
}()

func alaw2linCompute(a byte) int16 {
	a ^= 0x55
	t := int(a&0x0f) << 4
	seg := int(a&0x70) >> 4
	switch seg {
	case 0:
		t += 8
	case 1:
		t += 0x108
	default:
		t += 0x108
		t <<= uint(seg - 1)
	}
	if a&0x80 != 0 {
		return int16(t)
	}
	return int16(-t)
}

var segEndG = [8]int16{0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF}

func lin2alawG(pcm int16) byte {
	var mask byte
	v := pcm >> 3
	if v >= 0 {
		mask = 0xD5
	} else {
		mask = 0x55
		v = -v - 1
	}
	seg := 8
	for i, e := range segEndG {
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

var talkFrames int64
var talkPeakAcc int64

// processTalk mide el pico del micro (pre-ganancia) y aplica ganancia al A-law.
func processTalk(payload []byte) []byte {
	var pk int32
	for _, b := range payload {
		s := int32(alawDecTab[b])
		if s < 0 {
			s = -s
		}
		if s > pk {
			pk = s
		}
	}
	if p := atomic.LoadInt64(&talkPeakAcc); int64(pk) > p {
		atomic.StoreInt64(&talkPeakAcc, int64(pk))
	}
	if atomic.AddInt64(&talkFrames, 1)%50 == 0 {
		log.Info().Msgf("[dreame] intercom: micro pico=%d/32767 gain=%.1f", atomic.SwapInt64(&talkPeakAcc, 0), talkGain)
	}
	if talkGain == 1.0 {
		return payload
	}
	out := make([]byte, len(payload))
	for i, b := range payload {
		g := int32(float64(alawDecTab[b]) * talkGain)
		if g > 32767 {
			g = 32767
		} else if g < -32768 {
			g = -32768
		}
		out[i] = lin2alawG(int16(g))
	}
	return out
}
