package media

import (
	"sort"
)

type FusionLayer struct {
	epsilon int
}

func NewFusionLayer() *FusionLayer {
	return &FusionLayer{
		epsilon: 8 * 1024,
	}
}

func (f *FusionLayer) Fuse(spatialSignals []Signal) []Region {
	if len(spatialSignals) == 0 {
		return nil
	}

	sort.Slice(spatialSignals, func(i, j int) bool {
		return spatialSignals[i].Offset < spatialSignals[j].Offset
	})

	var regions []Region

	currentRegion := Region{
		StartOffset: spatialSignals[0].Offset,
		EndOffset:   spatialSignals[0].Offset + spatialSignals[0].Length,
		Signals:     []Signal{spatialSignals[0]},
	}

	for i := 1; i < len(spatialSignals); i++ {
		sig := spatialSignals[i]

		if sig.Offset <= currentRegion.EndOffset+f.epsilon {
			currentRegion.Signals = append(currentRegion.Signals, sig)
			end := sig.Offset + sig.Length
			if end > currentRegion.EndOffset {
				currentRegion.EndOffset = end
			}
		} else {
			regions = append(regions, f.processRegion(currentRegion))

			currentRegion = Region{
				StartOffset: sig.Offset,
				EndOffset:   sig.Offset + sig.Length,
				Signals:     []Signal{sig},
			}
		}
	}
	regions = append(regions, f.processRegion(currentRegion))

	return regions
}

func (f *FusionLayer) processRegion(r Region) Region {
	if len(r.Signals) == 0 {
		return r
	}

	payloadMap := make(map[string][]Signal)
	magicMap := make(map[string][]Signal)
	var maxEnt float64

	for _, s := range r.Signals {
		switch s.Type {
		case SignalHighEntropy:
			if s.Metadata.EntropyScore > maxEnt {
				maxEnt = s.Metadata.EntropyScore
			}
		case SignalPayload, SignalPrivacyLeak:
			payloadMap[s.Value] = append(payloadMap[s.Value], s)
		case SignalMagic, SignalZIPEOCD, SignalAPKStruct:
			val := string(s.Type) + ":" + s.Value
			magicMap[val] = append(magicMap[val], s)
		}
	}

	r.MaxEntropy = maxEnt

	var payloadKeys []string
	for k := range payloadMap {
		payloadKeys = append(payloadKeys, k)
	}
	sort.Strings(payloadKeys)

	var magicKeys []string
	for k := range magicMap {
		magicKeys = append(magicKeys, k)
	}
	sort.Strings(magicKeys)

	safeConfProb := 1.0
	safeSevProb := 1.0

	uniqueDominant := make(map[string]bool)

	for _, name := range payloadKeys {
		sigs := payloadMap[name]
		for _, s := range sigs {
			c := Clamp(s.Confidence)
			if c >= 0.999 {
				c = 0.999
			}
			safeConfProb *= (1.0 - c)
			if safeConfProb < 0.0001 {
				safeConfProb = 0.0001
			}

			sev := Clamp(s.Severity)
			if sev >= 0.999 {
				sev = 0.999
			}
			safeSevProb *= (1.0 - sev)
			if safeSevProb < 0.0001 {
				safeSevProb = 0.0001
			}

			if !uniqueDominant[name] {
				if len(r.DominantSignals) < 10 {
					r.DominantSignals = append(r.DominantSignals, name)
				}
				uniqueDominant[name] = true
			}
		}
	}

	for _, name := range magicKeys {
		sigs := magicMap[name]
		for _, m := range sigs {
			if !uniqueDominant[name] {
				if len(r.DominantSignals) < 10 {
					r.DominantSignals = append(r.DominantSignals, name)
				}
				uniqueDominant[name] = true
			}

			c := Clamp(m.Confidence)
			if c >= 0.999 {
				c = 0.999
			}
			safeConfProb *= (1.0 - c)
			if safeConfProb < 0.0001 {
				safeConfProb = 0.0001
			}

			sev := Clamp(m.Severity)
			if sev >= 0.999 {
				sev = 0.999
			}
			safeSevProb *= (1.0 - sev)
			if safeSevProb < 0.0001 {
				safeSevProb = 0.0001
			}
		}
	}

	if maxEnt >= 7.8 {
		name := "HighEntropy"
		if !uniqueDominant[name] {
			if len(r.DominantSignals) < 10 {
				r.DominantSignals = append(r.DominantSignals, name)
			}
			uniqueDominant[name] = true
		}
		safeConfProb *= (1.0 - 0.8)
		safeSevProb *= (1.0 - 0.7)
	}

	r.FusedConfidence = Clamp(1.0 - safeConfProb)
	r.FusedSeverity = Clamp(1.0 - safeSevProb)

	return r
}
