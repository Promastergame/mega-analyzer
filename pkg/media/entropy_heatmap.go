package media

// EntropyHeatmap is a 2D grid of Shannon entropy values, one cell per
// fixed-size byte range of the input file. Used to visualise where
// high-entropy (possibly encrypted/stego) regions sit inside a file.
type EntropyHeatmap struct {
	CellSize int         // bytes per cell
	Grid     [][]float64 // Grid[row][col]
	Width    int         // number of columns
	Height   int         // number of rows
	MinEnt   float64
	MaxEnt   float64
}

// HeatmapRegion is a rectangular area of anomalous entropy.
type HeatmapRegion struct {
	Row, Col      int
	Width, Height int
	MeanEntropy   float64
	ZScore        float64
}

// BuildEntropyHeatmap computes Shannon entropy for each cell of a grid
// overlaid on data. cellSize controls the byte range per cell; 256 is a
// good default for files up to ~10 MB.
func BuildEntropyHeatmap(data []byte, cellSize int) *EntropyHeatmap {
	if cellSize <= 0 {
		cellSize = 256
	}
	if len(data) == 0 {
		return &EntropyHeatmap{CellSize: cellSize}
	}

	cols := (len(data) + cellSize - 1) / cellSize
	rows := 1
	// For very large data, tile into rows if desired; currently 1 row.
	hm := &EntropyHeatmap{
		CellSize: cellSize,
		Width:    cols,
		Height:   rows,
		Grid:     make([][]float64, rows),
	}

	var sum float64
	for c := 0; c < cols; c++ {
		start := c * cellSize
		end := start + cellSize
		if end > len(data) {
			end = len(data)
		}
		e := calcShannonEntropy(data[start:end])
		hm.Grid[0] = append(hm.Grid[0], e)
		sum += e
		if c == 0 || e < hm.MinEnt {
			hm.MinEnt = e
		}
		if c == 0 || e > hm.MaxEnt {
			hm.MaxEnt = e
		}
	}

	return hm
}

// Anomalies returns cells whose entropy deviates from the mean by more
// than threshold standard deviations (local z-score).
func (h *EntropyHeatmap) Anomalies(threshold float64) []HeatmapRegion {
	if h == nil || len(h.Grid) == 0 || len(h.Grid[0]) == 0 {
		return nil
	}

	cells := h.Grid[0]
	n := float64(len(cells))
	var sum float64
	for _, e := range cells {
		sum += e
	}
	mean := sum / n

	var sumSq float64
	for _, e := range cells {
		d := e - mean
		sumSq += d * d
	}
	variance := sumSq / n
	var stddev float64
	if variance > 0 {
		// Newton's method sqrt approximation
		stddev = variance
		for i := 0; i < 20; i++ {
			stddev = (stddev + variance/stddev) / 2
		}
	}

	if stddev == 0 {
		return nil
	}

	var anomalies []HeatmapRegion
	for c, e := range cells {
		z := (e - mean) / stddev
		if z >= threshold || z <= -threshold {
			anomalies = append(anomalies, HeatmapRegion{
				Row:         0,
				Col:         c,
				Width:       1,
				Height:      1,
				MeanEntropy: e,
				ZScore:      z,
			})
		}
	}
	return anomalies
}
