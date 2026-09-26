// Package splitter finds page boundaries in a tall image made of manga pages
// stacked on top of each other with no gap between them.
package splitter

import (
	"image"
	"image/color"
	"math"
	"sort"
)

// minPiece is the smallest page height kept on its own; shorter pieces are
// merged into their neighbour so no pixel is lost.
const minPiece = 50

// Result of a page height detection.
type Result struct {
	// PageHeight is the detected page height in pixels.
	PageHeight int
	// Offset is the first seam when the strip starts mid-page, 0 otherwise.
	Offset int
	// Score tells how much PageHeight stands out among the candidates.
	Score float64
	// Reliable is false when no page height clearly fits the image.
	Reliable bool
	// Cuts are the page boundaries, from 0 to the image height.
	Cuts []int
}

// Detect looks for the page height that best explains the seams of img.
//
// Inside a page, neighbour rows look alike; across a seam they do not, and a
// seam between two white margins always falls on a flat row. Panel borders
// also create jumps, but only the right height hits a seam on every page, so
// it wins on average.
func Detect(img image.Image) Result {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	s := seamSignal(img)

	tol := func(H int) float64 { return math.Max(4, float64(H)*0.01) }
	exact := func(H int) bool {
		r := h % H
		return float64(minInt(r, H-r)) <= tol(H)
	}

	var heights, offsets, plateaus []int
	var scores []float64
	var anchored []bool
	for H := w; H <= 2*w; H++ {
		n := h / H
		if n < 2 {
			continue
		}
		mean := make([]float64, H)
		for k := 0; k < n; k++ {
			row := s[k*H : (k+1)*H]
			for off, v := range row {
				mean[off] += v
			}
		}
		for off := range mean {
			mean[off] /= float64(n)
		}
		// row 0 of the strip is not an informative seam; use only inner ones
		col0 := 0.0
		for k := 1; k < n; k++ {
			col0 += s[k*H]
		}
		col0 /= float64(n - 1)
		mean[0] = col0

		score := maxFloat(mean)
		// exact multiple whose top matches: the grid starts at the top and
		// competes with that grid's score, not with the best possible phase
		isAnchored := exact(H) && (col0 >= score-0.05 || col0 >= 0.85)
		off, plateau := 0, 0
		if isAnchored {
			score = col0
		} else {
			marked := make([]bool, H)
			for i, v := range mean {
				marked[i] = v >= score-0.02
			}
			off, plateau = widestPlateau(marked)
		}
		heights = append(heights, H)
		offsets = append(offsets, off)
		plateaus = append(plateaus, plateau)
		scores = append(scores, score)
		anchored = append(anchored, isAnchored)
	}
	if len(heights) == 0 {
		return Result{Cuts: []int{0, h}}
	}

	best := maxFloat(scores)
	var tied []int
	for i, v := range scores {
		if v >= best-0.03 {
			tied = append(tied, i)
		}
	}
	chosen := -1
	for _, i := range tied {
		// prefer the height that closes the strip in whole pages
		if anchored[i] && (chosen < 0 || scores[i] > scores[chosen]) {
			chosen = i
		}
	}
	if chosen < 0 {
		// no exact multiple: the right height keeps the margins aligned the
		// longest, so its plateau is the widest
		for _, i := range tied {
			if chosen < 0 || plateaus[i] > plateaus[chosen] ||
				(plateaus[i] == plateaus[chosen] && scores[i] > scores[chosen]) {
				chosen = i
			}
		}
	}

	H, off := heights[chosen], offsets[chosen]
	start := off
	if start == 0 {
		start = H
	}
	hits, seams := 0, 0
	for y := start; y < h-1; y += H {
		seams++
		if s[y] >= 0.5 {
			hits++
		}
	}
	hitRate := 0.0
	if seams > 0 {
		hitRate = float64(hits) / float64(seams)
	}
	score := scores[chosen] / (median(scores) + 1e-6)
	// a short strip has too few samples for the score; there, closing in
	// whole pages with matching seams is enough
	reliable := score >= 1.3 || (anchored[chosen] && hitRate >= 0.85)

	cuts := []int{0}
	for y := start; y < h; y += H {
		cuts = append(cuts, y)
	}
	cuts = append(cuts, h)

	return Result{
		PageHeight: H,
		Offset:     off,
		Score:      score,
		Reliable:   reliable,
		Cuts:       mergeSmallPieces(cuts, h),
	}
}

// seamSignal returns, per row, 0..1 for how much it looks like a seam: a
// capped jump from the previous row, or 1 for a flat row. The cap keeps a
// single panel border from outweighing many seams.
func seamSignal(img image.Image) []float64 {
	diff, flat := rowStats(img)
	base := median(diff) + 1
	s := make([]float64, len(diff))
	for y := range s {
		s[y] = math.Min(diff[y]/base, 8) / 8
		if flat[y] {
			s[y] = 1
		}
	}
	return s
}

// rowStats returns, per row, the mean absolute jump from the previous row and
// whether the row is flat (low standard deviation).
func rowStats(img image.Image) (diff []float64, flat []bool) {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	prev := make([]float64, w)
	cur := make([]float64, w)
	diff = make([]float64, h)
	flat = make([]bool, h)
	for y := 0; y < h; y++ {
		grayRow(img, b.Min.Y+y, cur)
		sum, sumSq, jump := 0.0, 0.0, 0.0
		for x, v := range cur {
			sum += v
			sumSq += v * v
			if y > 0 {
				jump += math.Abs(v - prev[x])
			}
		}
		mean := sum / float64(w)
		variance := sumSq/float64(w) - mean*mean
		flat[y] = math.Sqrt(math.Max(variance, 0)) < 6
		diff[y] = jump / float64(w)
		prev, cur = cur, prev
	}
	return diff, flat
}

// grayRow writes the luma of row y into out. JPEGs are read straight from
// the Y channel; everything else goes through the ITU-R 601 weights.
func grayRow(img image.Image, y int, out []float64) {
	minX := img.Bounds().Min.X
	if ycc, ok := img.(*image.YCbCr); ok {
		for x := range out {
			out[x] = float64(ycc.Y[ycc.YOffset(minX+x, y)])
		}
		return
	}
	for x := range out {
		r, g, b, a := img.At(minX+x, y).RGBA()
		if a < 0xffff {
			// transparency over a white background
			bg := uint32(0xffff - a)
			r, g, b = r+bg, g+bg, b+bg
		}
		out[x] = float64(color.GrayModel.Convert(color.RGBA64{
			R: uint16(minU32(r, 0xffff)), G: uint16(minU32(g, 0xffff)), B: uint16(minU32(b, 0xffff)), A: 0xffff,
		}).(color.Gray).Y)
	}
}

// widestPlateau returns the centre and length of the longest run of marked
// entries, wrapping around the end.
func widestPlateau(marked []bool) (centre, length int) {
	n := len(marked)
	start := -1
	for i, m := range marked {
		if !m {
			start = i + 1 // begin right after a gap
			break
		}
	}
	if start < 0 {
		return 0, n
	}
	run := 0
	for j := 0; j <= n; j++ {
		if j < n && marked[(start+j)%n] {
			run++
			continue
		}
		if run > length {
			centre, length = (start+j-run+run/2)%n, run
		}
		run = 0
	}
	return centre, length
}

// mergeSmallPieces drops cuts that would leave a piece shorter than
// minPiece, merging it into its neighbour.
func mergeSmallPieces(cuts []int, h int) []int {
	sorted := append([]int(nil), cuts...)
	sort.Ints(sorted)
	kept := []int{0}
	for _, c := range sorted {
		if c-kept[len(kept)-1] >= minPiece && h-c >= minPiece {
			kept = append(kept, c)
		}
	}
	return append(kept, h)
}

func median(values []float64) float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

func maxFloat(values []float64) float64 {
	m := math.Inf(-1)
	for _, v := range values {
		m = math.Max(m, v)
	}
	return m
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func minU32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
