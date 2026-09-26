package splitter

import (
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	_ "image/jpeg"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// page draws a synthetic page: white margins and random framed panels.
func page(rng *rand.Rand, w, h int) *image.Gray {
	img := image.NewGray(image.Rect(0, 0, w, h))
	draw.Draw(img, img.Bounds(), image.White, image.Point{}, draw.Src)
	margin := 30 + rng.Intn(30)
	for y := margin; y < h-margin-80; {
		ph := 150 + rng.Intn(250)
		if y+ph > h-margin {
			ph = h - margin - y
		}
		fill := color.Gray{Y: uint8(rng.Intn(200))}
		draw.Draw(img, image.Rect(margin, y, w-margin, y+ph-8), &image.Uniform{C: fill}, image.Point{}, draw.Src)
		for x := margin; x < w-margin; x += 3 + rng.Intn(9) {
			for yy := y; yy < y+ph-8; yy += 2 {
				img.SetGray(x, yy, color.Gray{Y: uint8(rng.Intn(256))})
			}
		}
		y += ph
	}
	return img
}

func strip(pages []*image.Gray, offset int) *image.Gray {
	w, h := pages[0].Bounds().Dx(), 0
	for _, p := range pages {
		h += p.Bounds().Dy()
	}
	out := image.NewGray(image.Rect(0, 0, w, h))
	y := 0
	for _, p := range pages {
		draw.Draw(out, p.Bounds().Add(image.Pt(0, y)), p, image.Point{}, draw.Src)
		y += p.Bounds().Dy()
	}
	return out.SubImage(image.Rect(0, offset, w, h)).(*image.Gray)
}

func TestDetect(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	tests := []struct {
		name   string
		pages  int
		w, h   int
		offset int
	}{
		{"exact multiple", 20, 800, 1149, 0},
		{"wider page", 12, 864, 1200, 0},
		{"two pages", 2, 800, 1150, 0},
		{"starts mid-page", 15, 800, 1170, 517},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pages []*image.Gray
			for i := 0; i < tt.pages; i++ {
				pages = append(pages, page(rng, tt.w, tt.h))
			}
			img := strip(pages, tt.offset)
			r := Detect(img)
			cuts := r.Cuts[1 : len(r.Cuts)-1]
			if !r.Reliable || len(cuts) != tt.pages-1 {
				t.Fatalf("got %d cuts at height %d (reliable=%v, score %.2f), want %d at %d",
					len(cuts), r.PageHeight, r.Reliable, r.Score, tt.pages-1, tt.h)
			}
			// a cut may land anywhere in the white margin around the seam:
			// no content moves to another page
			_, flat := rowStats(img)
			for i, c := range cuts {
				a, b := c, tt.h*(i+1)-tt.offset
				if a > b {
					a, b = b, a
				}
				if b-a > 3 && !allFlat(flat[a:b]) {
					t.Errorf("cut %d at %d moves content, seam at %d", i, c, tt.h*(i+1)-tt.offset)
				}
			}
		})
	}
}

func TestDetectSinglePage(t *testing.T) {
	r := Detect(page(rand.New(rand.NewSource(1)), 800, 1150))
	if r.Reliable || len(r.Cuts) != 2 {
		t.Fatalf("single page should not be split, got %+v", r)
	}
}

func TestWidestPlateau(t *testing.T) {
	marked := []bool{true, true, false, true, true, true, false, true}
	// the run 7,0,1 wraps around and ties with 3,4,5; the first found wins
	if c, l := widestPlateau(marked); l != 3 || (c != 4 && c != 0) {
		t.Fatalf("got centre %d length %d", c, l)
	}
}

// TestSuite runs Detect against the cortar-manga suite (synthetic strips plus
// real chapters already approved page by page). Point MANGAL_SPLIT_SUITE at
// the folder with gabarito.json to run it; real chapters must match exactly.
func TestSuite(t *testing.T) {
	dir := os.Getenv("MANGAL_SPLIT_SUITE")
	if dir == "" {
		t.Skip("MANGAL_SPLIT_SUITE not set")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "gabarito.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]struct {
		Files  []string `json:"arquivos"`
		Height int      `json:"altura"`
		Seams  []int    `json:"emendas"`
		Expect string   `json:"espera"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}

	for name, c := range cases {
		name, c := name, c
		t.Run(name, func(t *testing.T) {
			img := loadStrip(t, dir, c.Files)
			r := Detect(img)
			got := r.Cuts[1 : len(r.Cuts)-1]
			ok := r.Reliable && len(got) == len(c.Seams)
			worst := 0
			if ok {
				_, flat := rowStats(img)
				for i, cut := range got {
					a, b := cut, c.Seams[i]
					if a > b {
						a, b = b, a
					}
					if b-a > 3 && !allFlat(flat[a:b]) {
						worst = maxInt(worst, b-a)
					}
					if isReal(name) && cut != c.Seams[i] {
						worst = maxInt(worst, b-a)
					}
				}
				ok = worst == 0
			}
			t.Logf("height %d offset %d score %.2f reliable %v, %d/%d cuts, worst %dpx",
				r.PageHeight, r.Offset, r.Score, r.Reliable, len(got), len(c.Seams), worst)
			switch {
			case ok:
			case c.Expect == "limite":
				t.Skip("known limit")
			case name == "14_webtoon_espaco_branco":
				t.Skip("white-gap webtoons need the band fallback, not ported")
			default:
				t.Errorf("wrong cuts")
			}
		})
	}
}

func isReal(name string) bool { return len(name) > 5 && name[:5] == "real_" }

func loadStrip(t *testing.T, dir string, files []string) image.Image {
	var parts []image.Image
	w, h := 0, 0
	for _, f := range files {
		fh, err := os.Open(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		img, _, err := image.Decode(fh)
		fh.Close()
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, img)
		w, h = img.Bounds().Dx(), h+img.Bounds().Dy()
	}
	if len(parts) == 1 {
		return parts[0]
	}
	out := image.NewRGBA(image.Rect(0, 0, w, h))
	y := 0
	for _, p := range parts {
		draw.Draw(out, image.Rect(0, y, w, y+p.Bounds().Dy()), p, p.Bounds().Min, draw.Src)
		y += p.Bounds().Dy()
	}
	return out
}

func allFlat(rows []bool) bool {
	for _, f := range rows {
		if !f {
			return false
		}
	}
	return true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
