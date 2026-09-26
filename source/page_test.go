package source

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// mergedStrip encodes a JPEG of n synthetic pages stacked vertically.
func mergedStrip(t *testing.T, n, w, h int) *bytes.Buffer {
	rng := rand.New(rand.NewSource(7))
	img := image.NewGray(image.Rect(0, 0, w, n*h))
	for y := 0; y < n*h; y++ {
		inMargin := y%h < 40 || y%h >= h-40
		for x := 0; x < w; x++ {
			v := uint8(255)
			if !inMargin && x >= 40 && x < w-40 {
				v = uint8(rng.Intn(256))
			}
			img.SetGray(x, y, color.Gray{Y: v})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func pageHeights(t *testing.T, pages []*Page) []int {
	var hs []int
	for _, p := range pages {
		cfg, _, err := image.DecodeConfig(bytes.NewReader(p.Contents.Bytes()))
		if err != nil {
			t.Fatal(err)
		}
		hs = append(hs, cfg.Height)
	}
	return hs
}

func TestPage_SplitMergedPage(t *testing.T) {
	const w, h, n = 400, 580, 6
	tests := []struct {
		name   string
		url    string
		detect bool
		want   int
	}{
		{"page count in url", "https://cdn/merged_1-6.jpg", false, n},
		{"page count in url wins over detection", "https://cdn/merged_1-3.jpg", true, 3},
		{"no count, detection on", "https://cdn/merged_Chapter%2010.jpg", true, n},
		{"no count, detection off", "https://cdn/6ylmkqeefkbo", false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Page{URL: tt.url, Index: 1, Extension: ".jpg", Contents: mergedStrip(t, n, w, h)}
			pages, err := p.SplitMergedPage(tt.detect)
			if err != nil {
				t.Fatal(err)
			}
			if len(pages) != tt.want {
				t.Fatalf("got %d pages, want %d", len(pages), tt.want)
			}
			total := 0
			for i, ph := range pageHeights(t, pages) {
				total += ph
				if pages[i].Index != uint16(i+1) {
					t.Errorf("page %d has index %d", i, pages[i].Index)
				}
			}
			if total != n*h {
				t.Errorf("pages add up to %dpx, want %dpx", total, n*h)
			}
		})
	}
}

// TestPage_SplitMergedPageReal splits a real merged chapter; point
// MANGAL_SPLIT_REAL at a merged image and MANGAL_SPLIT_REAL_PAGES at the
// expected page count.
func TestPage_SplitMergedPageReal(t *testing.T) {
	path := os.Getenv("MANGAL_SPLIT_REAL")
	if path == "" {
		t.Skip("MANGAL_SPLIT_REAL not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	p := &Page{URL: "https://cdn/" + filepath.Base(path), Index: 1, Extension: ".jpg", Contents: bytes.NewBuffer(raw)}
	pages, err := p.SplitMergedPage(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d pages: %v", len(pages), pageHeights(t, pages))
	if want := os.Getenv("MANGAL_SPLIT_REAL_PAGES"); want != "" && want != strconv.Itoa(len(pages)) {
		t.Fatalf("got %d pages, want %s", len(pages), want)
	}
}
