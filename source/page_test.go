package source

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/spf13/viper"

	"github.com/metafates/mangal/key"
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

func TestNotAnImage(t *testing.T) {
	tests := []struct {
		name     string
		contents []byte
		wantErr  bool
	}{
		{"expired message", []byte("Expired"), true},
		{"html page", []byte("<!DOCTYPE html><html><body>404</body></html>"), true},
		{"jpeg", mergedStrip(t, 1, 100, 100).Bytes(), false},
		{"unknown binary", []byte{0x00, 0x01, 0x02, 0xff, 0xfe}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := notAnImage(tt.contents); (err != nil) != tt.wantErr {
				t.Fatalf("notAnImage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPage_DownloadRetriesTransientErrors(t *testing.T) {
	defer func(d []time.Duration) { pageRetryDelays = d }(pageRetryDelays)
	pageRetryDelays = []time.Duration{0, 0, 0}

	img := mergedStrip(t, 1, 100, 100).Bytes()
	tests := []struct {
		name      string
		failures  int
		failure   func(w http.ResponseWriter)
		wantErr   bool
		wantCalls int
	}{
		{"expired then image", 2, func(w http.ResponseWriter) { _, _ = w.Write([]byte("Expired")) }, false, 3},
		{"expired every time", 10, func(w http.ResponseWriter) { _, _ = w.Write([]byte("Expired")) }, true, 4},
		{"server error then image", 1, func(w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) }, false, 2},
		{"not found is not retried", 10, func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) }, true, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls <= tt.failures {
					tt.failure(w)
					return
				}
				_, _ = w.Write(img)
			}))
			defer srv.Close()

			page := &Page{URL: srv.URL, Index: 1, Chapter: &Chapter{Manga: &Manga{Source: &testSource{}}}}
			err := page.Download()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Download() error = %v, wantErr %v", err, tt.wantErr)
			}
			if calls != tt.wantCalls {
				t.Fatalf("got %d requests, want %d", calls, tt.wantCalls)
			}
			if !tt.wantErr && page.Contents.Len() != len(img) {
				t.Fatalf("got %d bytes, want %d", page.Contents.Len(), len(img))
			}
		})
	}
}

func TestChapter_DownloadPagesKeepsFirstError(t *testing.T) {
	defer func(async bool) { viper.Set(key.DownloaderAsync, async) }(viper.GetBool(key.DownloaderAsync))
	viper.Set(key.DownloaderAsync, true)

	img := mergedStrip(t, 1, 100, 100).Bytes()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// pages that succeed finish after the one that fails
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write(img)
	}))
	defer srv.Close()

	chapter := &Chapter{Manga: &Manga{Source: &testSource{}}}
	for i, path := range []string{"/missing", "/a", "/b", "/c"} {
		chapter.Pages = append(chapter.Pages, &Page{URL: srv.URL + path, Index: uint16(i + 1), Chapter: chapter})
	}

	if err := chapter.DownloadPages(true, func(string) {}); err == nil {
		t.Fatal("DownloadPages() error = nil, want the error of the missing page")
	}
}
