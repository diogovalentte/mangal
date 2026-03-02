package source

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"image"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/metafates/mangal/constant"
	"github.com/metafates/mangal/log"
	"github.com/metafates/mangal/network"
	"github.com/metafates/mangal/util"
)

// Page represents a page in a chapter
type Page struct {
	// URL of the page. Used to download the page.
	URL string `json:"url" jsonschema:"description=URL of the page. Used to download the image."`
	// Index of the page in the chapter.
	Index uint16 `json:"index" jsonschema:"description=Index of the page in the chapter."`
	// Extension of the page image.
	Extension string `json:"extension" jsonschema:"description=Extension of the page image."`
	// Size of the page in bytes
	Size uint64 `json:"-"`
	// Contents of the page
	Contents *bytes.Buffer `json:"-"`
	// Chapter that the page belongs to.
	Chapter *Chapter `json:"-"`
}

func (p *Page) request() (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, p.URL, nil)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	req.Header.Set("Referer", p.Chapter.URL)
	req.Header.Set("User-Agent", constant.UserAgent)
	return req, nil
}

// Download Page contents.
func (p *Page) Download() error {
	if p.URL == "" {
		log.Warnf("Page #%d has no URL", p.Index)
		return nil
	}

	log.Tracef("Downloading page #%d (%s)", p.Index, p.URL)

	req, err := p.request()
	if err != nil {
		return err
	}

	var resp *http.Response
	if p.Chapter.Manga.Source.Name() == "KLManga" {
		client := http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   100,
				MaxConnsPerHost:       200,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				ExpectContinueTimeout: 30 * time.Second,
			},
		}
		resp, err = client.Do(req)
	} else if p.Chapter.Manga.Source.Name() == "MangaHub" {
		client := http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MaxVersion: tls.VersionTLS12,
				},
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   100,
				MaxConnsPerHost:       200,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				ExpectContinueTimeout: 30 * time.Second,
			},
		}

		header := http.Header{}
		header.Set("Content-Type", "application/json")
		header.Set("Accept", "application/json")
		header.Set("Origin", "https://mangahub.io")
		header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:30.0) Gecko/20100101 Firefox/30.0")

		var uuid string
		uuid, err = generateUUID()
		if err != nil {
			return err
		}
		header.Set("x-mhub-access", uuid)
		resp, err = client.Do(req)
	} else {
		resp, err = network.Client.Do(req)
	}
	if err != nil {
		log.Error(err)
		return err
	}

	defer util.Ignore(resp.Body.Close)

	if resp.StatusCode != http.StatusOK {
		err = errors.New("http error: " + resp.Status)
		log.Error(err)
		return err
	}

	if resp.ContentLength == 0 {
		err = errors.New("http error: nothing was returned")
		log.Error(err)
		return err
	}

	var (
		buf           []byte
		contentLength int64
	)

	// if the content length is unknown
	if resp.ContentLength == -1 {
		buf, err = io.ReadAll(resp.Body)
		contentLength = int64(len(buf))
	} else {
		contentLength = resp.ContentLength
		buf = make([]byte, resp.ContentLength)
		_, err = io.ReadFull(resp.Body, buf)
	}

	if err != nil {
		return err
	}

	p.Contents = bytes.NewBuffer(buf)
	p.Size = uint64(util.Max(contentLength, 0))

	log.Tracef("Page #%d downloaded", p.Index)
	return nil
}

// Close closes the page contents.
func (p *Page) Close() error {
	return nil
}

// Read reads from the page contents.
func (p *Page) Read(b []byte) (int, error) {
	log.Tracef("Reading page contents #%d", p.Index)
	if p.Contents == nil {
		err := errors.New("page not downloaded")
		log.Error(err)
		return 0, err
	}

	return p.Contents.Read(b)
}

// Filename generates a filename for the page.
func (p *Page) Filename() (filename string) {
	filename = fmt.Sprintf("%d%s", p.Index, p.Extension)
	filename = util.PadZero(filename, 10)

	return
}

func (p *Page) Source() Source {
	return p.Chapter.Source()
}

func (p *Page) SplitMergedPage() ([]*Page, error) {
	pagesCount, err := pagesFromURL(p.URL)
	if err != nil {
		return nil, err
	}

	if pagesCount <= 1 || p.Contents == nil {
		return []*Page{p}, nil
	}

	// Decode image
	img, format, err := image.Decode(bytes.NewReader(p.Contents.Bytes()))
	if err != nil {
		return nil, err
	}

	b := img.Bounds()
	width := b.Dx()
	height := b.Dy()

	sliceHeight := height / pagesCount
	if sliceHeight == 0 {
		return []*Page{p}, nil
	}

	var pages []*Page
	y := 0
	index := p.Index

	for i := 0; i < pagesCount; i++ {
		h := sliceHeight
		if i == pagesCount-1 {
			h = height - y // remainder
		}

		sub := image.NewRGBA(image.Rect(0, 0, width, h))
		draw.Draw(
			sub,
			sub.Bounds(),
			img,
			image.Point{X: 0, Y: y},
			draw.Src,
		)

		var buf bytes.Buffer
		switch format {
		case "png":
			err = png.Encode(&buf, sub)
		default:
			err = jpeg.Encode(&buf, sub, &jpeg.Options{Quality: 95})
		}
		if err != nil {
			return nil, err
		}

		newPage := &Page{
			Index:     index,
			URL:       p.URL,
			Chapter:   p.Chapter,
			Contents:  &buf,
			Size:      uint64(buf.Len()),
			Extension: filepath.Ext(p.URL),
		}

		pages = append(pages, newPage)

		y += h
		index++
	}

	return pages, nil
}

func generateUUID() (string, error) {
	var uuid [16]byte
	_, err := rand.Read(uuid[:])
	if err != nil {
		return "", err
	}

	// Set version (4 bits) and variant (2 bits) according to the UUID v4 specification
	uuid[6] = (uuid[6] & 0x0F) | 0x40 // version 4
	uuid[8] = (uuid[8] & 0x3F) | 0x80 // variant 1

	// Format the UUID as a string
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func pagesFromURL(u string) (int, error) {
	// matches: merged_1-18.jpg / merged_1-18.jpeg / merged_1-18.png
	re := regexp.MustCompile(`merged_\d+-(\d+)\.`)

	m := re.FindStringSubmatch(u)
	if len(m) != 2 {
		return 0, fmt.Errorf("page count not found in url")
	}

	return strconv.Atoi(m[1])
}
