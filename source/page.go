package source

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	_ "image/gif"
	"io"
	"net/http"
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

		uuid, err := generateUUID()
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
