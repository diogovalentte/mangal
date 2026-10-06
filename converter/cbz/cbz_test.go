package cbz

import (
	"archive/zip"
	"bytes"
	"github.com/metafates/mangal/config"
	"github.com/metafates/mangal/constant"
	"github.com/metafates/mangal/filesystem"
	"github.com/metafates/mangal/key"
	"github.com/metafates/mangal/source"
	"github.com/samber/lo"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/viper"
	"io/fs"
	"path/filepath"
	"testing"
)

func init() {
	filesystem.SetMemMapFs()
	lo.Must0(config.Setup())
	viper.Set(key.FormatsUse, constant.FormatCBZ)
}

func TestCBZ(t *testing.T) {
	cbz := New()

	Convey("Given a FormatCBZ converter", t, func() {
		Convey("When saving a chapter", func() {
			chapter := SampleChapter(t)
			result, err := cbz.Save(chapter)
			Convey("Then the error should be nil", func() {
				So(err, ShouldBeNil)
				Convey("And the result should be a path with .cbz extension", func() {
					So(result, ShouldNotBeEmpty)
					So(filepath.Ext(result), ShouldEqual, ".cbz")

					Convey("A path that can be read", func() {
						file, err := filesystem.Api().Open(result)
						So(err, ShouldBeNil)
						So(file, ShouldNotBeNil)

						info := lo.Must(file.Stat())

						zipReader := lo.Must(zip.NewReader(file, info.Size()))

						Convey("Zip file should contain ComicInfo.xml", func() {
							_, ok := lo.Find(zipReader.File, func(f *zip.File) bool {
								return f.Name == "ComicInfo.xml"
							})

							So(ok, ShouldBeTrue)
						})

						Convey("And the number of files should be equal to the number of pages + 1", func() {
							So(len(zipReader.File), ShouldEqual, len(chapter.Pages)+1)
						})
					})
				})
			})
		})
	})

	_ = cbz
}

func SampleChapter(t *testing.T) *source.Chapter {
	t.Helper()
	chapter := source.Chapter{
		Name:  "chapter name",
		URL:   "chapter url",
		Index: 42069,
		ID:    "fawfa",
		Pages: []*source.Page{},
	}
	manga := source.Manga{
		Name:     "manga name",
		URL:      "manga url",
		Index:    1337,
		ID:       "wjakfkawgjj",
		Chapters: []*source.Chapter{&chapter},
	}
	chapter.Manga = &manga

	// to get images
	filesystem.SetOsFs()
	defer filesystem.SetMemMapFs()

	// get all images from ../assets/testdata
	err := filesystem.Api().Walk(
		// ../../assets/testdata
		// I wish windows used a normal path separator instead of whatever this \ is
		filepath.Join(filepath.Dir(filepath.Dir(lo.Must(filepath.Abs(".")))), filepath.Join("assets", "testdata")),
		func(path string, info fs.FileInfo, _ error) error {
			if lo.Must(filesystem.Api().IsDir(path)) || filepath.Ext(path) != ".jpeg" {
				return nil
			}

			image, err := filesystem.Api().ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			page := source.Page{
				URL:       "dwadwaf",
				Index:     0,
				Extension: filepath.Ext(path),
				Chapter:   &chapter,
				Contents:  bytes.NewBuffer(image),
			}
			chapter.Pages = append(chapter.Pages, &page)

			return nil
		},
	)

	if err != nil {
		t.Fatal(err)
	}

	return &chapter
}

func TestSaveToReplacesOnlyComplete(t *testing.T) {
	Convey("Given a CBZ file already saved for a chapter", t, func() {
		path := filepath.Join("replace", "chapter.cbz")
		// SampleChapter resets the filesystem, so the old file is written after it
		saveOld := func() {
			lo.Must0(filesystem.Api().MkdirAll("replace", 0755))
			lo.Must0(filesystem.Api().WriteFile(path, []byte("old"), 0644))
		}

		Convey("When a page of the new download is missing", func() {
			chapter := SampleChapter(t)
			saveOld()
			chapter.Pages[0].Contents = nil
			err := SaveTo(chapter, path)

			Convey("Then it fails and keeps the old file", func() {
				So(err, ShouldNotBeNil)
				So(string(lo.Must(filesystem.Api().ReadFile(path))), ShouldEqual, "old")
				So(lo.Must(filesystem.Api().Exists(path+".part")), ShouldBeFalse)
			})
		})

		Convey("When the new download is complete", func() {
			chapter := SampleChapter(t)
			saveOld()
			err := SaveTo(chapter, path)

			Convey("Then the old file is replaced and no .part is left", func() {
				So(err, ShouldBeNil)
				file := lo.Must(filesystem.Api().Open(path))
				info := lo.Must(file.Stat())
				zipReader := lo.Must(zip.NewReader(file, info.Size()))
				So(len(zipReader.File), ShouldEqual, len(chapter.Pages)+1)
				So(lo.Must(filesystem.Api().Exists(path+".part")), ShouldBeFalse)
			})
		})
	})
}
