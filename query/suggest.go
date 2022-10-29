package query

import (
	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/samber/lo"
	"github.com/samber/mo"
	"golang.org/x/exp/slices"
)

var (
	suggestionCache = make(map[string][]*queryRecord)
)

func SuggestMany(query string) []string {
	query = sanitize(query)

	var records []*queryRecord

	if prev, ok := suggestionCache[query]; ok {
		records = prev
	} else {
		cached, ok := cacher.Get().Get()
		if !ok {
			return []string{}
		}

		for _, record := range cached {
			if fuzzy.Match(query, record.Query) {
				records = append(records, record)
			}
		}

		slices.SortFunc(records, func(a, b *queryRecord) bool {
			return a.Rank > b.Rank
		})

		suggestionCache[query] = records
	}

	return lo.Map(records, func(record *queryRecord, _ int) string {
		return record.Query
	})
}

// Suggest gives a suggestion for a query
func Suggest(query string) mo.Option[string] {
	records := SuggestMany(query)

	var suggestion mo.Option[string]

	if len(records) == 0 {
		suggestion = mo.None[string]()
	} else {
		suggestion = mo.Some(records[0])
	}

	return suggestion
}
