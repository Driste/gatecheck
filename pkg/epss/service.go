package epss

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/epss/cache"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
)

var ErrAPIPartialFail = errors.New("an API request failed")

type CVE struct {
	ID       string
	Severity string
	Link     string
}

type response struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Version    string `json:"version"`
	Access     string `json:"access"`
	Total      int    `json:"total"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	Data       []Data `json:"data"`
}

type Data struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`
	Percentile string `json:"percentile"`
	Date       string `json:"date"`
	Severity   string `json:"severity,omitempty"`
	URL        string `json:"url,omitempty"`
}

type result struct {
	data  Data
	Error error
}

func NewEPSSService(c *http.Client, endpoint string) *Service {
	return &Service{client: c, BatchSize: 10, Endpoint: endpoint}
}

type Service struct {
	client    *http.Client
	BatchSize int
	Endpoint  string
	Cache     cache.Cache
}

func (s Service) Get(CVEs []CVE) ([]Data, error) {
	dataChan := make(chan result)
	var wg sync.WaitGroup

	for i := 0; i < len(CVEs); i = i + s.BatchSize {
		l := i + s.BatchSize
		if l > len(CVEs) {
			l = len(CVEs)
		}
		group := CVEs[i:l]
		wg.Add(1)
		go func(g []CVE) {
			defer wg.Done()

			query := fmt.Sprintf("cve=" + commaSeparated(g))
			resObj, err := s.get(query)
			if err != nil {
				dataChan <- result{Error: err}
				return
			}

			inputMap := cveMap(CVEs)
			for _, returnedData := range resObj.Data {
				returnedData.URL = inputMap[returnedData.CVE].Link
				returnedData.Severity = inputMap[returnedData.CVE].Severity
				dataChan <- result{data: returnedData}
			}
		}(group)
	}

	go func() {
		wg.Wait()
		close(dataChan)
	}()

	var data []Data
	var err error

	for d := range dataChan {
		data = append(data, d.data)
		if d.Error != nil {
			err = ErrAPIPartialFail
		}
	}

	return data, err
}

func (s Service) CreateCache() error {
	dataChan := make(chan result)
	var wg sync.WaitGroup
	s.Cache, _ = cache.NewCache()
	err := s.Cache.Open()
	if err != nil {
		return fmt.Errorf("cache file: %v", err)
	}
	defer s.Cache.Close()

	// TODO: Determine DB length
	stop := 3000
	limit := 1000
	for i := 0; i < stop; i = i + limit {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			query := fmt.Sprintf("limit=%d&offset=%d", limit, i)
			resObj, err := s.get(query)
			if err != nil {
				dataChan <- result{Error: err}
				return
			}

			for _, returnedData := range resObj.Data {
				dataChan <- result{data: returnedData}
			}
		}(i)
	}

	go func() {
		wg.Wait()
		close(dataChan)
	}()

	for d := range dataChan {
		if d.Error != nil {
			err = ErrAPIPartialFail
		}
		s.Cache.Put([]byte(d.data.CVE), []byte(d.data.EPSS))
	}

	return err
}

func (s Service) get(query string) (resp response, err error) {
	url := fmt.Sprintf("%s?%s", s.Endpoint, query)
	req, _ := http.NewRequest(http.MethodGet, url, nil)

	log.Debugf("Sending Request: %s", url)
	res, err := s.client.Do(req)
	if err != nil {
		return
	}
	if res.StatusCode != http.StatusOK {
		log.Infof("EPSS API response status: %s", res.Status)
		return resp, errors.New("received non 200 response")
	}
	err = json.NewDecoder(res.Body).Decode(&resp)

	if err != nil {
		return resp, err
	}

	return resp, nil
}

func commaSeparated(CVEs []CVE) string {
	items := make([]string, len(CVEs))
	for i, v := range CVEs {
		items[i] = v.ID
	}
	return strings.Join(items, ",")
}

func cveMap(CVEs []CVE) map[string]CVE {
	out := make(map[string]CVE)

	for _, v := range CVEs {
		out[v.ID] = v
	}
	return out
}

func Sprint(data []Data) string {

	table := new(gcStrings.Table).WithHeader("CVE", "Severity", "EPSS", "Percentile", "Date", "Link")

	percentage := func(s string) string {
		f, _ := strconv.ParseFloat(s, 32)

		return fmt.Sprintf("%.2f%%", 100*f)
	}

	for _, d := range data {
		table = table.WithRow(d.CVE, d.Severity, percentage(d.EPSS), percentage(d.Percentile), d.Date, d.URL)
	}

	// Dsc because EPSS has been converted into a percentage
	table = table.SortBy([]gcStrings.SortBy{
		{Name: "EPSS", Mode: gcStrings.Dsc},
	}).Sort()

	return table.String()
}
