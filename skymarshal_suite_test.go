package skymarshal_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/concourse/atc/db/dbfakes"
	"github.com/concourse/skymarshal"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	externalURL  = "https://example.com"
	oAuthBaseURL = "https://oauth.example.com"

	peerAddr string
	drain    chan struct{}

	dbTeamFactory *dbfakes.FakeTeamFactory

	server *httptest.Server
	client *http.Client
)

var _ = BeforeEach(func() {
	peerAddr = "127.0.0.1:1234"

	dbTeam := new(dbfakes.FakeTeam)
	dbTeam.IDReturns(734)

	dbTeamFactory = new(dbfakes.FakeTeamFactory)
	dbTeamFactory.FindTeamReturns(dbTeam, true, nil)
	dbTeamFactory.GetByIDReturns(dbTeam)

	config := &skymarshal.Config{
		BaseUrl:      externalURL,
		BaseAuthUrl:  oAuthBaseURL,
		Expiration:   24 * time.Hour,
		IsTLSEnabled: false,
		TeamFactory:  dbTeamFactory,
	}

	handler, err := skymarshal.NewHandler(config)
	Expect(err).NotTo(HaveOccurred())

	server = httptest.NewServer(handler)

	client = &http.Client{
		Transport: &http.Transport{},
	}
})

var _ = AfterEach(func() {
	server.Close()
})

func TestSkymarshal(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Skymarshal Suite")
}
