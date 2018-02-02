package skymarshal_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Auth API", func() {
	It("works", func() {
		Expect(server).NotTo(BeNil())
	})
})
