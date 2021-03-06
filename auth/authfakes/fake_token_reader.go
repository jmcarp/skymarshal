// Code generated by counterfeiter. DO NOT EDIT.
package authfakes

import (
	"net/http"
	"sync"

	"github.com/concourse/skymarshal/auth"
)

type FakeTokenReader struct {
	GetTeamStub        func(r *http.Request) (string, bool, bool)
	getTeamMutex       sync.RWMutex
	getTeamArgsForCall []struct {
		r *http.Request
	}
	getTeamReturns struct {
		result1 string
		result2 bool
		result3 bool
	}
	getTeamReturnsOnCall map[int]struct {
		result1 string
		result2 bool
		result3 bool
	}
	GetSystemStub        func(r *http.Request) (bool, bool)
	getSystemMutex       sync.RWMutex
	getSystemArgsForCall []struct {
		r *http.Request
	}
	getSystemReturns struct {
		result1 bool
		result2 bool
	}
	getSystemReturnsOnCall map[int]struct {
		result1 bool
		result2 bool
	}
	GetCSRFTokenStub        func(r *http.Request) (string, bool)
	getCSRFTokenMutex       sync.RWMutex
	getCSRFTokenArgsForCall []struct {
		r *http.Request
	}
	getCSRFTokenReturns struct {
		result1 string
		result2 bool
	}
	getCSRFTokenReturnsOnCall map[int]struct {
		result1 string
		result2 bool
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeTokenReader) GetTeam(r *http.Request) (string, bool, bool) {
	fake.getTeamMutex.Lock()
	ret, specificReturn := fake.getTeamReturnsOnCall[len(fake.getTeamArgsForCall)]
	fake.getTeamArgsForCall = append(fake.getTeamArgsForCall, struct {
		r *http.Request
	}{r})
	fake.recordInvocation("GetTeam", []interface{}{r})
	fake.getTeamMutex.Unlock()
	if fake.GetTeamStub != nil {
		return fake.GetTeamStub(r)
	}
	if specificReturn {
		return ret.result1, ret.result2, ret.result3
	}
	return fake.getTeamReturns.result1, fake.getTeamReturns.result2, fake.getTeamReturns.result3
}

func (fake *FakeTokenReader) GetTeamCallCount() int {
	fake.getTeamMutex.RLock()
	defer fake.getTeamMutex.RUnlock()
	return len(fake.getTeamArgsForCall)
}

func (fake *FakeTokenReader) GetTeamArgsForCall(i int) *http.Request {
	fake.getTeamMutex.RLock()
	defer fake.getTeamMutex.RUnlock()
	return fake.getTeamArgsForCall[i].r
}

func (fake *FakeTokenReader) GetTeamReturns(result1 string, result2 bool, result3 bool) {
	fake.GetTeamStub = nil
	fake.getTeamReturns = struct {
		result1 string
		result2 bool
		result3 bool
	}{result1, result2, result3}
}

func (fake *FakeTokenReader) GetTeamReturnsOnCall(i int, result1 string, result2 bool, result3 bool) {
	fake.GetTeamStub = nil
	if fake.getTeamReturnsOnCall == nil {
		fake.getTeamReturnsOnCall = make(map[int]struct {
			result1 string
			result2 bool
			result3 bool
		})
	}
	fake.getTeamReturnsOnCall[i] = struct {
		result1 string
		result2 bool
		result3 bool
	}{result1, result2, result3}
}

func (fake *FakeTokenReader) GetSystem(r *http.Request) (bool, bool) {
	fake.getSystemMutex.Lock()
	ret, specificReturn := fake.getSystemReturnsOnCall[len(fake.getSystemArgsForCall)]
	fake.getSystemArgsForCall = append(fake.getSystemArgsForCall, struct {
		r *http.Request
	}{r})
	fake.recordInvocation("GetSystem", []interface{}{r})
	fake.getSystemMutex.Unlock()
	if fake.GetSystemStub != nil {
		return fake.GetSystemStub(r)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getSystemReturns.result1, fake.getSystemReturns.result2
}

func (fake *FakeTokenReader) GetSystemCallCount() int {
	fake.getSystemMutex.RLock()
	defer fake.getSystemMutex.RUnlock()
	return len(fake.getSystemArgsForCall)
}

func (fake *FakeTokenReader) GetSystemArgsForCall(i int) *http.Request {
	fake.getSystemMutex.RLock()
	defer fake.getSystemMutex.RUnlock()
	return fake.getSystemArgsForCall[i].r
}

func (fake *FakeTokenReader) GetSystemReturns(result1 bool, result2 bool) {
	fake.GetSystemStub = nil
	fake.getSystemReturns = struct {
		result1 bool
		result2 bool
	}{result1, result2}
}

func (fake *FakeTokenReader) GetSystemReturnsOnCall(i int, result1 bool, result2 bool) {
	fake.GetSystemStub = nil
	if fake.getSystemReturnsOnCall == nil {
		fake.getSystemReturnsOnCall = make(map[int]struct {
			result1 bool
			result2 bool
		})
	}
	fake.getSystemReturnsOnCall[i] = struct {
		result1 bool
		result2 bool
	}{result1, result2}
}

func (fake *FakeTokenReader) GetCSRFToken(r *http.Request) (string, bool) {
	fake.getCSRFTokenMutex.Lock()
	ret, specificReturn := fake.getCSRFTokenReturnsOnCall[len(fake.getCSRFTokenArgsForCall)]
	fake.getCSRFTokenArgsForCall = append(fake.getCSRFTokenArgsForCall, struct {
		r *http.Request
	}{r})
	fake.recordInvocation("GetCSRFToken", []interface{}{r})
	fake.getCSRFTokenMutex.Unlock()
	if fake.GetCSRFTokenStub != nil {
		return fake.GetCSRFTokenStub(r)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	return fake.getCSRFTokenReturns.result1, fake.getCSRFTokenReturns.result2
}

func (fake *FakeTokenReader) GetCSRFTokenCallCount() int {
	fake.getCSRFTokenMutex.RLock()
	defer fake.getCSRFTokenMutex.RUnlock()
	return len(fake.getCSRFTokenArgsForCall)
}

func (fake *FakeTokenReader) GetCSRFTokenArgsForCall(i int) *http.Request {
	fake.getCSRFTokenMutex.RLock()
	defer fake.getCSRFTokenMutex.RUnlock()
	return fake.getCSRFTokenArgsForCall[i].r
}

func (fake *FakeTokenReader) GetCSRFTokenReturns(result1 string, result2 bool) {
	fake.GetCSRFTokenStub = nil
	fake.getCSRFTokenReturns = struct {
		result1 string
		result2 bool
	}{result1, result2}
}

func (fake *FakeTokenReader) GetCSRFTokenReturnsOnCall(i int, result1 string, result2 bool) {
	fake.GetCSRFTokenStub = nil
	if fake.getCSRFTokenReturnsOnCall == nil {
		fake.getCSRFTokenReturnsOnCall = make(map[int]struct {
			result1 string
			result2 bool
		})
	}
	fake.getCSRFTokenReturnsOnCall[i] = struct {
		result1 string
		result2 bool
	}{result1, result2}
}

func (fake *FakeTokenReader) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.getTeamMutex.RLock()
	defer fake.getTeamMutex.RUnlock()
	fake.getSystemMutex.RLock()
	defer fake.getSystemMutex.RUnlock()
	fake.getCSRFTokenMutex.RLock()
	defer fake.getCSRFTokenMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeTokenReader) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ auth.TokenReader = new(FakeTokenReader)
