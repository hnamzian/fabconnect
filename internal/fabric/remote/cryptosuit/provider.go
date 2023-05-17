package cryptosuit

import (
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/logging/api"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/logging/modlog"
	signingMgr "github.com/hyperledger/fabric-sdk-go/pkg/fab/signingmgr"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk/provider/fabpvdr"
)

type CryptoSuiteProvideFactory struct {
	addr string
}

func NewCryptoSuiteProvideFactory(addr string) *CryptoSuiteProvideFactory {
	return &CryptoSuiteProvideFactory{addr: addr}
}

// CreateCryptoSuiteProvider returns a new default implementation of BCCSP
func (f *CryptoSuiteProvideFactory) CreateCryptoSuiteProvider(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	cryptoSuiteProvider := NewCryptoSuite(f.addr)
	return cryptoSuiteProvider, nil
}

// CreateSigningManager returns a new default implementation of signing manager
func (f *CryptoSuiteProvideFactory) CreateSigningManager(cryptoProvider core.CryptoSuite) (core.SigningManager, error) {
	return signingMgr.New(cryptoProvider)
}

// CreateInfraProvider returns a new default implementation of fabric primitives
func (f *CryptoSuiteProvideFactory) CreateInfraProvider(config fab.EndpointConfig) (fab.InfraProvider, error) {
	return fabpvdr.New(config), nil
}

// NewLoggerProvider returns a new default implementation of a logger backend
// This function is separated from the factory to allow logger creation first.
func NewLoggerProvider() api.LoggerProvider {
	return modlog.LoggerProvider()
}
