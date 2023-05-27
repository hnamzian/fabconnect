package wallet

import (
	"github.com/golang/protobuf/proto"
	pb_msp "github.com/hyperledger/fabric-protos-go/msp"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
	"github.com/hyperledger/firefly-fabconnect/internal/fabric/remote/handlers"
	remoteIdentity "github.com/hyperledger/firefly-fabconnect/internal/fabric/remote/identity"

	"github.com/pkg/errors"
)

type walletIdentity struct {
	id                    string
	mspID                 string
	enrollmentCertificate []byte
	privateKey            core.Key

	handler *handlers.CryptosuitHandler
}

func NewWalletIdentity(id string, mspID string, remoteHost string) *walletIdentity {
	wid := &walletIdentity{
		id:      id,
		mspID:   mspID,
		handler: handlers.NewCryptosuitHandler(remoteHost),
	}

	signingIdentity, err := remoteIdentity.NewSigningIdentity(id, mspID, remoteHost)
	if err != nil {
		return nil
	}
	wid.privateKey = *signingIdentity.Key

	cert, err := wid.handler.GetIdentity(id)
	if err != nil {
		return nil
	}
	wid.enrollmentCertificate = []byte(cert)

	return wid
}

// Identifier returns walletIdentity identifier
func (u *walletIdentity) Identifier() *msp.IdentityIdentifier {
	return &msp.IdentityIdentifier{MSPID: u.mspID, ID: u.id}
}

// Verify a signature over some message using this identity as reference
func (u *walletIdentity) Verify(msg []byte, sig []byte) error {
	verified, err := u.handler.Verify(u.privateKey.SKI(), msg, sig)
	if err != nil {
		return err
	}
	if !verified {
		return errors.New("signature verification failed")
	}
	return nil
}

// Serialize converts an identity to bytes
func (u *walletIdentity) Serialize() ([]byte, error) {
	serializedIdentity := &pb_msp.SerializedIdentity{
		Mspid:   u.mspID,
		IdBytes: u.enrollmentCertificate,
	}
	identity, err := proto.Marshal(serializedIdentity)
	if err != nil {
		return nil, errors.Wrap(err, "marshal serializedIdentity failed")
	}
	return identity, nil
}

// EnrollmentCertificate Returns the underlying ECert representing this walletIdentity’s identity.
func (u *walletIdentity) EnrollmentCertificate() []byte {
	return u.enrollmentCertificate
}

// PrivateKey returns the crypto suite representation of the private key
func (u *walletIdentity) PrivateKey() core.Key {
	return u.privateKey
}

// PublicVersion returns the public parts of this identity
func (u *walletIdentity) PublicVersion() msp.Identity {
	return u
}

// Sign the message
func (u *walletIdentity) Sign(msg []byte) ([]byte, error) {
	return u.handler.Sign(u.privateKey.SKI(), msg)
}
