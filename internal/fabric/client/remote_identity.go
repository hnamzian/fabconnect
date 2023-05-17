package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	mspApi "github.com/hyperledger/fabric-sdk-go/pkg/msp/api"
)

type Attribute struct {
	Name  string	`json:"name"`
	Value string	`json:"value"`
	ECert bool		`json:"ecert"`
}

type RemoteRegisterRequest struct {
	Name           string      `json:"name"`
	Type           string      `json:"type"`
	MaxEnrollments int         `json:"max_enrollments"`
	Affiliation    string      `json:"affiliation"`
	Attributes     []Attribute `json:"attributes"`
	CAName         string      `json:"caname"`
	Secret         string      `json:"secret"`
}

type SignRequest struct {
	Message string `json:"message"`
}

func remoteRegister(regReq *mspApi.RegistrationRequest) (string, error) {
	// send POST request to http://localhost:4000/fabric/identities/:username
	posturl := "http://localhost:4000/fabric-cryptosuit/identities/" + regReq.Name

	rr := &RemoteRegisterRequest{
		Name:           regReq.Name,
		Type:           regReq.Type,
		MaxEnrollments: regReq.MaxEnrollments,
		Affiliation:    regReq.Affiliation,
		CAName:         regReq.CAName,
		Secret:         regReq.Secret,
	}
	if regReq.Attributes != nil {
		rr.Attributes = []Attribute{}
		for key, _ := range regReq.Attributes {
			rr.Attributes = append(rr.Attributes, Attribute{
				Name: regReq.Attributes[key].Name, 
				Value: regReq.Attributes[key].Value, 
				ECert: regReq.Attributes[key].ECert,
			})
		}
	}

	// convert rr to bytes
	body, err := json.Marshal(rr)
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("failed to encode register request payload: %s", err), 400)
	}

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", posturl, bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("failed to create remote register request: %s", err), 400)
	}

	// Add headers
	postReq.Header.Add("Content-Type", "application/json")


	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		return "", fmt.Errorf(fmt.Sprintf("failed to register identity remotely: %s", err), 400)
	}
	defer resp.Body.Close()

	secret, _ := io.ReadAll(resp.Body)

	return string(secret), nil
}

func remoteEnroll(enrollmentID string) ([]byte, error) {
	// send POST request to http://localhost:4000/fabric/identities/:username/enroll
	posturl := "http://localhost:4000/fabric-cryptosuit/identities/" + enrollmentID + "/enroll"

	body := []byte(`{}`)

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", posturl, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Add headers
	postReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result, _ := io.ReadAll(resp.Body)

	return result, nil
}

func remoteRevoke(revokeReq mspApi.RevocationRequest) (*mspApi.RevocationResponse, error) {
	fmt.Printf("revokeReq: %s\n", revokeReq.Name)
	// send POST request to http://localhost:4000/fabric/identities/:username/revoke
	posturl := "http://localhost:4000/fabric-cryptosuit/identities/" + revokeReq.Name + "/revoke"

	body := []byte(`{}`)

	// Create a HTTP post request
	postReq, err := http.NewRequest("POST", posturl, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	// Add headers
	postReq.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(postReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	fmt.Printf("result: %s\n", result)
	if err != nil {
		return nil, err
	}

	var revokeResult *mspApi.RevocationResponse = &mspApi.RevocationResponse{}
	if err = json.Unmarshal(result, revokeResult); err != nil {
		return nil, err
	}

	return revokeResult, err
}

