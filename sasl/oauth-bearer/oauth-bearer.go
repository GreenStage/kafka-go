package oauthbearer

import (
	"context"
	"fmt"
	"github.com/segmentio/kafka-go/sasl"
)

type GetToken func() (string, error)

type mechanism struct {
	getToken GetToken
}

func Mechanism(token GetToken) sasl.Mechanism {
	return &mechanism{
		getToken: token,
	}
}

func (m *mechanism) Name() string {
	return "OAUTHBEARER"
}

func (m *mechanism) Start(_ context.Context) (sasl.StateMachine, []byte, error) {
	token, err := m.getToken()
	if err != nil {
		return nil, nil, fmt.Errorf("error fetching token for OAUTHBEARER authentication: %s", err.Error())
	}

	return m, []byte(fmt.Sprintf("n,,\x01%s\x01", token)), nil
}

func (m *mechanism) Next(_ context.Context, _ []byte) (bool, []byte, error) {
	// kafka will return error if the broker rejected the token, so we'd only
	// arrive here on success.
	return true, nil, nil
}
