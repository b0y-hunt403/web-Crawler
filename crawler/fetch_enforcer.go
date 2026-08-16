package crawler

import (
	"context"
	"errors"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

var ErrNetworkPolicyEnforcement = errors.New("NETWORK_POLICY_ENFORCEMENT_FAILED")

type FetchRequestEnforcer interface {
	Continue(context.Context, fetch.RequestID) error
	Fail(context.Context, fetch.RequestID, network.ErrorReason) error
}

type chromedpFetchEnforcer struct{}

func (e chromedpFetchEnforcer) Continue(ctx context.Context, id fetch.RequestID) error {
	return chromedp.Run(ctx, fetch.ContinueRequest(id))
}
func (e chromedpFetchEnforcer) Fail(ctx context.Context, id fetch.RequestID, r network.ErrorReason) error {
	return chromedp.Run(ctx, fetch.FailRequest(id, r))
}
