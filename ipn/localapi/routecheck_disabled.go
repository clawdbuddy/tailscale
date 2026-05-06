// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build ts_omit_routecheck

package localapi

import (
	"context"
	"net/http"
	"time"

	"tailscale.com/feature"
)

func (h *Handler) serveRouteCheck(w http.ResponseWriter, r *http.Request) {
	panic(feature.ErrUnavailable.Error())
}

func (h *Handler) routeCheckProbe(ctx context.Context, timeout time.Duration) error {
	return nil
}
