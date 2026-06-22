package server

import (
	"context"
	"log"
	"time"
)

// unverifiedAccountTTL is the grace period a self-registered account has to verify
// its e-mail address. Past this deadline the background sweeper purges the account.
const unverifiedAccountTTL = 72 * time.Hour

// unverifiedDeleteBatch bounds how many accounts a single sweep statement deletes,
// so a large backlog cannot become one long row-locking transaction.
const unverifiedDeleteBatch = 500

// startUnverifiedCleanup runs an hourly sweep that purges self-registered accounts
// which never verified their e-mail within unverifiedAccountTTL. Accounts an admin
// has manually (un)verified, and OIDC auto-registered accounts, carry a NULL
// deadline and are never touched. The first sweep runs shortly after startup.
func (h *Handler) startUnverifiedCleanup() {
	go func() {
		sweep := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			n, err := h.st.DeleteUnverifiedExpired(ctx, unverifiedDeleteBatch)
			if err != nil {
				log.Printf("unverified cleanup: %v", err)
				return
			}
			if n > 0 {
				log.Printf("unverified cleanup: removed %d account(s) unverified past the %s deadline", n, unverifiedAccountTTL)
			}
		}
		sweep()
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			sweep()
		}
	}()
}
