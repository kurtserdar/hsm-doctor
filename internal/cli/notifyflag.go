package cli

import (
	"github.com/kurtserdar/hsm-doctor/internal/notify"
	"github.com/kurtserdar/hsm-doctor/internal/server"
	"github.com/kurtserdar/hsm-doctor/internal/store"
)

// applyNotify loads the e-mail notification config and installs a notifier
// on the server. The store backs the per-certificate deduplication ledger;
// when persistence is disabled cert-expiry reminders would repeat, so the
// notifier runs without a ledger (drift still works).
func applyNotify(srv *server.Server, path string, st store.Store) error {
	if path == "" {
		return nil
	}
	cfg, err := notify.LoadConfig(path)
	if err != nil {
		return err
	}
	var ledger notify.Ledger
	if st != nil {
		ledger = st
	}
	srv.SetNotifier(notify.New(cfg, ledger))
	return nil
}
