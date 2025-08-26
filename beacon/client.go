package beacon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	nativehttp "net/http"
	"sync"
	"sync/atomic"
	"time"

	eth2client "github.com/attestantio/go-eth2-client"
	"github.com/attestantio/go-eth2-client/api"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	http "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

type cacheRecord struct {
	slot     phase0.Slot
	birthday time.Time

	summaries map[common.Address]ValidatorSummaries
}

type Client struct {
	logger *slog.Logger
	beacon eth2client.Service

	cancel context.CancelFunc

	updateMutex sync.Mutex
	cache       atomic.Pointer[cacheRecord]
}

var _ BeaconProvider = (*Client)(nil)

func slogToZerologLevel(level slog.Level) zerolog.Level {
	switch level {
	case slog.LevelDebug:
		return zerolog.DebugLevel
	case slog.LevelInfo:
		return zerolog.InfoLevel
	case slog.LevelWarn:
		return zerolog.WarnLevel
	case slog.LevelError:
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

func NewClient(ctx context.Context, logger *slog.Logger, level slog.Level, beaconUrl string) (*Client, error) {
	out := new(Client)

	ctx, cancel := context.WithCancel(ctx)
	client, err := http.New(ctx,
		http.WithAddress(beaconUrl),
		http.WithLogLevel(slogToZerologLevel(level)),
	)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create beacon client: %w", err)
	}

	out.logger = logger
	out.beacon = client
	out.cancel = cancel

	// Prime the cache.
	updateCtx, updateCancel := context.WithTimeout(ctx, 60*time.Second)
	defer updateCancel()
	start := time.Now()
	logger.Debug("priming cache")
	err = out.updateCache(updateCtx, 0)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to prime cache: %w", err)
	}
	logger.Debug("primed cache", "duration", time.Since(start))

	// Subscribe to head events to update the cache.
	err = client.(eth2client.EventsProvider).Events(ctx, &api.EventsOpts{
		HeadHandler: out.handleHeadEvent,
		Topics:      []string{"head"},
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to subscribe to head events: %w", err)
	}
	logger.Debug("subscribed to head events")

	return out, nil
}

func errorIs404(err error) bool {
	var apiErr *api.Error
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == nativehttp.StatusNotFound
	}
	return false
}

func (c *Client) updateCache(ctx context.Context, slot phase0.Slot) error {
	if !c.updateMutex.TryLock() {
		c.logger.Debug("cache update in progress, skipping")
		// If we can't lock, that's fine, something else is in the process of updating the cache.
		return nil
	}
	defer c.updateMutex.Unlock()

	client := c.beacon.(*http.Service)

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(60 * time.Second)
	}
	commonOpts := api.CommonOpts{
		Timeout: time.Until(deadline),
	}

	// Load the current cache record.
	if slot > 0 {
		cache := c.cache.Load()
		if cache != nil && cache.slot >= slot {
			// If the cache is up to date, we can return.
			c.logger.Debug("cache is up to date, skipping")
			return nil
		}
	} else {
		// Get the head slot.
		beaconBlockHeader, err := client.BeaconBlockHeader(ctx, &api.BeaconBlockHeaderOpts{
			Block:  "head",
			Common: commonOpts,
		})
		if err != nil {
			return fmt.Errorf("failed to get beacon block header: %w", err)
		}
		slot = beaconBlockHeader.Data.Header.Message.Slot
	}

	start := time.Now()
	c.logger.Debug("updating cache", "slot", slot)

	var validators map[phase0.ValidatorIndex]*apiv1.Validator
	pendingConsolidations := make(map[phase0.ValidatorIndex][]*electra.PendingConsolidation, 64)
	pendingDeposits := make(map[phase0.BLSPubKey][]*electra.PendingDeposit, 64)
	pendingPartialWithdrawals := make(map[phase0.ValidatorIndex][]*electra.PendingPartialWithdrawal, 64)

	group, wgCtx := errgroup.WithContext(ctx)
	group.Go(func() error {
		validatorsResponse, err := client.Validators(wgCtx, &api.ValidatorsOpts{
			State:  fmt.Sprint(slot),
			Common: commonOpts,
		})
		if err != nil {
			return fmt.Errorf("failed to get validators: %w", err)
		}
		validators = validatorsResponse.Data
		return nil
	})
	group.Go(func() error {
		pendingConsolidationsResponse, err := client.PendingConsolidations(wgCtx, &api.PendingConsolidationsOpts{
			State:  fmt.Sprint(slot),
			Common: commonOpts,
		})
		if err != nil {
			if errorIs404(err) {
				return nil
			}
			return fmt.Errorf("failed to get pending consolidations: %w", err)
		}
		for _, consolidation := range pendingConsolidationsResponse.Data {
			pendingConsolidations[consolidation.SourceIndex] = append(pendingConsolidations[consolidation.SourceIndex], consolidation)
			pendingConsolidations[consolidation.TargetIndex] = append(pendingConsolidations[consolidation.TargetIndex], consolidation)
		}
		return nil
	})
	group.Go(func() error {
		pendingDepositsResponse, err := client.PendingDeposits(wgCtx, &api.PendingDepositsOpts{
			State:  fmt.Sprint(slot),
			Common: commonOpts,
		})
		if err != nil {
			if errorIs404(err) {
				return nil
			}
			return fmt.Errorf("failed to get pending deposits: %w", err)
		}
		for _, deposit := range pendingDepositsResponse.Data {
			pendingDeposits[deposit.Pubkey] = append(pendingDeposits[deposit.Pubkey], deposit)
		}
		return nil
	})
	group.Go(func() error {
		pendingPartialWithdrawalsResponse, err := client.PendingPartialWithdrawals(wgCtx, &api.PendingPartialWithdrawalsOpts{
			State:  fmt.Sprint(slot),
			Common: commonOpts,
		})
		if err != nil {
			if errorIs404(err) {
				return nil
			}
			return fmt.Errorf("failed to get pending partial withdrawals: %w", err)
		}
		for _, partialWithdrawal := range pendingPartialWithdrawalsResponse.Data {
			pendingPartialWithdrawals[partialWithdrawal.ValidatorIndex] = append(pendingPartialWithdrawals[partialWithdrawal.ValidatorIndex], partialWithdrawal)
		}
		return nil
	})
	if err := group.Wait(); err != nil {
		return fmt.Errorf("failed to update cache: %w", err)
	}

	// The rest of the function is pure, so allocate the cache now.

	cache := new(cacheRecord)
	cache.slot = slot
	cache.birthday = time.Now()

	cache.summaries = make(map[common.Address]ValidatorSummaries, len(validators))

	for _, validator := range validators {
		if bytes.HasPrefix(validator.Validator.WithdrawalCredentials, []byte{0x00}) {
			// We can ignore 0x00 validators, since they don't have an execution address.
			continue
		}

		withdrawalAddress := common.BytesToAddress(validator.Validator.WithdrawalCredentials[12:])

		summary := ValidatorSummary{
			Validator:                 validator,
			PendingConsolidations:     pendingConsolidations[validator.Index],
			PendingDeposits:           pendingDeposits[validator.Validator.PublicKey],
			PendingPartialWithdrawals: pendingPartialWithdrawals[validator.Index],
		}

		cache.summaries[withdrawalAddress] = append(cache.summaries[withdrawalAddress], summary)
	}

	c.cache.Store(cache)
	c.logger.Debug("updated cache", "duration", time.Since(start))

	return nil
}

func (c *Client) handleHeadEvent(ctx context.Context, head *apiv1.HeadEvent) {
	c.logger.Debug("head event", "slot", head.Slot)
	c.updateCache(ctx, head.Slot)
}

func (c *Client) Stop() {
	c.cancel()
}

// Simply pass-through for the regular validator query.
func (c *Client) LookupValidator(ctx context.Context, pubkey phase0.BLSPubKey) (*apiv1.Validator, error) {

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(12 * time.Second)
	}
	commonOpts := api.CommonOpts{
		Timeout: time.Until(deadline),
	}
	httpClient := c.beacon.(*http.Service)
	validator, err := httpClient.Validators(ctx, &api.ValidatorsOpts{
		PubKeys: []phase0.BLSPubKey{pubkey},
		State:   "head",
		Common:  commonOpts,
	})
	if err != nil {
		return nil, err
	}
	if len(validator.Data) == 0 {
		return nil, nil
	}
	return validator.Data[0], nil
}

func (c *Client) Validators(ctx context.Context, executionAddress common.Address) (ValidatorSummaries, error) {
	cache := c.cache.Load()
	if cache == nil {
		return nil, fmt.Errorf("cache not initialized")
	}
	return cache.summaries[executionAddress], nil
}
