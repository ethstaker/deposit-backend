package service

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/EthStaker/deposit-backend/beacon"
	"github.com/EthStaker/deposit-backend/service/test"
	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

const validPubkey = "0x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
const validPubkey2 = "0x333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"
const validPubkey3 = "0x444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444"
const validExecutionAddress = "0x1111111111111111111111111111111111111111"
const validExecutionAddress2 = "0x2222222222222222222222222222222222222222"

type testLogger struct {
	t *testing.T
}

func newTestLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(&testLogger{t: t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func (l *testLogger) Write(p []byte) (n int, err error) {
	if l.t.Context().Err() != nil {
		return
	}
	l.t.Log(string(p))
	return len(p), nil
}

var testMockBeacon *test.MockBeacon

func init() {
	pubkey, err := hex.DecodeString(validPubkey[2:])
	if err != nil {
		panic(err)
	}
	pubkey2, err := hex.DecodeString(validPubkey2[2:])
	if err != nil {
		panic(err)
	}
	pubkey3, err := hex.DecodeString(validPubkey3[2:])
	if err != nil {
		panic(err)
	}
	var withdrawalCreds [32]byte
	validExecutionAddressBytes, err := hex.DecodeString(validExecutionAddress[2:])
	if err != nil {
		panic(err)
	}
	copy(withdrawalCreds[12:], validExecutionAddressBytes)
	var withdrawalCreds2 [32]byte
	validExecutionAddressBytes2, err := hex.DecodeString(validExecutionAddress2[2:])
	if err != nil {
		panic(err)
	}
	copy(withdrawalCreds2[12:], validExecutionAddressBytes2)
	var executionAddress bellatrix.ExecutionAddress
	copy(executionAddress[:], validExecutionAddressBytes)
	var executionAddress2 bellatrix.ExecutionAddress
	copy(executionAddress2[:], validExecutionAddressBytes2)
	testMockBeacon = &test.MockBeacon{
		MockHead: beacon.HeadInfo{Slot: 12800},
		MockValidators: map[phase0.BLSPubKey]*apiv1.Validator{
			phase0.BLSPubKey(pubkey): {
				Index:   1,
				Balance: 1000000000000000000,
				Status:  apiv1.ValidatorStateActiveOngoing,
				Validator: &phase0.Validator{
					PublicKey:             phase0.BLSPubKey(pubkey),
					WithdrawalCredentials: withdrawalCreds[:],
				},
			},
			phase0.BLSPubKey(pubkey2): {
				Index:   2,
				Balance: 1000000000000000000,
				Status:  apiv1.ValidatorStateActiveOngoing,
				Validator: &phase0.Validator{
					PublicKey:             phase0.BLSPubKey(pubkey2),
					WithdrawalCredentials: withdrawalCreds[:],
				},
			},
			phase0.BLSPubKey(pubkey3): {
				Index:   3,
				Balance: 1000000000000000000,
				Status:  apiv1.ValidatorStateActiveOngoing,
				Validator: &phase0.Validator{
					PublicKey:             phase0.BLSPubKey(pubkey3),
					WithdrawalCredentials: withdrawalCreds2[:],
				},
			},
		},
		PendingConsolidations: []*electra.PendingConsolidation{
			{
				SourceIndex: 1,
				TargetIndex: 2,
			},
		},
		PendingDeposits: []*electra.PendingDeposit{
			{
				Pubkey:                phase0.BLSPubKey(pubkey),
				WithdrawalCredentials: withdrawalCreds[:],
			},
		},
		PendingPartialWithdrawals: []*electra.PendingPartialWithdrawal{
			{
				ValidatorIndex: 1,
			},
		},
		MockBuilders: map[phase0.BLSPubKey]*beacon.BuilderResponse{
			phase0.BLSPubKey(pubkey): {
				Index:  1,
				Status: "active",
				Builder: &gloas.Builder{
					PublicKey:        phase0.BLSPubKey(pubkey),
					ExecutionAddress: executionAddress,
				},
			},
			phase0.BLSPubKey(pubkey2): {
				Index:  2,
				Status: "active",
				Builder: &gloas.Builder{
					PublicKey:        phase0.BLSPubKey(pubkey2),
					ExecutionAddress: executionAddress,
				},
			},
			phase0.BLSPubKey(pubkey3): {
				Index:  3,
				Status: "active",
				Builder: &gloas.Builder{
					PublicKey:        phase0.BLSPubKey(pubkey3),
					ExecutionAddress: executionAddress2,
				},
			},
		},
		BuilderPendingPayments: []*gloas.BuilderPendingPayment{
			{
				Weight:        1,
				ProposerIndex: 1,
				Withdrawal: &gloas.BuilderPendingWithdrawal{
					BuilderIndex: 1,
				},
			},
			{
				Weight:        2,
				ProposerIndex: 2,
				Withdrawal: &gloas.BuilderPendingWithdrawal{
					BuilderIndex: 2,
				},
			},
		},
		BuilderPendingWithdrawals: []*gloas.BuilderPendingWithdrawal{
			{
				BuilderIndex: 1,
			},
		},
	}
}

func TestValidatorHandlerErrors(t *testing.T) {
	beacon := &test.MockBeacon{}
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   beacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	// The server should be responsive
	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	// Missing public key should produce an error and 404
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validator/")
	if err != nil {
		t.Fatalf("Failed to get validator: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected status NotFound, got %d", resp.StatusCode)
	}

	// Missing the 0x prefix should produce an error and 400
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validator/0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Failed to get validator: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	// Invalid hex should produce an error and 400
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validator/0xgg")
	if err != nil {
		t.Fatalf("Failed to get validator: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	// Invalid length should produce an error and 400
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validator/0xaa")
	if err != nil {
		t.Fatalf("Failed to get validator: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	// Valid hex should 404 since there are no validators in the mock
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validator/" + validPubkey)
	if err != nil {
		t.Fatalf("Failed to get validator: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected status NotFound, got %d", resp.StatusCode)
	}
}

func TestValidatorHandler(t *testing.T) {
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   testMockBeacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	// The server should be responsive
	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	// The validator should be found
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validator/" + validPubkey)
	if err != nil {
		t.Fatalf("Failed to get validator: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	// Make sure it can be parsed by attestantio's go-eth2-client
	var validator apiv1.Validator
	if err := json.NewDecoder(resp.Body).Decode(&validator); err != nil {
		t.Fatalf("Failed to decode validator: %v", err)
	}
	t.Logf("Round-tripped validator: %+v", validator)
}

func TestValidatorsHandlerErrors(t *testing.T) {
	beacon := &test.MockBeacon{}
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   beacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	// The server should be responsive
	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	// Missing execution address should produce an error and 404
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validators/")
	if err != nil {
		t.Fatalf("Failed to get validators: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected status NotFound, got %d", resp.StatusCode)
	}

	// Missing the 0x prefix should produce an error and 400
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validators/0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Failed to get validators: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	// Invalid execution address should produce an error and 400
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validators/0xgg")
	if err != nil {
		t.Fatalf("Failed to get validators: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	// Invalid length should produce an error and 400
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validators/0xaa")
	if err != nil {
		t.Fatalf("Failed to get validators: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	// Valid execution address should 404 since there are no validators in the mock
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validators/" + validExecutionAddress)
	if err != nil {
		t.Fatalf("Failed to get validators: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected status NotFound, got %d", resp.StatusCode)
	}
}

func TestValidatorsHandler(t *testing.T) {
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   testMockBeacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	// The server should be responsive
	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	// Query the validators by the execution address
	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/validators/" + validExecutionAddress)
	if err != nil {
		t.Fatalf("Failed to get validators: %v", err)
	}
	defer resp.Body.Close()

	// Parse the response
	var responseValidators beacon.ValidatorSummaries
	if err := json.NewDecoder(resp.Body).Decode(&responseValidators); err != nil {
		t.Fatalf("Failed to decode validators: %v", err)
	}

	t.Logf("Response validators: %+v", responseValidators)

	sort.Slice(responseValidators, func(i, j int) bool {
		return responseValidators[i].Validator.Index < responseValidators[j].Validator.Index
	})

	// Make sure the response is correct
	if len(responseValidators) != 2 {
		t.Fatalf("Expected 2 validators, got %d", len(responseValidators))
	}

	if len(responseValidators[0].PendingConsolidations) != 1 {
		t.Fatalf("Expected 1 pending consolidation, got %d", len(responseValidators[0].PendingConsolidations))
	}

	if len(responseValidators[0].PendingDeposits) != 1 {
		t.Fatalf("Expected 1 pending deposit, got %d", len(responseValidators[0].PendingDeposits))
	}

	if len(responseValidators[0].PendingPartialWithdrawals) != 1 {
		t.Fatalf("Expected 1 pending partial withdrawal, got %d", len(responseValidators[0].PendingPartialWithdrawals))
	}

	if len(responseValidators[1].PendingConsolidations) != 1 {
		t.Fatalf("Expected 1 pending consolidations, got %d", len(responseValidators[1].PendingConsolidations))
	}

	if len(responseValidators[1].PendingDeposits) != 0 {
		t.Fatalf("Expected 0 pending deposits, got %d", len(responseValidators[1].PendingDeposits))
	}

	if len(responseValidators[1].PendingPartialWithdrawals) != 0 {
		t.Fatalf("Expected 0 pending partial withdrawals, got %d", len(responseValidators[1].PendingPartialWithdrawals))
	}
}

func TestBuilderHandlerErrors(t *testing.T) {
	beacon := &test.MockBeacon{}
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   beacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builder/")
	if err != nil {
		t.Fatalf("Failed to get builder: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected status NotFound, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builder/0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Failed to get builder: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builder/0xgg")
	if err != nil {
		t.Fatalf("Failed to get builder: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builder/0xaa")
	if err != nil {
		t.Fatalf("Failed to get builder: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builder/" + validPubkey)
	if err != nil {
		t.Fatalf("Failed to get builder: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected status NotFound, got %d", resp.StatusCode)
	}
}

func TestBuilderHandler(t *testing.T) {
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   testMockBeacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builder/" + validPubkey)
	if err != nil {
		t.Fatalf("Failed to get builder: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	var builder beacon.BuilderResponse
	if err := json.NewDecoder(resp.Body).Decode(&builder); err != nil {
		t.Fatalf("Failed to decode builder: %v", err)
	}

	if builder.Index != 1 {
		t.Fatalf("Expected builder index 1, got %d", builder.Index)
	}
	if builder.Status != "active" {
		t.Fatalf("Expected builder status active, got %s", builder.Status)
	}
}

func TestBuildersHandlerErrors(t *testing.T) {
	beacon := &test.MockBeacon{}
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   beacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builders/")
	if err != nil {
		t.Fatalf("Failed to get builders: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected status NotFound, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builders/0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("Failed to get builders: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builders/0xgg")
	if err != nil {
		t.Fatalf("Failed to get builders: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builders/0xaa")
	if err != nil {
		t.Fatalf("Failed to get builders: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builders/" + validExecutionAddress)
	if err != nil {
		t.Fatalf("Failed to get builders: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected status NotFound, got %d", resp.StatusCode)
	}
}

func TestBuildersHandler(t *testing.T) {
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   testMockBeacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/health")
	if err != nil {
		t.Fatalf("Failed to get health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/builders/" + validExecutionAddress)
	if err != nil {
		t.Fatalf("Failed to get builders: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	var responseBuilders beacon.BuilderSummaries
	if err := json.NewDecoder(resp.Body).Decode(&responseBuilders); err != nil {
		t.Fatalf("Failed to decode builders: %v", err)
	}

	sort.Slice(responseBuilders, func(i, j int) bool {
		return bytes.Compare(responseBuilders[i].Builder.PublicKey[:], responseBuilders[j].Builder.PublicKey[:]) < 0
	})

	if len(responseBuilders) != 2 {
		t.Fatalf("Expected 2 builders, got %d", len(responseBuilders))
	}

	if len(responseBuilders[0].PendingPayments) != 1 {
		t.Fatalf("Expected 1 pending payment, got %d", len(responseBuilders[0].PendingPayments))
	}

	if len(responseBuilders[0].PendingWithdrawals) != 1 {
		t.Fatalf("Expected 1 pending withdrawal, got %d", len(responseBuilders[0].PendingWithdrawals))
	}

	if len(responseBuilders[1].PendingPayments) != 1 {
		t.Fatalf("Expected 1 pending payment, got %d", len(responseBuilders[1].PendingPayments))
	}

	if len(responseBuilders[1].PendingWithdrawals) != 0 {
		t.Fatalf("Expected 0 pending withdrawals, got %d", len(responseBuilders[1].PendingWithdrawals))
	}
}

func TestAddressHandler(t *testing.T) {
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   testMockBeacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/address/0x3333333333333333333333333333333333333333")
	if err != nil {
		t.Fatalf("Failed to get address: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Expected status NotFound, got %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/address/" + validExecutionAddress)
	if err != nil {
		t.Fatalf("Failed to get address: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	var response struct {
		Builders   beacon.BuilderSummaries   `json:"builders"`
		Validators beacon.ValidatorSummaries `json:"validators"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode address response: %v", err)
	}

	if len(response.Builders) != 2 {
		t.Fatalf("Expected 2 builders, got %d", len(response.Builders))
	}
	if len(response.Validators) != 2 {
		t.Fatalf("Expected 2 validators, got %d", len(response.Validators))
	}
}

func TestHeadHandler(t *testing.T) {
	svc := Service{
		Context:  t.Context(),
		Logger:   newTestLogger(t),
		Beacon:   testMockBeacon,
		Listener: httptest.NewUnstartedServer(nil).Listener,
		Port:     0,
	}

	go func() {
		if err := svc.Run(); err != nil {
			panic(err)
		}
	}()

	resp, err := http.Get("http://" + svc.Listener.Addr().String() + "/api/v1/head")
	if err != nil {
		t.Fatalf("Failed to get head: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK, got %d", resp.StatusCode)
	}

	var head beacon.HeadInfo
	if err := json.NewDecoder(resp.Body).Decode(&head); err != nil {
		t.Fatalf("Failed to decode head: %v", err)
	}

	if head.Slot != testMockBeacon.MockHead.Slot {
		t.Fatalf("Expected slot %d, got %d", testMockBeacon.MockHead.Slot, head.Slot)
	}
}
