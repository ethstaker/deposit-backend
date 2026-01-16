package beacon

import (
	"bytes"
	"encoding/hex"
	"testing"

	apiv1 "github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
)

func TestAddMissingValidatorDeposits_SingleDeposit(t *testing.T) {
	const pubkeyHex = "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
	const executionAddressHex = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	pubkey, err := hex.DecodeString(pubkeyHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode pubkey: %v", err)
	}

	var withdrawalCreds [32]byte
	executionAddressBytes, err := hex.DecodeString(executionAddressHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode execution address: %v", err)
	}
	copy(withdrawalCreds[12:], executionAddressBytes)
	withdrawalCreds[0] = 0x02 // Use 0x02 prefix for valid withdrawal credentials

	deposit := &electra.PendingDeposit{
		Pubkey:                phase0.BLSPubKey(pubkey),
		WithdrawalCredentials: withdrawalCreds[:],
	}

	cache := &cacheRecord{
		summaries: make(map[common.Address]ValidatorSummaries),
	}

	addMissingValidatorDeposits([]*electra.PendingDeposit{deposit}, cache)

	executionAddress := common.BytesToAddress(executionAddressBytes)
	summaries, ok := cache.summaries[executionAddress]
	if !ok {
		t.Fatalf("Expected summary to be added to cache")
	}

	if len(summaries) != 1 {
		t.Fatalf("Expected 1 summary, got %d", len(summaries))
	}

	summary := summaries[0]
	if summary.Validator == nil {
		t.Fatalf("Expected validator to be set")
	}

	if !bytes.Equal(summary.Validator.Validator.PublicKey[:], pubkey) {
		t.Fatalf("Expected pubkey to match")
	}

	if len(summary.PendingDeposits) != 1 {
		t.Fatalf("Expected 1 pending deposit, got %d", len(summary.PendingDeposits))
	}

	if !bytes.Equal(summary.PendingDeposits[0].Pubkey[:], pubkey) {
		t.Fatalf("Expected deposit pubkey to match")
	}
}

func TestAddMissingValidatorDeposits_MultipleDepositsSamePubkey(t *testing.T) {
	const pubkeyHex = "0x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222"
	const executionAddressHex = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	pubkey, err := hex.DecodeString(pubkeyHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode pubkey: %v", err)
	}

	var firstWithdrawalCreds [32]byte
	executionAddressBytes, err := hex.DecodeString(executionAddressHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode execution address: %v", err)
	}
	copy(firstWithdrawalCreds[12:], executionAddressBytes)
	firstWithdrawalCreds[0] = 0x02 // Use 0x02 prefix for valid withdrawal credentials

	var secondWithdrawalCreds [32]byte
	copy(secondWithdrawalCreds[12:], executionAddressBytes)
	secondWithdrawalCreds[0] = 0x01 // Different prefix

	var thirdWithdrawalCreds [32]byte
	copy(thirdWithdrawalCreds[12:], executionAddressBytes)
	thirdWithdrawalCreds[0] = 0x02 // Different prefix

	deposits := []*electra.PendingDeposit{
		{
			Pubkey:                phase0.BLSPubKey(pubkey),
			WithdrawalCredentials: firstWithdrawalCreds[:],
		},
		{
			Pubkey:                phase0.BLSPubKey(pubkey),
			WithdrawalCredentials: secondWithdrawalCreds[:],
		},
		{
			Pubkey:                phase0.BLSPubKey(pubkey),
			WithdrawalCredentials: thirdWithdrawalCreds[:],
		},
	}

	cache := &cacheRecord{
		summaries: make(map[common.Address]ValidatorSummaries),
	}

	addMissingValidatorDeposits(deposits, cache)

	executionAddress := common.BytesToAddress(executionAddressBytes)
	summaries, ok := cache.summaries[executionAddress]
	if !ok {
		t.Fatalf("Expected summary to be added to cache")
	}

	if len(summaries) != 1 {
		t.Fatalf("Expected 1 summary, got %d", len(summaries))
	}

	summary := summaries[0]
	if len(summary.PendingDeposits) != 3 {
		t.Fatalf("Expected 3 pending deposits, got %d", len(summary.PendingDeposits))
	}

	// Verify that the validator uses the first deposit's withdrawal credentials
	if !bytes.Equal(summary.Validator.Validator.WithdrawalCredentials[:], firstWithdrawalCreds[:]) {
		t.Fatalf("Expected validator to use first deposit's withdrawal credentials")
	}

	// Verify all deposits are present
	if !bytes.Equal(summary.PendingDeposits[0].WithdrawalCredentials[:], firstWithdrawalCreds[:]) {
		t.Fatalf("Expected first deposit to have first withdrawal credentials")
	}
	if !bytes.Equal(summary.PendingDeposits[1].WithdrawalCredentials[:], secondWithdrawalCreds[:]) {
		t.Fatalf("Expected second deposit to have second withdrawal credentials")
	}
	if !bytes.Equal(summary.PendingDeposits[2].WithdrawalCredentials[:], thirdWithdrawalCreds[:]) {
		t.Fatalf("Expected third deposit to have third withdrawal credentials")
	}
}

func TestAddMissingValidatorDeposits_MultipleDepositsDifferentPubkeys(t *testing.T) {
	const pubkey1Hex = "0x333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333"
	const pubkey2Hex = "0x444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444"
	const executionAddress1Hex = "0xcccccccccccccccccccccccccccccccccccccccc"
	const executionAddress2Hex = "0xdddddddddddddddddddddddddddddddddddddddd"

	pubkey1, err := hex.DecodeString(pubkey1Hex[2:])
	if err != nil {
		t.Fatalf("Failed to decode pubkey1: %v", err)
	}

	pubkey2, err := hex.DecodeString(pubkey2Hex[2:])
	if err != nil {
		t.Fatalf("Failed to decode pubkey2: %v", err)
	}

	var withdrawalCreds1 [32]byte
	executionAddress1Bytes, err := hex.DecodeString(executionAddress1Hex[2:])
	if err != nil {
		t.Fatalf("Failed to decode execution address 1: %v", err)
	}
	copy(withdrawalCreds1[12:], executionAddress1Bytes)
	withdrawalCreds1[0] = 0x02 // Use 0x02 prefix for valid withdrawal credentials

	var withdrawalCreds2 [32]byte
	executionAddress2Bytes, err := hex.DecodeString(executionAddress2Hex[2:])
	if err != nil {
		t.Fatalf("Failed to decode execution address 2: %v", err)
	}
	copy(withdrawalCreds2[12:], executionAddress2Bytes)
	withdrawalCreds2[0] = 0x02 // Use 0x02 prefix for valid withdrawal credentials

	deposits := []*electra.PendingDeposit{
		{
			Pubkey:                phase0.BLSPubKey(pubkey1),
			WithdrawalCredentials: withdrawalCreds1[:],
		},
		{
			Pubkey:                phase0.BLSPubKey(pubkey2),
			WithdrawalCredentials: withdrawalCreds2[:],
		},
	}

	cache := &cacheRecord{
		summaries: make(map[common.Address]ValidatorSummaries),
	}

	addMissingValidatorDeposits(deposits, cache)

	executionAddress1 := common.BytesToAddress(executionAddress1Bytes)
	executionAddress2 := common.BytesToAddress(executionAddress2Bytes)

	summaries1, ok1 := cache.summaries[executionAddress1]
	if !ok1 {
		t.Fatalf("Expected summary 1 to be added to cache")
	}

	summaries2, ok2 := cache.summaries[executionAddress2]
	if !ok2 {
		t.Fatalf("Expected summary 2 to be added to cache")
	}

	if len(summaries1) != 1 {
		t.Fatalf("Expected 1 summary for address 1, got %d", len(summaries1))
	}

	if len(summaries2) != 1 {
		t.Fatalf("Expected 1 summary for address 2, got %d", len(summaries2))
	}

	if !bytes.Equal(summaries1[0].Validator.Validator.PublicKey[:], pubkey1) {
		t.Fatalf("Expected summary 1 to have pubkey1")
	}

	if !bytes.Equal(summaries2[0].Validator.Validator.PublicKey[:], pubkey2) {
		t.Fatalf("Expected summary 2 to have pubkey2")
	}
}

func TestAddMissingValidatorDeposits_IgnoresExistingValidators(t *testing.T) {
	const pubkeyHex = "0x555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555"
	const executionAddressHex = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

	pubkey, err := hex.DecodeString(pubkeyHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode pubkey: %v", err)
	}

	var withdrawalCreds [32]byte
	executionAddressBytes, err := hex.DecodeString(executionAddressHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode execution address: %v", err)
	}
	copy(withdrawalCreds[12:], executionAddressBytes)
	withdrawalCreds[0] = 0x02 // Use 0x02 prefix for valid withdrawal credentials

	// Create an existing validator in the cache
	executionAddress := common.BytesToAddress(executionAddressBytes)
	existingSummary := ValidatorSummary{
		Validator: &apiv1.Validator{
			Validator: &phase0.Validator{
				PublicKey:             phase0.BLSPubKey(pubkey),
				WithdrawalCredentials: withdrawalCreds[:],
			},
		},
	}

	cache := &cacheRecord{
		summaries: map[common.Address]ValidatorSummaries{
			executionAddress: {existingSummary},
		},
	}

	deposit := &electra.PendingDeposit{
		Pubkey:                phase0.BLSPubKey(pubkey),
		WithdrawalCredentials: withdrawalCreds[:],
	}

	addMissingValidatorDeposits([]*electra.PendingDeposit{deposit}, cache)

	// Verify the cache still has only the original summary
	summaries, ok := cache.summaries[executionAddress]
	if !ok {
		t.Fatalf("Expected existing summary to remain in cache")
	}

	if len(summaries) != 1 {
		t.Fatalf("Expected 1 summary, got %d", len(summaries))
	}

	// Verify the summary wasn't modified (no pending deposits added)
	if len(summaries[0].PendingDeposits) != 0 {
		t.Fatalf("Expected no pending deposits in existing summary, got %d", len(summaries[0].PendingDeposits))
	}
}

func TestAddMissingValidatorDeposits_MixedExistingAndMissing(t *testing.T) {
	const existingPubkeyHex = "0x666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666"
	const missingPubkeyHex = "0x777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777777"
	const existingExecutionAddressHex = "0xffffffffffffffffffffffffffffffffffffffff"
	const missingExecutionAddressHex = "0x0000000000000000000000000000000000000000"

	existingPubkey, err := hex.DecodeString(existingPubkeyHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode existing pubkey: %v", err)
	}

	missingPubkey, err := hex.DecodeString(missingPubkeyHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode missing pubkey: %v", err)
	}

	var existingWithdrawalCreds [32]byte
	existingExecutionAddressBytes, err := hex.DecodeString(existingExecutionAddressHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode existing execution address: %v", err)
	}
	copy(existingWithdrawalCreds[12:], existingExecutionAddressBytes)
	existingWithdrawalCreds[0] = 0x02 // Use 0x02 prefix for valid withdrawal credentials

	var missingWithdrawalCreds [32]byte
	missingExecutionAddressBytes, err := hex.DecodeString(missingExecutionAddressHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode missing execution address: %v", err)
	}
	copy(missingWithdrawalCreds[12:], missingExecutionAddressBytes)
	missingWithdrawalCreds[0] = 0x02 // Use 0x02 prefix for valid withdrawal credentials

	// Create an existing validator in the cache
	existingExecutionAddress := common.BytesToAddress(existingExecutionAddressBytes)
	existingSummary := ValidatorSummary{
		Validator: &apiv1.Validator{
			Validator: &phase0.Validator{
				PublicKey:             phase0.BLSPubKey(existingPubkey),
				WithdrawalCredentials: existingWithdrawalCreds[:],
			},
		},
	}

	cache := &cacheRecord{
		summaries: map[common.Address]ValidatorSummaries{
			existingExecutionAddress: {existingSummary},
		},
	}

	deposits := []*electra.PendingDeposit{
		{
			Pubkey:                phase0.BLSPubKey(existingPubkey),
			WithdrawalCredentials: existingWithdrawalCreds[:],
		},
		{
			Pubkey:                phase0.BLSPubKey(missingPubkey),
			WithdrawalCredentials: missingWithdrawalCreds[:],
		},
	}

	addMissingValidatorDeposits(deposits, cache)

	// Verify existing validator is unchanged
	existingSummaries, ok := cache.summaries[existingExecutionAddress]
	if !ok {
		t.Fatalf("Expected existing summary to remain in cache")
	}
	if len(existingSummaries) != 1 {
		t.Fatalf("Expected 1 existing summary, got %d", len(existingSummaries))
	}
	if len(existingSummaries[0].PendingDeposits) != 0 {
		t.Fatalf("Expected no pending deposits in existing summary, got %d", len(existingSummaries[0].PendingDeposits))
	}

	// Verify missing validator was added
	missingExecutionAddress := common.BytesToAddress(missingExecutionAddressBytes)
	missingSummaries, ok := cache.summaries[missingExecutionAddress]
	if !ok {
		t.Fatalf("Expected missing summary to be added to cache")
	}
	if len(missingSummaries) != 1 {
		t.Fatalf("Expected 1 missing summary, got %d", len(missingSummaries))
	}
	if !bytes.Equal(missingSummaries[0].Validator.Validator.PublicKey[:], missingPubkey) {
		t.Fatalf("Expected missing summary to have missing pubkey")
	}
	if len(missingSummaries[0].PendingDeposits) != 1 {
		t.Fatalf("Expected 1 pending deposit in missing summary, got %d", len(missingSummaries[0].PendingDeposits))
	}
}

func TestAddMissingValidatorDeposits_Ignores0x00PrefixedDeposits(t *testing.T) {
	const pubkeyHex = "0x888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888"
	const executionAddressHex = "0x9999999999999999999999999999999999999999"

	pubkey, err := hex.DecodeString(pubkeyHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode pubkey: %v", err)
	}

	var firstWithdrawalCreds [32]byte
	executionAddressBytes, err := hex.DecodeString(executionAddressHex[2:])
	if err != nil {
		t.Fatalf("Failed to decode execution address: %v", err)
	}
	copy(firstWithdrawalCreds[12:], executionAddressBytes)
	firstWithdrawalCreds[0] = 0x00 // First deposit has 0x00 prefix - should be ignored

	var secondWithdrawalCreds [32]byte
	copy(secondWithdrawalCreds[12:], executionAddressBytes)
	secondWithdrawalCreds[0] = 0x01 // Second deposit has 0x01 prefix

	var thirdWithdrawalCreds [32]byte
	copy(thirdWithdrawalCreds[12:], executionAddressBytes)
	thirdWithdrawalCreds[0] = 0x02 // Third deposit has 0x02 prefix

	deposits := []*electra.PendingDeposit{
		{
			Pubkey:                phase0.BLSPubKey(pubkey),
			WithdrawalCredentials: firstWithdrawalCreds[:], // First deposit with 0x00 prefix
		},
		{
			Pubkey:                phase0.BLSPubKey(pubkey),
			WithdrawalCredentials: secondWithdrawalCreds[:], // Second deposit with 0x01 prefix
		},
		{
			Pubkey:                phase0.BLSPubKey(pubkey),
			WithdrawalCredentials: thirdWithdrawalCreds[:], // Third deposit with 0x02 prefix
		},
	}

	cache := &cacheRecord{
		summaries: make(map[common.Address]ValidatorSummaries),
	}

	addMissingValidatorDeposits(deposits, cache)

	// Verify that nothing was added to the cache because the first deposit has 0x00 prefix
	executionAddress := common.BytesToAddress(executionAddressBytes)
	summaries, ok := cache.summaries[executionAddress]
	if ok {
		t.Fatalf("Expected no summary to be added to cache (0x00 prefix should be ignored), but got %d summaries", len(summaries))
	}

	// Verify the cache is empty
	if len(cache.summaries) != 0 {
		t.Fatalf("Expected empty cache, got %d entries", len(cache.summaries))
	}
}

func TestAddMissingValidatorDeposits_Ignores0x00PrefixedDepositsWithDifferentPubkeys(t *testing.T) {
	const pubkey1Hex = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const pubkey2Hex = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const executionAddress1Hex = "0x1111111111111111111111111111111111111111"
	const executionAddress2Hex = "0x2222222222222222222222222222222222222222"

	pubkey1, err := hex.DecodeString(pubkey1Hex[2:])
	if err != nil {
		t.Fatalf("Failed to decode pubkey1: %v", err)
	}

	pubkey2, err := hex.DecodeString(pubkey2Hex[2:])
	if err != nil {
		t.Fatalf("Failed to decode pubkey2: %v", err)
	}

	var withdrawalCreds1 [32]byte
	executionAddress1Bytes, err := hex.DecodeString(executionAddress1Hex[2:])
	if err != nil {
		t.Fatalf("Failed to decode execution address 1: %v", err)
	}
	copy(withdrawalCreds1[12:], executionAddress1Bytes)
	withdrawalCreds1[0] = 0x00 // 0x00 prefix - should be ignored

	var withdrawalCreds2 [32]byte
	executionAddress2Bytes, err := hex.DecodeString(executionAddress2Hex[2:])
	if err != nil {
		t.Fatalf("Failed to decode execution address 2: %v", err)
	}
	copy(withdrawalCreds2[12:], executionAddress2Bytes)
	withdrawalCreds2[0] = 0x02 // 0x02 prefix - should be added

	deposits := []*electra.PendingDeposit{
		{
			Pubkey:                phase0.BLSPubKey(pubkey1),
			WithdrawalCredentials: withdrawalCreds1[:], // 0x00 prefix - should be ignored
		},
		{
			Pubkey:                phase0.BLSPubKey(pubkey2),
			WithdrawalCredentials: withdrawalCreds2[:], // 0x02 prefix - should be added
		},
	}

	cache := &cacheRecord{
		summaries: make(map[common.Address]ValidatorSummaries),
	}

	addMissingValidatorDeposits(deposits, cache)

	// Verify that pubkey1 (0x00 prefix) was not added
	executionAddress1 := common.BytesToAddress(executionAddress1Bytes)
	_, ok1 := cache.summaries[executionAddress1]
	if ok1 {
		t.Fatalf("Expected pubkey1 summary to be ignored (0x00 prefix), but it was added")
	}

	// Verify that pubkey2 (0x02 prefix) was added
	executionAddress2 := common.BytesToAddress(executionAddress2Bytes)
	summaries2, ok2 := cache.summaries[executionAddress2]
	if !ok2 {
		t.Fatalf("Expected pubkey2 summary to be added to cache")
	}

	if len(summaries2) != 1 {
		t.Fatalf("Expected 1 summary for pubkey2, got %d", len(summaries2))
	}

	var expectedPubkey2 phase0.BLSPubKey
	copy(expectedPubkey2[:], pubkey2)
	if summaries2[0].Validator.Validator.PublicKey != expectedPubkey2 {
		t.Fatalf("Expected summary 2 to have pubkey2, got %x, expected %x", summaries2[0].Validator.Validator.PublicKey, expectedPubkey2)
	}
}
