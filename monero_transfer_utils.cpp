//
//  monero_transfer_utils.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 12/2/17.
//  Copyright © 2018 MyMonero. All rights reserved.
//
//
#include <random>
//
#include "monero_transfer_utils.hpp"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "monero_transfer_utils.hpp"
#include "include_base_utils.h"
#include "monero_fork_rules.hpp"
#include "misc_log_ex.h"
//#include "common/apply_permutation.h"
#include "wallet_errors.h"
//
using namespace std;
using namespace crypto;
using namespace epee;
using namespace cryptonote;
using namespace tools; // for error::
using namespace monero_transfer_utils;
using namespace monero_fork_rules;
//
uint64_t monero_transfer_utils::get_fee_multiplier(
	uint32_t priority,
	uint32_t default_priority,
	int fee_algorithm,
	use_fork_rules_fn_type use_fork_rules_fn
) {
	static const uint64_t old_multipliers[3] = {1, 2, 3};
	static const uint64_t new_multipliers[3] = {1, 20, 166};
	static const uint64_t newer_multipliers[4] = {1, 4, 20, 166};
	
	if (fee_algorithm == -1)
		fee_algorithm = get_fee_algorithm(use_fork_rules_fn);
	
	// 0 -> default (here, x1 till fee algorithm 2, x4 from it)
	if (priority == 0)
		priority = default_priority;
	if (priority == 0)
	{
		if (fee_algorithm >= 2)
			priority = 2;
		else
			priority = 1;
	}
	
	// 1 to 3/4 are allowed as priorities
	uint32_t max_priority = (fee_algorithm >= 2) ? 4 : 3;
	if (priority >= 1 && priority <= max_priority)
	{
		switch (fee_algorithm)
		{
			case 0: return old_multipliers[priority-1];
			case 1: return new_multipliers[priority-1];
			case 2: return newer_multipliers[priority-1];
			default: THROW_WALLET_EXCEPTION_IF (true, error::invalid_priority);
		}
	}
	
	THROW_WALLET_EXCEPTION_IF (false, error::invalid_priority);
	return 1;
}

int monero_transfer_utils::get_fee_algorithm(use_fork_rules_fn_type use_fork_rules_fn)
{
	// changes at v3 and v5
	if (use_fork_rules_fn(5, 0))
		return 2;
	if (use_fork_rules_fn(3, -720 * 14))
		return 1;
	return 0;
}
//

size_t monero_transfer_utils::estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof)
{
	size_t size = 0;
	
	// tx prefix
	
	// first few bytes
	size += 1 + 6;
	
	// vin
	size += n_inputs * (1+6+(mixin+1)*2+32);
	
	// vout
	size += n_outputs * (6+32);
	
	// extra
	size += extra_size;
	
	// rct signatures
	
	// type
	size += 1;
	
	// rangeSigs
	if (bulletproof)
		size += ((2*6 + 4 + 5)*32 + 3) * n_outputs;
	else
		size += (2*64*32+32+64*32) * n_outputs;
	
	// MGs
	size += n_inputs * (64 * (mixin+1) + 32);
	
	// mixRing - not serialized, can be reconstructed
	/* size += 2 * 32 * (mixin+1) * n_inputs; */
	
	// pseudoOuts
	size += 32 * n_inputs;
	// ecdhInfo
	size += 2 * 32 * n_outputs;
	// outPk - only commitment is saved
	size += 32 * n_outputs;
	// txnFee
	size += 4;
	
	LOG_PRINT_L2("estimated rct tx size for " << n_inputs << " with ring size " << (mixin+1) << " and " << n_outputs << ": " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
	return size;
}
size_t monero_transfer_utils::estimate_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof)
{
	if (use_rct)
		return estimate_rct_tx_size(n_inputs, mixin, n_outputs + 1, extra_size, bulletproof);
	else
		return n_inputs * (mixin+1) * APPROXIMATE_INPUT_BYTES + extra_size;
}
//
uint64_t monero_transfer_utils::calculate_fee(uint64_t fee_per_kb, size_t bytes, uint64_t fee_multiplier)
{
	uint64_t kB = (bytes + 1023) / 1024;
	return kB * fee_per_kb * fee_multiplier;
}
uint64_t monero_transfer_utils::calculate_fee(uint64_t fee_per_kb, const cryptonote::blobdata &blob, uint64_t fee_multiplier)
{
	return calculate_fee(fee_per_kb, blob.size(), fee_multiplier);
}
//
uint32_t monero_transfer_utils::fixed_ringsize()
{
	return 10; // TODO/FIXME: temporary…… for lightwallet code!
}
uint32_t monero_transfer_utils::fixed_mixinsize()
{
	return monero_transfer_utils::fixed_ringsize() - 1;
}

std::string monero_transfer_utils::new_dummy_address_string_for_rct_tx(bool isTestnet)
{
	cryptonote::account_base account;
	account.generate();
	//
	return account.get_public_address_str(isTestnet ? cryptonote::TESTNET : cryptonote::MAINNET);
}
