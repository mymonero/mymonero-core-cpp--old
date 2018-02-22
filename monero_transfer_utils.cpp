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
#include "monero_paymentID_utils.hpp"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "monero_transfer_utils.hpp"
#include "include_base_utils.h"
#include "monero_fork_rules.hpp"
#include "monero_multisig_utils.hpp"
#include "misc_log_ex.h"
#include "common/apply_permutation.h"
#include "wallet_errors.h"
//
using namespace std;
using namespace crypto;
using namespace epee;
using namespace cryptonote;
using namespace tools; // for error::
using namespace monero_transfer_utils;
using namespace monero_fork_rules;
using namespace monero_paymentID_utils;
using namespace monero_multisig_utils;
//
// Shared / Utility
std::string strjoin(const std::vector<size_t> &V, const char *sep)
{
	std::stringstream ss;
	bool first = true;
	for (const auto &v: V)
	{
		if (!first)
			ss << sep;
		ss << std::to_string(v);
		first = false;
	}
	return ss.str();
}
std::string get_size_string(size_t sz)
{
	return std::to_string(sz) + " bytes (" + std::to_string((sz + 1023) / 1024) + " kB)";
}

std::string get_size_string(const cryptonote::blobdata &tx)
{
	return get_size_string(tx.size());
}
//
namespace
{
	template<typename T>
	T pop_index(std::vector<T>& vec, size_t idx)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");
		
		T res = vec[idx];
		if (idx + 1 != vec.size())
		{
			vec[idx] = vec.back();
		}
		vec.resize(vec.size() - 1);
		
		return res;
	}
	
	template<typename T>
	T pop_random_value(std::vector<T>& vec)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		
		size_t idx = crypto::rand<size_t>() % vec.size();
		return pop_index (vec, idx);
	}
	
	template<typename T>
	T pop_back(std::vector<T>& vec)
	{
		CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
		
		T res = vec.back();
		vec.pop_back();
		return res;
	}
	
	template<typename T>
	void pop_if_present(std::vector<T>& vec, T e)
	{
		for (size_t i = 0; i < vec.size(); ++i)
		{
			if (e == vec[i])
			{
				pop_index (vec, i);
				return;
			}
		}
	}
}
bool monero_transfer_utils::create_pending_transactions_3(
	const cryptonote::account_keys &account_keys,
	const std::vector<wallet2::transfer_details> &transfers,
	std::unordered_map<crypto::hash, wallet2::unconfirmed_transfer_details> unconfirmed_txs,
	std::vector<cryptonote::tx_destination_entry> dsts,
	const size_t fake_outs_count,
	const uint64_t fee_per_kb,
	const uint64_t unlock_time,
	uint64_t blockchain_size,
	uint32_t priority,
	uint32_t default_priority,
	const std::vector<uint8_t>& extra,
	uint64_t upper_transaction_size_limit__or_0_for_default,
	//
	uint32_t subaddr_account,
	std::set<uint32_t> subaddr_indices,
	uint64_t unlocked_balance_for_subaddr_index,
	const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses,
	//
	uint32_t min_output_count,
	uint64_t min_output_value,
	//
	uint32_t multisig_threshold,
	std::vector<crypto::public_key> wallet_multisig_signers,
	//
	bool merge_destinations,
	bool trusted_daemon,
	bool is_testnet,
	bool is_wallet_multisig,
	//
	monero_transfer_utils::get_random_outs_fn_type get_random_outs_fn, // this function MUST be synchronous
	use_fork_rules_fn_type use_fork_rules_fn,
	//
	CreatePendingTx_RetVals &retVals
) {
	retVals = {};
	//
	std::vector<std::pair<uint32_t, std::vector<size_t>>> unused_transfers_indices_per_subaddr;
	std::vector<std::pair<uint32_t, std::vector<size_t>>> unused_dust_indices_per_subaddr;
	uint64_t needed_money;
	uint64_t accumulated_fee, accumulated_outputs, accumulated_change;
	struct TX {
		std::vector<size_t> selected_transfers;
		std::vector<cryptonote::tx_destination_entry> dsts;
		cryptonote::transaction tx;
		wallet2::pending_tx ptx;
		size_t bytes;
		
		void add(const account_public_address &addr, bool is_subaddress, uint64_t amount, unsigned int original_output_index, bool merge_destinations) {
			if (merge_destinations)
			{
				std::vector<cryptonote::tx_destination_entry>::iterator i;
				i = std::find_if(dsts.begin(), dsts.end(), [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &addr, sizeof(addr)); });
				if (i == dsts.end())
				{
					dsts.push_back(tx_destination_entry(0,addr,is_subaddress));
					i = dsts.end() - 1;
				}
				i->amount += amount;
			}
			else
			{
				THROW_WALLET_EXCEPTION_IF(original_output_index > dsts.size(), error::wallet_internal_error,
										  std::string("original_output_index too large: ") + std::to_string(original_output_index) + " > " + std::to_string(dsts.size()));
				if (original_output_index == dsts.size())
					dsts.push_back(tx_destination_entry(0,addr,is_subaddress));
				THROW_WALLET_EXCEPTION_IF(memcmp(&dsts[original_output_index].addr, &addr, sizeof(addr)), error::wallet_internal_error, "Mismatched destination address");
				dsts[original_output_index].amount += amount;
			}
		}
	};
	std::vector<TX> txes;
	bool adding_fee; // true if new outputs go towards fee, rather than destinations
	uint64_t needed_fee, available_for_fee = 0;
	uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit(upper_transaction_size_limit__or_0_for_default, use_fork_rules_fn);
	const bool use_rct = use_fork_rules_fn(4, 0);
	const bool bulletproof = use_fork_rules_fn(get_bulletproof_fork(is_testnet), 0);
	
	const uint64_t fee_multiplier = get_fee_multiplier(priority, default_priority, get_fee_algorithm(use_fork_rules_fn), use_fork_rules_fn);
	
	// throw if attempting a transaction with no destinations
	THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);
	
	// calculate total amount being sent to all destinations
	// throw if total amount overflows uint64_t
	needed_money = 0;
	for(auto& dt: dsts)
	{
		THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_destination);
		needed_money += dt.amount;
		LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
		THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, 0, is_testnet);
	}
	
	// throw if attempting a transaction with no money
	THROW_WALLET_EXCEPTION_IF(needed_money == 0, error::zero_destination);
	
	std::map<uint32_t, uint64_t> unlocked_balance_per_subaddr = unlocked_balance_per_subaddress(transfers, subaddr_account, blockchain_size, is_testnet);
	std::map<uint32_t, uint64_t> balance_per_subaddr = balance_per_subaddress(transfers, unconfirmed_txs, is_testnet);
	
	if (subaddr_indices.empty()) // "index=<N1>[,<N2>,...]" wasn't specified -> use all the indices with non-zero unlocked balance
	{
		for (const auto& i : balance_per_subaddr)
			subaddr_indices.insert(i.first);
	}
	
	// early out if we know we can't make it anyway
	// we could also check for being within FEE_PER_KB, but if the fee calculation
	// ever changes, this might be missed, so let this go through
	uint64_t balance_subtotal = 0;
	uint64_t unlocked_balance_subtotal = 0;
	for (uint32_t index_minor : subaddr_indices)
	{
		balance_subtotal += balance_per_subaddr[index_minor];
		unlocked_balance_subtotal += unlocked_balance_per_subaddr[index_minor];
	}
	if (needed_money > balance_subtotal) {
		retVals.did_error = true;
		retVals.err_string = "Insufficient funds";
		// TODO: return these error::not_enough_money, balance_subtotal, needed_money, 0
		return false;
	}
	// first check overall balance is enough, then unlocked one, so we throw distinct exceptions
	THROW_WALLET_EXCEPTION_IF(needed_money > unlocked_balance_subtotal, error::not_enough_unlocked_money,
							  unlocked_balance_subtotal, needed_money, 0);
	
	for (uint32_t i : subaddr_indices)
		LOG_PRINT_L2("Candidate subaddress index for spending: " << i);
	
	// gather all dust and non-dust outputs belonging to specified subaddresses
	size_t num_nondust_outputs = 0;
	size_t num_dust_outputs = 0;
	for (size_t i = 0; i < transfers.size(); ++i)
	{
		const wallet2::transfer_details& td = transfers[i];
		if (!td.m_spent && !td.m_key_image_partial && (use_rct ? true : !td.is_rct()) && is_transfer_unlocked(td, blockchain_size, is_testnet) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
		{
			const uint32_t index_minor = td.m_subaddr_index.minor;
			auto find_predicate = [&index_minor](const std::pair<uint32_t, std::vector<size_t>>& x) { return x.first == index_minor; };
			if ((td.is_rct()) || is_valid_decomposed_amount(td.amount()))
			{
				auto found = std::find_if(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), find_predicate);
				if (found == unused_transfers_indices_per_subaddr.end())
				{
					unused_transfers_indices_per_subaddr.push_back({index_minor, {i}});
				}
				else
				{
					found->second.push_back(i);
				}
				++num_nondust_outputs;
			}
			else
			{
				auto found = std::find_if(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), find_predicate);
				if (found == unused_dust_indices_per_subaddr.end())
				{
					unused_dust_indices_per_subaddr.push_back({index_minor, {i}});
				}
				else
				{
					found->second.push_back(i);
				}
				++num_dust_outputs;
			}
		}
	}
	
	// shuffle & sort output indices
	{
		std::random_device rd;
		std::mt19937 g(rd());
		std::shuffle(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), g);
		std::shuffle(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), g);
		auto sort_predicate = [&unlocked_balance_per_subaddr] (const std::pair<uint32_t, std::vector<size_t>>& x, const std::pair<uint32_t, std::vector<size_t>>& y)
		{
			return unlocked_balance_per_subaddr[x.first] > unlocked_balance_per_subaddr[y.first];
		};
		std::sort(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), sort_predicate);
		std::sort(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), sort_predicate);
	}
	
	LOG_PRINT_L2("Starting with " << num_nondust_outputs << " non-dust outputs and " << num_dust_outputs << " dust outputs");
	
	if (unused_dust_indices_per_subaddr.empty() && unused_transfers_indices_per_subaddr.empty()) {
		retVals.pending_txs = std::vector<wallet2::pending_tx>();
		return true;
	}
	
	// if empty, put dummy entry so that the front can be referenced later in the loop
	if (unused_dust_indices_per_subaddr.empty())
		unused_dust_indices_per_subaddr.push_back({});
	if (unused_transfers_indices_per_subaddr.empty())
		unused_transfers_indices_per_subaddr.push_back({});
	
	// start with an empty tx
	txes.push_back(TX());
	accumulated_fee = 0;
	accumulated_outputs = 0;
	accumulated_change = 0;
	adding_fee = false;
	needed_fee = 0;
	std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;
	
	// for rct, since we don't see the amounts, we will try to make all transactions
	// look the same, with 1 or 2 inputs, and 2 outputs. One input is preferable, as
	// this prevents linking to another by provenance analysis, but two is ok if we
	// try to pick outputs not from the same block. We will get two outputs, one for
	// the destination, and one for change.
	LOG_PRINT_L2("checking preferred");
	std::vector<size_t> preferred_inputs;
	uint64_t rct_outs_needed = 2 * (fake_outs_count + 1);
	rct_outs_needed += 100; // some fudge factor since we don't know how many are locked
	if (use_rct)
	{
		// this is used to build a tx that's 1 or 2 inputs, and 2 outputs, which
		// will get us a known fee.
		uint64_t estimated_fee = calculate_fee(fee_per_kb, estimate_rct_tx_size(2, fake_outs_count, 2, extra.size(), bulletproof), fee_multiplier);
		preferred_inputs = pick_preferred_rct_inputs(transfers, needed_money + estimated_fee, subaddr_account, subaddr_indices, blockchain_size, is_testnet);
		if (!preferred_inputs.empty())
		{
			string s;
			for (auto i: preferred_inputs) s += boost::lexical_cast<std::string>(i) + " (" + print_money(transfers[i].amount()) + ") ";
			LOG_PRINT_L1("Found prefered rct inputs for rct tx: " << s);
			
			// bring the list of available outputs stored by the same subaddress index to the front of the list
			uint32_t index_minor = transfers[preferred_inputs[0]].m_subaddr_index.minor;
			for (size_t i = 1; i < unused_transfers_indices_per_subaddr.size(); ++i)
			{
				if (unused_transfers_indices_per_subaddr[i].first == index_minor)
				{
					std::swap(unused_transfers_indices_per_subaddr[0], unused_transfers_indices_per_subaddr[i]);
					break;
				}
			}
			for (size_t i = 1; i < unused_dust_indices_per_subaddr.size(); ++i)
			{
				if (unused_dust_indices_per_subaddr[i].first == index_minor)
				{
					std::swap(unused_dust_indices_per_subaddr[0], unused_dust_indices_per_subaddr[i]);
					break;
				}
			}
		}
	}
	LOG_PRINT_L2("done checking preferred");
	
	// while:
	// - we have something to send
	// - or we need to gather more fee
	// - or we have just one input in that tx, which is rct (to try and make all/most rct txes 2/2)
	unsigned int original_output_index = 0;
	std::vector<size_t>* unused_transfers_indices = &unused_transfers_indices_per_subaddr[0].second;
	std::vector<size_t>* unused_dust_indices      = &unused_dust_indices_per_subaddr[0].second;
	while ((!dsts.empty() && dsts[0].amount > 0) || adding_fee || !preferred_inputs.empty() || should_pick_a_second_output(use_rct, transfers, txes.back().selected_transfers.size(), *unused_transfers_indices, *unused_dust_indices)) {
		TX &tx = txes.back();
		
		LOG_PRINT_L2("Start of loop with " << unused_transfers_indices->size() << " " << unused_dust_indices->size());
		LOG_PRINT_L2("unused_transfers_indices: " << strjoin(*unused_transfers_indices, " "));
		LOG_PRINT_L2("unused_dust_indices: " << strjoin(*unused_dust_indices, " "));
		LOG_PRINT_L2("dsts size " << dsts.size() << ", first " << (dsts.empty() ? "-" : cryptonote::print_money(dsts[0].amount)));
		LOG_PRINT_L2("adding_fee " << adding_fee << ", use_rct " << use_rct);
		
		// if we need to spend money and don't have any left, we fail
		if (unused_dust_indices->empty() && unused_transfers_indices->empty()) {
			LOG_PRINT_L2("No more outputs to choose from");
			THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance_for_subaddr_index, needed_money, accumulated_fee + needed_fee);
		}
		
		// get a random unspent output and use it to pay part (or all) of the current destination (and maybe next one, etc)
		// This could be more clever, but maybe at the cost of making probabilistic inferences easier
		size_t idx;
		if (!preferred_inputs.empty()) {
			idx = pop_back(preferred_inputs);
			pop_if_present(*unused_transfers_indices, idx);
			pop_if_present(*unused_dust_indices, idx);
		} else if ((dsts.empty() || dsts[0].amount == 0) && !adding_fee) {
			// the "make rct txes 2/2" case - we pick a small value output to "clean up" the wallet too
			std::vector<size_t> indices = get_only_rct(transfers, *unused_dust_indices, *unused_transfers_indices);
			idx = pop_best_value_from(transfers, indices, tx.selected_transfers, true);
			
			// we might not want to add it if it's a large output and we don't have many left
			if (transfers[idx].amount() >= min_output_value) {
				if (get_count_above(transfers, *unused_transfers_indices, min_output_value) < min_output_count) {
					LOG_PRINT_L2("Second output was not strictly needed, and we're running out of outputs above " << print_money(min_output_value) << ", not adding");
					break;
				}
			}
			
			// since we're trying to add a second output which is not strictly needed,
			// we only add it if it's unrelated enough to the first one
			float relatedness = get_output_relatedness(transfers[idx], transfers[tx.selected_transfers.front()]);
			if (relatedness > SECOND_OUTPUT_RELATEDNESS_THRESHOLD)
			{
				LOG_PRINT_L2("Second output was not strictly needed, and relatedness " << relatedness << ", not adding");
				break;
			}
			pop_if_present(*unused_transfers_indices, idx);
			pop_if_present(*unused_dust_indices, idx);
		} else
			idx = pop_best_value_from(transfers, unused_transfers_indices->empty() ? *unused_dust_indices : *unused_transfers_indices, tx.selected_transfers);
		
		const wallet2::transfer_details &td = transfers[idx];
		LOG_PRINT_L2("Picking output " << idx << ", amount " << print_money(td.amount()) << ", ki " << td.m_key_image);
		
		// add this output to the list to spend
		tx.selected_transfers.push_back(idx);
		uint64_t available_amount = td.amount();
		accumulated_outputs += available_amount;
		
		// clear any fake outs we'd already gathered, since we'll need a new set
		outs.clear();
		
		if (adding_fee)
		{
			LOG_PRINT_L2("We need more fee, adding it to fee");
			available_for_fee += available_amount;
		}
		else
		{
			while (!dsts.empty() && dsts[0].amount <= available_amount && estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof) < TX_SIZE_TARGET(upper_transaction_size_limit))
			{
				// we can fully pay that destination
				LOG_PRINT_L2("We can fully pay " << get_account_address_as_str(is_testnet, dsts[0].is_subaddress, dsts[0].addr) <<
							 " for " << print_money(dsts[0].amount));
				tx.add(dsts[0].addr, dsts[0].is_subaddress, dsts[0].amount, original_output_index, merge_destinations);
				available_amount -= dsts[0].amount;
				dsts[0].amount = 0;
				pop_index(dsts, 0);
				++original_output_index;
			}
			
			if (available_amount > 0 && !dsts.empty() && estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof) < TX_SIZE_TARGET(upper_transaction_size_limit)) {
				// we can partially fill that destination
				LOG_PRINT_L2("We can partially pay " << get_account_address_as_str(is_testnet, dsts[0].is_subaddress, dsts[0].addr) <<
							 " for " << print_money(available_amount) << "/" << print_money(dsts[0].amount));
				tx.add(dsts[0].addr, dsts[0].is_subaddress, available_amount, original_output_index, merge_destinations);
				dsts[0].amount -= available_amount;
				available_amount = 0;
			}
		}
		
		// here, check if we need to sent tx and start a new one
		LOG_PRINT_L2("Considering whether to create a tx now, " << tx.selected_transfers.size() << " inputs, tx limit "
					 << upper_transaction_size_limit);
		bool try_tx = false;
		// if we have preferred picks, but haven't yet used all of them, continue
		if (preferred_inputs.empty())
		{
			if (adding_fee)
			{
				/* might not actually be enough if adding this output bumps size to next kB, but we need to try */
				try_tx = available_for_fee >= needed_fee;
			}
			else
			{
				const size_t estimated_rct_tx_size = estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof);
				try_tx = dsts.empty() || (estimated_rct_tx_size >= TX_SIZE_TARGET(upper_transaction_size_limit));
			}
		}
		
		if (try_tx) {
			cryptonote::transaction test_tx;
			wallet2::pending_tx test_ptx;
			
			const size_t estimated_tx_size = estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof);
			needed_fee = calculate_fee(fee_per_kb, estimated_tx_size, fee_multiplier);
			
			uint64_t inputs = 0, outputs = needed_fee;
			for (size_t idx: tx.selected_transfers) inputs += transfers[idx].amount();
			for (const auto &o: tx.dsts) outputs += o.amount;
			
			if (inputs < outputs)
			{
				LOG_PRINT_L2("We don't have enough for the basic fee, switching to adding_fee");
				adding_fee = true;
				goto skip_tx;
			}
			
			LOG_PRINT_L2("Trying to create a tx now, with " << tx.dsts.size() << " outputs and " <<
						 tx.selected_transfers.size() << " inputs");
			RetVals_base tfer_retVals;
			if (use_rct)
				transfer_selected_rct(transfers, subaddresses, is_wallet_multisig, is_testnet, upper_transaction_size_limit, account_keys, multisig_threshold, wallet_multisig_signers, tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra, test_tx, test_ptx, bulletproof, get_random_outs_fn, use_fork_rules_fn, tfer_retVals);
			else
				transfer_selected(transfers, subaddresses, is_wallet_multisig, is_testnet, upper_transaction_size_limit, account_keys, multisig_threshold, tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra, detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx, get_random_outs_fn, use_fork_rules_fn, tfer_retVals);
			if (tfer_retVals.did_error) {
				retVals.did_error = true;
				retVals.err_string = *tfer_retVals.err_string;
				return false;
			}
			auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
			needed_fee = calculate_fee(fee_per_kb, txBlob, fee_multiplier);
			available_for_fee = test_ptx.fee + test_ptx.change_dts.amount + (!test_ptx.dust_added_to_fee ? test_ptx.dust : 0);
			LOG_PRINT_L2("Made a " << get_size_string(txBlob) << " tx, with " << print_money(available_for_fee) << " available for fee (" <<
						 print_money(needed_fee) << " needed)");
			
			if (needed_fee > available_for_fee && !dsts.empty() && dsts[0].amount > 0)
			{
				// we don't have enough for the fee, but we've only partially paid the current address,
				// so we can take the fee from the paid amount, since we'll have to make another tx anyway
				std::vector<cryptonote::tx_destination_entry>::iterator i;
				i = std::find_if(tx.dsts.begin(), tx.dsts.end(),
								 [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &dsts[0].addr, sizeof(dsts[0].addr)); });
				THROW_WALLET_EXCEPTION_IF(i == tx.dsts.end(), error::wallet_internal_error, "paid address not found in outputs");
				if (i->amount > needed_fee)
				{
					uint64_t new_paid_amount = i->amount /*+ test_ptx.fee*/ - needed_fee;
					LOG_PRINT_L2("Adjusting amount paid to " << get_account_address_as_str(is_testnet, i->is_subaddress, i->addr) << " from " <<
								 print_money(i->amount) << " to " << print_money(new_paid_amount) << " to accommodate " <<
								 print_money(needed_fee) << " fee");
					dsts[0].amount += i->amount - new_paid_amount;
					i->amount = new_paid_amount;
					test_ptx.fee = needed_fee;
					available_for_fee = needed_fee;
				}
			}
			
			if (needed_fee > available_for_fee)
			{
				LOG_PRINT_L2("We could not make a tx, switching to fee accumulation");
				
				adding_fee = true;
			}
			else
			{
				LOG_PRINT_L2("We made a tx, adjusting fee and saving it, we need " << print_money(needed_fee) << " and we have " << print_money(test_ptx.fee));
				while (needed_fee > test_ptx.fee) {
					RetVals_base tfer_retVals;
					if (use_rct)
						transfer_selected_rct(transfers, subaddresses, is_wallet_multisig, is_testnet, upper_transaction_size_limit, account_keys, multisig_threshold, wallet_multisig_signers, tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra, test_tx, test_ptx, bulletproof, get_random_outs_fn, use_fork_rules_fn, tfer_retVals);
					else
						transfer_selected(transfers, subaddresses, is_wallet_multisig, is_testnet, upper_transaction_size_limit, account_keys, multisig_threshold, tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra, detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx, get_random_outs_fn, use_fork_rules_fn, tfer_retVals);
					if (tfer_retVals.did_error) {
						retVals.did_error = true;
						retVals.err_string = *tfer_retVals.err_string;
						return false;
					}
					txBlob = t_serializable_object_to_blob(test_ptx.tx);
					needed_fee = calculate_fee(fee_per_kb, txBlob, fee_multiplier);
					LOG_PRINT_L2("Made an attempt at a  final " << get_size_string(txBlob) << " tx, with " << print_money(test_ptx.fee) <<
								 " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
				}
				
				LOG_PRINT_L2("Made a final " << get_size_string(txBlob) << " tx, with " << print_money(test_ptx.fee) <<
							 " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
				
				tx.tx = test_tx;
				tx.ptx = test_ptx;
				tx.bytes = txBlob.size();
				accumulated_fee += test_ptx.fee;
				accumulated_change += test_ptx.change_dts.amount;
				adding_fee = false;
				if (!dsts.empty())
				{
					LOG_PRINT_L2("We have more to pay, starting another tx");
					txes.push_back(TX());
					original_output_index = 0;
				}
			}
		}
		
	skip_tx:
		// if unused_*_indices is empty while unused_*_indices_per_subaddr has multiple elements, and if we still have something to pay,
		// pop front of unused_*_indices_per_subaddr and have unused_*_indices point to the front of unused_*_indices_per_subaddr
		if ((!dsts.empty() && dsts[0].amount > 0) || adding_fee)
		{
			if (unused_transfers_indices->empty() && unused_transfers_indices_per_subaddr.size() > 1)
			{
				unused_transfers_indices_per_subaddr.erase(unused_transfers_indices_per_subaddr.begin());
				unused_transfers_indices = &unused_transfers_indices_per_subaddr[0].second;
			}
			if (unused_dust_indices->empty() && unused_dust_indices_per_subaddr.size() > 1)
			{
				unused_dust_indices_per_subaddr.erase(unused_dust_indices_per_subaddr.begin());
				unused_dust_indices = &unused_dust_indices_per_subaddr[0].second;
			}
		}
	}
	
	if (adding_fee)
	{
		LOG_PRINT_L1("We ran out of outputs while trying to gather final fee");
		THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance_for_subaddr_index, needed_money, accumulated_fee + needed_fee);
	}
	
	LOG_PRINT_L1("Done creating " << txes.size() << " transactions, " << print_money(accumulated_fee) <<
				 " total fee, " << print_money(accumulated_change) << " total change");
	
	std::vector<wallet2::pending_tx> ptx_vector;
	for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
	{
		TX &tx = *i;
		uint64_t tx_money = 0;
		for (size_t idx: tx.selected_transfers)
			tx_money += transfers[idx].amount();
		LOG_PRINT_L1("  Transaction " << (1+std::distance(txes.begin(), i)) << "/" << txes.size() <<
					 ": " << get_size_string(tx.bytes) << ", sending " << print_money(tx_money) << " in " << tx.selected_transfers.size() <<
					 " outputs to " << tx.dsts.size() << " destination(s), including " <<
					 print_money(tx.ptx.fee) << " fee, " << print_money(tx.ptx.change_dts.amount) << " change");
		ptx_vector.push_back(tx.ptx);
	}
	
	// if we made it this far, we're OK to actually send the transactions
	retVals.pending_txs = ptx_vector;
	return true;
}
//
//
// monero_transfer_utils - transfer_selected, transfer_selected_rct
//
template<typename T>
void monero_transfer_utils::transfer_selected(
	const wallet2::transfer_container &transfers,
	const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses,
	bool is_wallet_multisig,
	bool is_testnet,
	uint64_t upper_transaction_size_limit,
	const cryptonote::account_keys &account_keys,
	uint32_t multisig_threshold,
	//
	const std::vector<cryptonote::tx_destination_entry>& dsts,
	const std::vector<size_t>& selected_transfers,
	size_t fake_outputs_count,
	std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs,
	uint64_t unlock_time,
	uint64_t fee,
	const std::vector<uint8_t>& extra,
	T destination_split_strategy,
	const tx_dust_policy& dust_policy,
	cryptonote::transaction& tx,
	wallet2::pending_tx &ptx,
	//
	get_random_outs_fn_type get_random_outs_fn, // this function MUST be synchronous
	use_fork_rules_fn_type use_fork_rules_fn,
	
	tools::RetVals_base &retVals // use custom type if it becomes necessary

) {
	retVals = {}; // must init
	//
	using namespace cryptonote;
	// throw if attempting a transaction with no destinations
	THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);
	
	THROW_WALLET_EXCEPTION_IF(is_wallet_multisig, error::wallet_internal_error, "Multisig wallets cannot spend non rct outputs");
	
	uint64_t needed_money = fee;
	LOG_PRINT_L2("transfer: starting with fee " << print_money (needed_money));
	
	// calculate total amount being sent to all destinations
	// throw if total amount overflows uint64_t
	for(auto& dt: dsts)
	{
		THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_destination);
		needed_money += dt.amount;
		LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
		THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, fee, is_testnet);
	}
	
	uint64_t found_money = 0;
	for(size_t idx: selected_transfers)
	{
		found_money += transfers[idx].amount();
	}
	
	LOG_PRINT_L2("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
	THROW_WALLET_EXCEPTION_IF(found_money < needed_money, error::not_enough_unlocked_money, found_money, needed_money - fee, fee);
	
	uint32_t subaddr_account = transfers[*selected_transfers.begin()].m_subaddr_index.major;
	for (auto i = ++selected_transfers.begin(); i != selected_transfers.end(); ++i)
		THROW_WALLET_EXCEPTION_IF(subaddr_account != transfers[*i].m_subaddr_index.major, error::wallet_internal_error, "the tx uses funds from multiple accounts");
	
	if (outs.empty()) {
		monero_transfer_utils::get_random_outs_fn_RetVals fn__retVals;
		bool r = get_random_outs_fn(outs, selected_transfers, fake_outputs_count, fn__retVals);
		if (!r) {
			retVals.did_error = true;
			retVals.err_string = *fn__retVals.err_string;
			return;
		}
	}
	//prepare inputs
	LOG_PRINT_L2("preparing outputs");
	typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
	size_t i = 0, out_index = 0;
	std::vector<cryptonote::tx_source_entry> sources;
	for(size_t idx: selected_transfers)
	{
		sources.resize(sources.size()+1);
		cryptonote::tx_source_entry& src = sources.back();
		const wallet2::transfer_details& td = transfers[idx];
		src.amount = td.amount();
		src.rct = td.is_rct();
		//paste keys (fake and real)
		
		for (size_t n = 0; n < fake_outputs_count + 1; ++n)
		{
			tx_output_entry oe;
			oe.first = std::get<0>(outs[out_index][n]);
			oe.second.dest = rct::pk2rct(std::get<1>(outs[out_index][n]));
			oe.second.mask = std::get<2>(outs[out_index][n]);
			
			src.outputs.push_back(oe);
			++i;
		}
		
		//paste real transaction to the random index
		auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
										  {
											  return a.first == td.m_global_output_index;
										  });
		THROW_WALLET_EXCEPTION_IF(it_to_replace == src.outputs.end(), error::wallet_internal_error,
								  "real output not found");
		
		tx_output_entry real_oe;
		real_oe.first = td.m_global_output_index;
		real_oe.second.dest = rct::pk2rct(boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key);
		real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
		*it_to_replace = real_oe;
		src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
		src.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);
		src.real_output = it_to_replace - src.outputs.begin();
		src.real_output_in_tx_index = td.m_internal_output_index;
		src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
		detail::print_source_entry(src);
		++out_index;
	}
	LOG_PRINT_L2("outputs prepared");
	
	cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
	if (needed_money < found_money)
	{
		change_dts.addr = get_subaddress({subaddr_account, 0}, account_keys);
		change_dts.amount = found_money - needed_money;
	}
	
	std::vector<cryptonote::tx_destination_entry> splitted_dsts, dust_dsts;
	uint64_t dust = 0;
	destination_split_strategy(dsts, change_dts, dust_policy.dust_threshold, splitted_dsts, dust_dsts);
	for(auto& d: dust_dsts) {
		THROW_WALLET_EXCEPTION_IF(dust_policy.dust_threshold < d.amount, error::wallet_internal_error, "invalid dust value: dust = " +
								  std::to_string(d.amount) + ", dust_threshold = " + std::to_string(dust_policy.dust_threshold));
	}
	for(auto& d: dust_dsts) {
		if (!dust_policy.add_to_fee)
			splitted_dsts.push_back(cryptonote::tx_destination_entry(d.amount, dust_policy.addr_for_dust, d.is_subaddress));
		dust += d.amount;
	}
	
	crypto::secret_key tx_key;
	std::vector<crypto::secret_key> additional_tx_keys;
	rct::multisig_out msout;
	LOG_PRINT_L2("constructing tx");
	bool r = cryptonote::construct_tx_and_get_tx_key(account_keys, subaddresses, sources, splitted_dsts, change_dts.addr, extra, tx, unlock_time, tx_key, additional_tx_keys, false, false, is_wallet_multisig ? &msout : NULL);
	LOG_PRINT_L2("constructed tx, r="<<r);
	THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, splitted_dsts, unlock_time, is_testnet);
	THROW_WALLET_EXCEPTION_IF(upper_transaction_size_limit <= get_object_blobsize(tx), error::tx_too_big, tx, upper_transaction_size_limit);
	
	std::string key_images;
	bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
										   {
											   CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
											   key_images += boost::to_string(in.k_image) + " ";
											   return true;
										   });
	THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, tx);
	
	
	bool dust_sent_elsewhere = (dust_policy.addr_for_dust.m_view_public_key != change_dts.addr.m_view_public_key
								|| dust_policy.addr_for_dust.m_spend_public_key != change_dts.addr.m_spend_public_key);
	
	if (dust_policy.add_to_fee || dust_sent_elsewhere) change_dts.amount -= dust;
	
	ptx.key_images = key_images;
	ptx.fee = (dust_policy.add_to_fee ? fee+dust : fee);
	ptx.dust = ((dust_policy.add_to_fee || dust_sent_elsewhere) ? dust : 0);
	ptx.dust_added_to_fee = dust_policy.add_to_fee;
	ptx.tx = tx;
	ptx.change_dts = change_dts;
	ptx.selected_transfers = selected_transfers;
	ptx.tx_key = tx_key;
	ptx.additional_tx_keys = additional_tx_keys;
	ptx.dests = dsts;
	ptx.construction_data.sources = sources;
	ptx.construction_data.change_dts = change_dts;
	ptx.construction_data.splitted_dsts = splitted_dsts;
	ptx.construction_data.selected_transfers = selected_transfers;
	ptx.construction_data.extra = tx.extra;
	ptx.construction_data.unlock_time = unlock_time;
	ptx.construction_data.use_rct = false;
	ptx.construction_data.dests = dsts;
	// record which subaddress indices are being used as inputs
	ptx.construction_data.subaddr_account = subaddr_account;
	ptx.construction_data.subaddr_indices.clear();
	for (size_t idx: selected_transfers)
		ptx.construction_data.subaddr_indices.insert(transfers[idx].m_subaddr_index.minor);
	LOG_PRINT_L2("transfer_selected done");
}

void monero_transfer_utils::transfer_selected_rct(
	const wallet2::transfer_container &transfers,
	const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses,
	bool is_wallet_multisig,
	bool is_testnet,
	uint64_t upper_transaction_size_limit,
	const cryptonote::account_keys &account_keys,
	uint32_t multisig_threshold,
	std::vector<crypto::public_key> wallet_multisig_signers,
	//
	std::vector<cryptonote::tx_destination_entry> dsts,
	const std::vector<size_t>& selected_transfers,
	size_t fake_outputs_count,
	std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs,
	uint64_t unlock_time,
	uint64_t fee,
	const std::vector<uint8_t>& extra,
	cryptonote::transaction& tx,
	wallet2::pending_tx &ptx,
	bool bulletproof,
	//
	get_random_outs_fn_type get_random_outs_fn, // this function MUST be synchronous
	use_fork_rules_fn_type use_fork_rules_fn,
	//;
	tools::RetVals_base &retVals
) {
	retVals = {}; // must init
	//
	using namespace cryptonote;
	// throw if attempting a transaction with no destinations
	THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);
	
	uint64_t needed_money = fee;
	LOG_PRINT_L2("transfer_selected_rct: starting with fee " << print_money (needed_money));
	LOG_PRINT_L2("selected transfers: " << strjoin(selected_transfers, " "));
	
	// calculate total amount being sent to all destinations
	// throw if total amount overflows uint64_t
	for(auto& dt: dsts)
	{
		THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_destination);
		needed_money += dt.amount;
		LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
		THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, fee, is_testnet);
	}
	
	// if this is a multisig wallet, create a list of multisig signers we can use
	std::deque<crypto::public_key> multisig_signers;
	size_t n_multisig_txes = 0;
	if (is_wallet_multisig && !transfers.empty())
	{
		const crypto::public_key local_signer = get_multisig_signer_public_key(is_wallet_multisig, account_keys);
		size_t n_available_signers = 1;
		for (const crypto::public_key &signer: wallet_multisig_signers)
		{
			if (signer == local_signer)
				continue;
			multisig_signers.push_front(signer);
			for (const auto &i: transfers[0].m_multisig_info)
			{
				if (i.m_signer == signer)
				{
					multisig_signers.pop_front();
					multisig_signers.push_back(signer);
					++n_available_signers;
					break;
				}
			}
		}
		multisig_signers.push_back(local_signer);
		MDEBUG("We can use " << n_available_signers << "/" << wallet_multisig_signers.size() <<  " other signers");
		THROW_WALLET_EXCEPTION_IF(n_available_signers+1 < multisig_threshold, error::multisig_import_needed);
		n_multisig_txes = n_available_signers == wallet_multisig_signers.size() ? multisig_threshold : 1;
		MDEBUG("We will create " << n_multisig_txes << " txes");
	}
	
	uint64_t found_money = 0;
	for(size_t idx: selected_transfers)
	{
		found_money += transfers[idx].amount();
	}
	
	LOG_PRINT_L2("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
	THROW_WALLET_EXCEPTION_IF(found_money < needed_money, error::not_enough_unlocked_money, found_money, needed_money - fee, fee);
	
	uint32_t subaddr_account = transfers[*selected_transfers.begin()].m_subaddr_index.major;
	for (auto i = ++selected_transfers.begin(); i != selected_transfers.end(); ++i)
		THROW_WALLET_EXCEPTION_IF(subaddr_account != transfers[*i].m_subaddr_index.major, error::wallet_internal_error, "the tx uses funds from multiple accounts");
	
	if (outs.empty()) {
		monero_transfer_utils::get_random_outs_fn_RetVals fn__retVals;
		bool r = get_random_outs_fn(outs, selected_transfers, fake_outputs_count, fn__retVals);
		if (!r) {
			retVals.did_error = true;
			retVals.err_string = *fn__retVals.err_string;
			return;
		}
	}
	
	//prepare inputs
	LOG_PRINT_L2("preparing outputs");
	size_t i = 0, out_index = 0;
	std::vector<cryptonote::tx_source_entry> sources;
	std::unordered_set<rct::key> used_L;
	for(size_t idx: selected_transfers)
	{
		sources.resize(sources.size()+1);
		cryptonote::tx_source_entry& src = sources.back();
		const wallet2::transfer_details& td = transfers[idx];
		src.amount = td.amount();
		src.rct = td.is_rct();
		//paste mixin transaction
		
		THROW_WALLET_EXCEPTION_IF(outs.size() < out_index + 1 ,  error::wallet_internal_error, "outs.size() < out_index + 1");
		THROW_WALLET_EXCEPTION_IF(outs[out_index].size() < fake_outputs_count ,  error::wallet_internal_error, "fake_outputs_count > random outputs found");
		
		typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
		for (size_t n = 0; n < fake_outputs_count + 1; ++n)
		{
			tx_output_entry oe;
			oe.first = std::get<0>(outs[out_index][n]);
			oe.second.dest = rct::pk2rct(std::get<1>(outs[out_index][n]));
			oe.second.mask = std::get<2>(outs[out_index][n]);
			src.outputs.push_back(oe);
		}
		++i;
		
		//paste real transaction to the random index
		auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
										  {
											  return a.first == td.m_global_output_index;
										  });
		THROW_WALLET_EXCEPTION_IF(it_to_replace == src.outputs.end(), error::wallet_internal_error,
								  "real output not found");
		
		tx_output_entry real_oe;
		real_oe.first = td.m_global_output_index;
		real_oe.second.dest = rct::pk2rct(td.get_public_key());
		real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
		*it_to_replace = real_oe;
		src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
		src.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);
		src.real_output = it_to_replace - src.outputs.begin();
		src.real_output_in_tx_index = td.m_internal_output_index;
		src.mask = td.m_mask;
		if (is_wallet_multisig)
		{
			crypto::public_key ignore = multisig_threshold == wallet_multisig_signers.size() ? crypto::null_pkey : multisig_signers.front();
			src.multisig_kLRki = get_multisig_composite_kLRki(idx, ignore, used_L, used_L, transfers, multisig_threshold);
		}
		else
			src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
		detail::print_source_entry(src);
		++out_index;
	}
	LOG_PRINT_L2("outputs prepared");
	
	// we still keep a copy, since we want to keep dsts free of change for user feedback purposes
	std::vector<cryptonote::tx_destination_entry> splitted_dsts = dsts;
	cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
	change_dts.amount = found_money - needed_money;
	if (change_dts.amount == 0)
	{
		if (splitted_dsts.size() == 1)
		{
			// If the change is 0, send it to a random address, to avoid confusing
			// the sender with a 0 amount output. We send a 0 amount in order to avoid
			// letting the destination be able to work out which of the inputs is the
			// real one in our rings
			LOG_PRINT_L2("generating dummy address for 0 change");
			cryptonote::account_base dummy;
			dummy.generate();
			change_dts.addr = dummy.get_keys().m_account_address;
			LOG_PRINT_L2("generated dummy address for 0 change");
			splitted_dsts.push_back(change_dts);
		}
	}
	else
	{
		change_dts.addr = get_subaddress({subaddr_account, 0}, account_keys);
		splitted_dsts.push_back(change_dts);
	}
	
	crypto::secret_key tx_key;
	std::vector<crypto::secret_key> additional_tx_keys;
	rct::multisig_out msout;
	LOG_PRINT_L2("constructing tx");
	auto sources_copy = sources;
	bool r = cryptonote::construct_tx_and_get_tx_key(account_keys, subaddresses, sources, splitted_dsts, change_dts.addr, extra, tx, unlock_time, tx_key, additional_tx_keys, true, bulletproof, is_wallet_multisig ? &msout : NULL);
	LOG_PRINT_L2("constructed tx, r="<<r);
	THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, dsts, unlock_time, is_testnet);
	THROW_WALLET_EXCEPTION_IF(upper_transaction_size_limit <= get_object_blobsize(tx), error::tx_too_big, tx, upper_transaction_size_limit);
	
	// work out the permutation done on sources
	std::vector<size_t> ins_order;
	for (size_t n = 0; n < sources.size(); ++n)
	{
		for (size_t idx = 0; idx < sources_copy.size(); ++idx)
		{
			THROW_WALLET_EXCEPTION_IF((size_t)sources_copy[idx].real_output >= sources_copy[idx].outputs.size(),
									  error::wallet_internal_error, "Invalid real_output");
			if (sources_copy[idx].outputs[sources_copy[idx].real_output].second.dest == sources[n].outputs[sources[n].real_output].second.dest)
				ins_order.push_back(idx);
		}
	}
	THROW_WALLET_EXCEPTION_IF(ins_order.size() != sources.size(), error::wallet_internal_error, "Failed to work out sources permutation");
	
	std::vector<tools::wallet2::multisig_sig> multisig_sigs;
	if (is_wallet_multisig)
	{
		crypto::public_key ignore = multisig_threshold == wallet_multisig_signers.size() ? crypto::null_pkey : multisig_signers.front();
		multisig_sigs.push_back({tx.rct_signatures, ignore, used_L, std::unordered_set<crypto::public_key>(), msout});
		
		if (multisig_threshold < wallet_multisig_signers.size())
		{
			const crypto::hash prefix_hash = cryptonote::get_transaction_prefix_hash(tx);
			
			// create the other versions, one for every other participant (the first one's already done above)
			for (size_t signer_index = 1; signer_index < n_multisig_txes; ++signer_index)
			{
				std::unordered_set<rct::key> new_used_L;
				size_t src_idx = 0;
				THROW_WALLET_EXCEPTION_IF(selected_transfers.size() != sources.size(), error::wallet_internal_error, "mismatched selected_transfers and sources sixes");
				for(size_t idx: selected_transfers)
				{
					cryptonote::tx_source_entry& src = sources[src_idx];
					src.multisig_kLRki = get_multisig_composite_kLRki(idx, multisig_signers[signer_index], used_L, new_used_L, transfers, multisig_threshold);
					++src_idx;
				}
				
				LOG_PRINT_L2("Creating supplementary multisig transaction");
				cryptonote::transaction ms_tx;
				auto sources_copy_copy = sources_copy;
				bool r = cryptonote::construct_tx_with_tx_key(account_keys, subaddresses, sources_copy_copy, splitted_dsts, change_dts.addr, extra, ms_tx, unlock_time,tx_key, additional_tx_keys, true, bulletproof, &msout);
				LOG_PRINT_L2("constructed tx, r="<<r);
				THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, splitted_dsts, unlock_time, is_testnet);
				THROW_WALLET_EXCEPTION_IF(upper_transaction_size_limit <= get_object_blobsize(tx), error::tx_too_big, tx, upper_transaction_size_limit);
				THROW_WALLET_EXCEPTION_IF(cryptonote::get_transaction_prefix_hash(ms_tx) != prefix_hash, error::wallet_internal_error, "Multisig txes do not share prefix");
				multisig_sigs.push_back({ms_tx.rct_signatures, multisig_signers[signer_index], new_used_L, std::unordered_set<crypto::public_key>(), msout});
				
				ms_tx.rct_signatures = tx.rct_signatures;
				THROW_WALLET_EXCEPTION_IF(cryptonote::get_transaction_hash(ms_tx) != cryptonote::get_transaction_hash(tx), error::wallet_internal_error, "Multisig txes differ by more than the signatures");
			}
		}
	}
	
	LOG_PRINT_L2("gathering key images");
	std::string key_images;
	bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
										   {
											   CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
											   key_images += boost::to_string(in.k_image) + " ";
											   return true;
										   });
	THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, tx);
	LOG_PRINT_L2("gathered key images");
	
	ptx.key_images = key_images;
	ptx.fee = fee;
	ptx.dust = 0;
	ptx.dust_added_to_fee = false;
	ptx.tx = tx;
	ptx.change_dts = change_dts;
	ptx.selected_transfers = selected_transfers;
	tools::apply_permutation(ins_order, ptx.selected_transfers);
	ptx.tx_key = tx_key;
	ptx.additional_tx_keys = additional_tx_keys;
	ptx.dests = dsts;
	ptx.multisig_sigs = multisig_sigs;
	ptx.construction_data.sources = sources_copy;
	ptx.construction_data.change_dts = change_dts;
	ptx.construction_data.splitted_dsts = splitted_dsts;
	ptx.construction_data.selected_transfers = ptx.selected_transfers;
	ptx.construction_data.extra = tx.extra;
	ptx.construction_data.unlock_time = unlock_time;
	ptx.construction_data.use_rct = true;
	ptx.construction_data.dests = dsts;
	// record which subaddress indices are being used as inputs
	ptx.construction_data.subaddr_account = subaddr_account;
	ptx.construction_data.subaddr_indices.clear();
	for (size_t idx: selected_transfers)
		ptx.construction_data.subaddr_indices.insert(transfers[idx].m_subaddr_index.minor);
	LOG_PRINT_L2("transfer_selected_rct done");
}
//
//
// monero_transfer_utils - General functions
//
uint64_t monero_transfer_utils::get_upper_transaction_size_limit(uint64_t upper_transaction_size_limit__or_0_for_default, use_fork_rules_fn_type use_fork_rules_fn)
{
	if (upper_transaction_size_limit__or_0_for_default > 0)
		return upper_transaction_size_limit__or_0_for_default;
	uint64_t full_reward_zone = use_fork_rules_fn(5, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 : use_fork_rules_fn(2, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
	return full_reward_zone - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}
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

std::vector<size_t> monero_transfer_utils::pick_preferred_rct_inputs(const wallet2::transfer_container &transfers, uint64_t needed_money, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices, uint64_t blockchain_size, bool is_testnet)
{
	std::vector<size_t> picks;
	float current_output_relatdness = 1.0f;
	
	LOG_PRINT_L2("pick_preferred_rct_inputs: needed_money " << print_money(needed_money));
	
	// try to find a rct input of enough size
	for (size_t i = 0; i < transfers.size(); ++i)
	{
		const wallet2::transfer_details& td = transfers[i];
		if (!td.m_spent && td.is_rct() && td.amount() >= needed_money && is_transfer_unlocked(td, blockchain_size, is_testnet) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
		{
			LOG_PRINT_L2("We can use " << i << " alone: " << print_money(td.amount()));
			picks.push_back(i);
			return picks;
		}
	}
	
	// then try to find two outputs
	// this could be made better by picking one of the outputs to be a small one, since those
	// are less useful since often below the needed money, so if one can be used in a pair,
	// it gets rid of it for the future
	for (size_t i = 0; i < transfers.size(); ++i)
	{
		const wallet2::transfer_details& td = transfers[i];
		if (!td.m_spent && !td.m_key_image_partial && td.is_rct() && is_transfer_unlocked(td, blockchain_size, is_testnet) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
		{
			LOG_PRINT_L2("Considering input " << i << ", " << print_money(td.amount()));
			for (size_t j = i + 1; j < transfers.size(); ++j)
			{
				const wallet2::transfer_details& td2 = transfers[j];
				if (!td2.m_spent && !td.m_key_image_partial && td2.is_rct() && td.amount() + td2.amount() >= needed_money && is_transfer_unlocked(td2, blockchain_size, is_testnet) && td2.m_subaddr_index == td.m_subaddr_index)
				{
					// update our picks if those outputs are less related than any we
					// already found. If the same, don't update, and oldest suitable outputs
					// will be used in preference.
					float relatedness = get_output_relatedness(td, td2);
					LOG_PRINT_L2("  with input " << j << ", " << print_money(td2.amount()) << ", relatedness " << relatedness);
					if (relatedness < current_output_relatdness)
					{
						// reset the current picks with those, and return them directly
						// if they're unrelated. If they are related, we'll end up returning
						// them if we find nothing better
						picks.clear();
						picks.push_back(i);
						picks.push_back(j);
						LOG_PRINT_L0("we could use " << i << " and " << j);
						if (relatedness == 0.0f)
							return picks;
						current_output_relatdness = relatedness;
					}
				}
			}
		}
	}
	
	return picks;
}
bool monero_transfer_utils::should_pick_a_second_output(bool use_rct, const wallet2::transfer_container &transfers, size_t n_transfers, const std::vector<size_t> &unused_transfers_indices, const std::vector<size_t> &unused_dust_indices)
{
	if (!use_rct)
		return false;
	if (n_transfers > 1)
		return false;
	if (unused_dust_indices.empty() && unused_transfers_indices.empty())
		return false;
	// we want at least one free rct output to avoid a corner case where
	// we'd choose a non rct output which doesn't have enough "siblings"
	// value-wise on the chain, and thus can't be mixed
	bool found = false;
	for (auto i: unused_dust_indices)
	{
		if (transfers[i].is_rct())
		{
			found = true;
			break;
		}
	}
	if (!found) for (auto i: unused_transfers_indices)
	{
		if (transfers[i].is_rct())
		{
			found = true;
			break;
		}
	}
	if (!found)
		return false;
	return true;
}
size_t monero_transfer_utils::pop_best_value_from(const wallet2::transfer_container &transfers, std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, bool smallest)
{
	std::vector<size_t> candidates;
	float best_relatedness = 1.0f;
	for (size_t n = 0; n < unused_indices.size(); ++n)
	{
		const wallet2::transfer_details &candidate = transfers[unused_indices[n]];
		float relatedness = 0.0f;
		for (std::vector<size_t>::const_iterator i = selected_transfers.begin(); i != selected_transfers.end(); ++i)
		{
			float r = get_output_relatedness(candidate, transfers[*i]);
			if (r > relatedness)
			{
				relatedness = r;
				if (relatedness == 1.0f)
					break;
			}
		}
		
		if (relatedness < best_relatedness)
		{
			best_relatedness = relatedness;
			candidates.clear();
		}
		
		if (relatedness == best_relatedness)
			candidates.push_back(n);
	}
	
	// we have all the least related outputs in candidates, so we can pick either
	// the smallest, or a random one, depending on request
	size_t idx;
	if (smallest)
	{
		idx = 0;
		for (size_t n = 0; n < candidates.size(); ++n)
		{
			const wallet2::transfer_details &td = transfers[unused_indices[candidates[n]]];
			if (td.amount() < transfers[unused_indices[candidates[idx]]].amount())
				idx = n;
		}
	}
	else
	{
		idx = crypto::rand<size_t>() % candidates.size();
	}
	return pop_index (unused_indices, candidates[idx]);
}
std::vector<size_t> monero_transfer_utils::get_only_rct(const wallet2::transfer_container &transfers, const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices)
{
	std::vector<size_t> indices;
	for (size_t n: unused_dust_indices)
		if (transfers[n].is_rct())
			indices.push_back(n);
	for (size_t n: unused_transfers_indices)
		if (transfers[n].is_rct())
			indices.push_back(n);
	return indices;
}

uint32_t monero_transfer_utils::get_count_above(const wallet2::transfer_container &transfers, const std::vector<size_t> &indices, uint64_t threshold)
{
	uint32_t count = 0;
	for (size_t idx: indices)
		if (transfers[idx].amount() >= threshold)
			++count;
	return count;
}

// This returns a handwavy estimation of how much two outputs are related
// If they're from the same tx, then they're fully related. From close block
// heights, they're kinda related. The actual values don't matter, just
// their ordering, but it could become more murky if we add scores later.
float monero_transfer_utils::get_output_relatedness(const wallet2::transfer_details &td0, const wallet2::transfer_details &td1)
{
	int dh;
	
	// expensive test, and same tx will fall onto the same block height below
	if (td0.m_txid == td1.m_txid)
		return 1.0f;
	
	// same block height -> possibly tx burst, or same tx (since above is disabled)
	dh = td0.m_block_height > td1.m_block_height ? td0.m_block_height - td1.m_block_height : td1.m_block_height - td0.m_block_height;
	if (dh == 0)
		return 0.9f;
	
	// adjacent blocks -> possibly tx burst
	if (dh == 1)
		return 0.8f;
	
	// could extract the payment id, and compare them, but this is a bit expensive too
	
	// similar block heights
	if (dh < 10)
		return 0.2f;
	
	// don't think these are particularly related
	return 0.0f;
}
//
//
// Transfer parsing/derived properties
bool monero_transfer_utils::is_transfer_unlocked(
	uint64_t unlock_time,
	uint64_t block_height,
	uint64_t blockchain_size, /* extracting wallet2->m_blockchain.size() / m_local_bc_height */
	bool is_testnet
) {
	if(!is_tx_spendtime_unlocked(unlock_time, block_height, blockchain_size, is_testnet))
		return false;
	
	if(block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > blockchain_size)
		return false;
	
	return true;
}
bool monero_transfer_utils::is_transfer_unlocked(
	const tools::wallet2::transfer_details& td,
	uint64_t blockchain_size,
	bool is_testnet
) {
	return is_transfer_unlocked(td.m_tx.unlock_time, td.m_block_height, blockchain_size, is_testnet);
}
bool monero_transfer_utils::is_tx_spendtime_unlocked(
	uint64_t unlock_time,
	uint64_t block_height,
	uint64_t blockchain_size,
	bool is_testnet
) {
	if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
	{
		//interpret as block index
		if(block_height-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
			return true;
		else
			return false;
	}else
	{
		//interpret as time
		uint64_t current_time = static_cast<uint64_t>(time(NULL));
		// XXX: this needs to be fast, so we'd need to get the starting heights
		// from the daemon to be correct once voting kicks in
		uint64_t v2height = is_testnet ? 624634 : 1009827;
		uint64_t leeway = block_height < v2height ? CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1 : CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2;
		if(current_time + leeway >= unlock_time)
			return true;
		else
			return false;
	}
	return false;
}

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
	return account.get_public_address_str(isTestnet);
}
//
std::map<uint32_t, uint64_t> monero_transfer_utils::balance_per_subaddress(
	std::vector<wallet2::transfer_details> transfers,
	std::unordered_map<crypto::hash, tools::wallet2::unconfirmed_transfer_details> unconfirmed_txs,
	uint32_t index_major
) {
	std::map<uint32_t, uint64_t> amount_per_subaddr;
	for (const auto& td: transfers)
	{
		if (td.m_subaddr_index.major == index_major && !td.m_spent)
		{
			auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
			if (found == amount_per_subaddr.end())
				amount_per_subaddr[td.m_subaddr_index.minor] = td.amount();
			else
				found->second += td.amount();
		}
	}
	for (const auto& utx: unconfirmed_txs)
	{
		if (utx.second.m_subaddr_account == index_major && utx.second.m_state != wallet2::unconfirmed_transfer_details::failed)
		{
			// all changes go to 0-th subaddress (in the current subaddress account)
			auto found = amount_per_subaddr.find(0);
			if (found == amount_per_subaddr.end())
				amount_per_subaddr[0] = utx.second.m_change;
			else
				found->second += utx.second.m_change;
		}
	}
	return amount_per_subaddr;
}
std::map<uint32_t, uint64_t> monero_transfer_utils::unlocked_balance_per_subaddress(
	std::vector<wallet2::transfer_details> transfers,
	uint32_t index_major,
	uint64_t blockchain_size,
	bool is_testnet
) {
	std::map<uint32_t, uint64_t> amount_per_subaddr;
	for(const wallet2::transfer_details& td: transfers)
	{
		if(td.m_subaddr_index.major == index_major && !td.m_spent && is_transfer_unlocked(td, blockchain_size, is_testnet))
		{
			auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
			if (found == amount_per_subaddr.end())
				amount_per_subaddr[td.m_subaddr_index.minor] = td.amount();
			else
				found->second += td.amount();
		}
	}
	return amount_per_subaddr;
}
//
void monero_transfer_utils::set_spent(wallet2::transfer_details &td, uint64_t height)
{
	LOG_PRINT_L2("Setting SPENT at " << height << ": ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
	td.m_spent = true;
	td.m_spent_height = height;
}
void monero_transfer_utils::set_unspent(wallet2::transfer_details &td)
{
	LOG_PRINT_L2("Setting UNSPENT: ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
	td.m_spent = false;
	td.m_spent_height = 0;
}
void monero_transfer_utils::set_spent(std::vector<wallet2::transfer_details> &transfers, size_t idx, uint64_t height)
{
	wallet2::transfer_details &td = transfers[idx];
	monero_transfer_utils::set_spent(td, height);
}
void monero_transfer_utils::set_unspent(std::vector<wallet2::transfer_details> &transfers, size_t idx)
{
	wallet2::transfer_details &td = transfers[idx];
	monero_transfer_utils::set_unspent(td);
}
//
crypto::public_key monero_transfer_utils::get_tx_pub_key_from_received_outs(const tools::wallet2::transfer_details &td, const cryptonote::account_keys& keys, const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses)
{
	std::vector<tx_extra_field> tx_extra_fields;
	if(!parse_tx_extra(td.m_tx.extra, tx_extra_fields))
	{
		// Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
	}
	
	// Due to a previous bug, there might be more than one tx pubkey in extra, one being
	// the result of a previously discarded signature.
	// For speed, since scanning for outputs is a slow process, we check whether extra
	// contains more than one pubkey. If not, the first one is returned. If yes, they're
	// checked for whether they yield at least one output
	tx_extra_pub_key pub_key_field;
	THROW_WALLET_EXCEPTION_IF(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, 0), error::wallet_internal_error,
							  "Public key wasn't found in the transaction extra");
	const crypto::public_key tx_pub_key = pub_key_field.pub_key;
	bool two_found = find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, 1);
	if (!two_found) {
		// easy case, just one found
		return tx_pub_key;
	}
	
	// more than one, loop and search
	size_t pk_index = 0;
	
	const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);
	std::vector<crypto::key_derivation> additional_derivations;
	for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
	{
		additional_derivations.push_back({});
		bool r = generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back());
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
	}
	
	while (find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, pk_index++)) {
		const crypto::public_key tx_pub_key = pub_key_field.pub_key;
		crypto::key_derivation derivation;
		bool r = generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation);
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
		
		for (size_t i = 0; i < td.m_tx.vout.size(); ++i)
		{
			wallet2::tx_scan_info_t tx_scan_info;
			check_acc_out_precomp(td.m_tx.vout[i], derivation, additional_derivations, i, tx_scan_info, subaddresses);
			if (!tx_scan_info.error && tx_scan_info.received)
				return tx_pub_key;
		}
	}
	
	// we found no key yielding an output
	THROW_WALLET_EXCEPTION_IF(true, error::wallet_internal_error,
							  "Public key yielding at least one output wasn't found in the transaction extra");
	return crypto::null_pkey;
}
void monero_transfer_utils::check_acc_out_precomp(const tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, wallet2::tx_scan_info_t &tx_scan_info, const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses)
{
	if (o.target.type() !=  typeid(txout_to_key))
	{
		tx_scan_info.error = true;
		LOG_ERROR("wrong type id in transaction out");
		return;
	}
	tx_scan_info.received = is_out_to_acc_precomp(subaddresses, boost::get<txout_to_key>(o.target).key, derivation, additional_derivations, i);
	if(tx_scan_info.received)
	{
		tx_scan_info.money_transfered = o.amount; // may be 0 for ringct outputs
	}
	else
	{
		tx_scan_info.money_transfered = 0;
	}
	tx_scan_info.error = false;
}
//
cryptonote::account_public_address monero_transfer_utils::get_subaddress(const cryptonote::subaddress_index& index, const cryptonote::account_keys& keys)
{
	if (index.is_zero())
		return keys.m_account_address;
	
	crypto::public_key D = get_subaddress_spend_public_key(index, keys);
	
	// C = a*D
	crypto::public_key C = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(D), rct::sk2rct(keys.m_view_secret_key)));   // could have defined secret_key_mult_public_key() under src/crypto
	
	// result: (C, D)
	cryptonote::account_public_address address;
	address.m_view_public_key  = C;
	address.m_spend_public_key = D;
	return address;
}
crypto::public_key monero_transfer_utils::get_subaddress_spend_public_key(const cryptonote::subaddress_index& index, const cryptonote::account_keys& keys)
{
	if (index.is_zero())
		return keys.m_account_address.m_spend_public_key;
	
	// m = Hs(a || index_major || index_minor)
	crypto::secret_key m = cryptonote::get_subaddress_secret_key(keys.m_view_secret_key, index);
	
	// M = m*G
	crypto::public_key M;
	crypto::secret_key_to_public_key(m, M);
	
	// D = B + M
	rct::key D_rct;
	rct::addKeys(D_rct, rct::pk2rct(keys.m_account_address.m_spend_public_key), rct::pk2rct(M));  // could have defined add_public_key() under src/crypto
	crypto::public_key D = rct::rct2pk(D_rct);
	
	return D;
}
//
tools::wallet2::tx_construction_data monero_transfer_utils::get_construction_data_with_decrypted_short_payment_id(const tools::wallet2::pending_tx &ptx)
{
	tools::wallet2::tx_construction_data construction_data = ptx.construction_data;
	crypto::hash8 payment_id = get_short_payment_id(ptx);
	if (payment_id != null_hash8)
	{
		// Remove encrypted
		remove_field_from_tx_extra(construction_data.extra, typeid(cryptonote::tx_extra_nonce));
		// Add decrypted
		std::string extra_nonce;
		set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
		THROW_WALLET_EXCEPTION_IF(!add_extra_nonce_to_tx_extra(construction_data.extra, extra_nonce),
								  tools::error::wallet_internal_error, "Failed to add decrypted payment id to tx extra");
		LOG_PRINT_L1("Decrypted payment ID: " << payment_id);
	}
	return construction_data;
}
crypto::hash monero_transfer_utils::get_payment_id(const wallet2::pending_tx &ptx)
{
	std::vector<tx_extra_field> tx_extra_fields;
	parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
	tx_extra_nonce extra_nonce;
	crypto::hash payment_id = null_hash;
	if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
	{
		crypto::hash8 payment_id8 = null_hash8;
		if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
		{
			if (ptx.dests.empty())
			{
				MWARNING("Encrypted payment id found, but no destinations public key, cannot decrypt");
				return crypto::null_hash;
			}
			if (decrypt_payment_id(payment_id8, ptx.dests[0].addr.m_view_public_key, ptx.tx_key))
			{
				memcpy(payment_id.data, payment_id8.data, 8);
			}
		}
		else if (!get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
		{
			payment_id = crypto::null_hash;
		}
	}
	return payment_id;
}
crypto::hash8 monero_transfer_utils::get_short_payment_id(const tools::wallet2::pending_tx &ptx)
{
	crypto::hash8 payment_id8 = null_hash8;
	std::vector<tx_extra_field> tx_extra_fields;
	parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
	cryptonote::tx_extra_nonce extra_nonce;
	if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
	{
		if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
		{
			if (ptx.dests.empty())
			{
				MWARNING("Encrypted payment id found, but no destinations public key, cannot decrypt");
				return crypto::null_hash8;
			}
			decrypt_payment_id(payment_id8, ptx.dests[0].addr.m_view_public_key, ptx.tx_key);
		}
	}
	return payment_id8;
}
