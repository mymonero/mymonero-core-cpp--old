//
//  monero_transfer_utils.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 12/2/17.
//  Copyright © 2017 MyMonero. All rights reserved.
//
//
#include "monero_transfer_utils.hpp"
#include "monero_key_utils.hpp"
#include "monero_paymentID_utils.hpp"
#include "cryptonote_basic/cryptonote_format_utils.h"
//
using namespace std;
using namespace cryptonote;
using namespace tools; // for error::
using namespace monero_transfer_utils;
//
namespace
{ // TODO/FIXME extract this to another domain?
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
//
size_t monero_transfer_utils::fixed_ringsize()
{
	return 10; // TODO/FIXME: temporary
}
size_t monero_transfer_utils::fixed_mixinsize()
{
	return monero_transfer_utils::fixed_ringsize() - 1;
}
//
bool monero_transfer_utils::create_signed_transaction(
	const CreateTx_Args &args,
	CreateTx_RetVals &retVals
) {
	std::vector<size_t> unused_transfers_indices;
	std::vector<size_t> unused_dust_indices;
	uint64_t needed_money;
	uint64_t accumulated_fee, accumulated_outputs, accumulated_change;
	struct TX
	{ // TODO/FIXME: improve name or extract definition?
		std::list<size_t> selected_transfers;
		std::vector<cryptonote::tx_destination_entry> dsts;
		cryptonote::transaction tx;
		pending_tx ptx;
		size_t bytes;
		//
		bool add(
			const cryptonote::account_public_address &addr,
			uint64_t amount,
			unsigned int original_output_index,
			bool should_merge_this_destination
		) {
			if (should_merge_this_destination) {
				std::vector<tx_destination_entry>::iterator i;
				i = std::find_if(dsts.begin(), dsts.end(), [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &addr, sizeof(addr)); });
				if (i == dsts.end()) {
					dsts.push_back(tx_destination_entry(0, addr));
					i = dsts.end() - 1;
				}
				i->amount += amount;
			} else {
				if (original_output_index > dsts.size()) {
					// TODO
//					retVals.didError = true;
//					retVals.err_string = "original_output_index too large";
//					error::wallet_internal_error
					return false; // TODO:
				}
				if (original_output_index == dsts.size()) {
					dsts.push_back(tx_destination_entry(0, addr));
				}
				if (memcmp(&dsts[original_output_index].addr, &addr, sizeof(addr))) {
					// TODO
//					retVals.didError = true;
//					retVals.err_string = "Mismatched destination address";
					// error::wallet_internal_error
					return false;
				}
				dsts[original_output_index].amount += amount;
			}
			return true;
		}
	};
	std::vector<TX> txes;
	bool adding_fee; // true if new outputs go towards fee, rather than destinations
	uint64_t needed_fee, available_for_fee = 0;
	//
	uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit();
	//
	// TODO / FIXME:
	const bool use_rct = true;//use_fork_rules(4, 0); // TODO/FIXME
	//
	//
	std::vector<cryptonote::tx_destination_entry> dsts = args.dsts;
	std::vector<transfer_details> transfers = args.transfers;
	uint64_t blockchain_size = args.blockchain_size;
	const size_t fake_outs_count = monero_transfer_utils::fixed_mixinsize();
	const uint64_t unlock_time = args.unlock_time;
	uint32_t priority = args.priority;
	uint32_t default_priority = args.default_priority;
	bool is_testnet = args.is_testnet;
	//
	const uint64_t fee_per_kb  = per_kb_fee();
	const uint64_t fee_multiplier = get_fee_multiplier(
		priority,
		default_priority,
		fee_algorithm()
	);
	//
	// error if attempting a transaction with no destinations
	if (dsts.empty()) {
		retVals.didError = true;
		retVals.err_string = "No destination";
		// TODO
		// error::zero_destination
		return false;
	}
	//
	// calculate total amount being sent to all destinations
	// throw if total amount overflows uint64_t
	needed_money = 0;
	{
		for(auto& dt: dsts) {
			if (dt.amount == 0) {
				retVals.didError = true;
				retVals.err_string = "Zero destination";
				// TODO
				// error::zero_destination
				return false;
			}
			needed_money += dt.amount;
			LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
			if (needed_money < dt.amount) {
				retVals.didError = true;
				retVals.err_string = "Zero destination";
				// TODO
				// error::tx_sum_overflow, dsts, 0, m_testnet
				return false;
			}
		}
	}
	if (needed_money == 0) { // throw if attempting a transaction with no money
		retVals.didError = true;
		retVals.err_string = "Zero destination";
		// TODO
		// error::zero_destination
		return false;
	}
	//
	// gather all our dust and non dust outputs
	for (size_t i = 0; i < transfers.size(); ++i) {
		const transfer_details& td = transfers[i];
		if (!td.m_spent && (use_rct ? true : !td.is_rct()) && is_transfer_unlocked(td, blockchain_size, is_testnet)) {
			if ((td.is_rct()) || cryptonote::is_valid_decomposed_amount(td.amount())) {
				unused_transfers_indices.push_back(i);
			} else {
				unused_dust_indices.push_back(i);
			}
		}
	}
	LOG_PRINT_L2("Starting with " << unused_transfers_indices.size() << " non-dust outputs and " << unused_dust_indices.size() << " dust outputs");
	//
	uint64_t unlocked_balance = get_unlocked_balance(transfers, blockchain_size, is_testnet);
	//
	// early out if we know we can't make it anyway
	// we could also check for being within FEE_PER_KB, but if the fee calculation
	// ever changes, this might be missed, so let this go through
	bool has_enough_money = needed_money <= unlocked_balance;
	if (has_enough_money == false) {
		retVals.didError = true;
		retVals.err_string = "Zero destination";
		// TODO
		// error::not_enough_money, unlocked_balance, needed_money, 0
		return false;
	}
	if (unused_dust_indices.empty() && unused_transfers_indices.empty()) {
		retVals.didError = true;
		retVals.err_string = "No unused transferrable outs nor dusts";
		// TODO
		// matching err code
		return false;
	}
	// start with an empty tx
	txes.push_back(TX());
	accumulated_fee = 0;
	accumulated_outputs = 0;
	accumulated_change = 0;
	adding_fee = false;
	needed_fee = 0;
	std::vector<std::vector<get_outs_entry>> outs;
	//
	// for rct, since we don't see the amounts, we will try to make all transactions
	// look the same, with 1 or 2 inputs, and 2 outputs. One input is preferable, as
	// this prevents linking to another by provenance analysis, but two is ok if we
	// try to pick outputs not from the same block. We will get two outputs, one for
	// the destination, and one for change.
	LOG_PRINT_L2("checking preferred");
	std::vector<size_t> prefered_inputs;
	uint64_t rct_outs_needed = 2 * (fake_outs_count + 1);
	rct_outs_needed += 100; // some fudge factor since we don't know how many are locked
	if (use_rct && num_rct_outputs() >= rct_outs_needed) {
		// this is used to build a tx that's 1 or 2 inputs, and 2 outputs, which
		// will get us a known fee.
		uint64_t estimated_fee = calculated_fee(
			fee_per_kb,
			estimated_rct_tx_size(2, fake_outs_count + 1, 2),
			fee_multiplier
		);
		prefered_inputs = picked_preferred_rct_inputs(
			transfers,
			needed_money + estimated_fee,
			blockchain_size,
			is_testnet
		);
		if (!prefered_inputs.empty()) {
			string s;
			{
				for (auto i: prefered_inputs) {
					s += boost::lexical_cast<std::string>(i) + "(" + print_money(transfers[i].amount()) + ") ";
				}
			}
			LOG_PRINT_L1("Found prefered rct inputs for rct tx: " << s);
		}
	}
	LOG_PRINT_L2("done checking preferred");
	//
	cryptonote::account_keys account_keys = {};
	account_keys.m_view_secret_key = *(monero_key_utils::valid_sec_key_from(args.sec_viewKey_string));
	account_keys.m_spend_secret_key = *(monero_key_utils::valid_sec_key_from(args.sec_spendKey_string));
	// ^-- I have unwrapped these optionals without checking their nilness b/c I figure their failure/absence will indicate a consumer application code fault for calling construct tx with unverified inputs
	{
		cryptonote::account_public_address address = {};
		{
			crypto::public_key pub_viewKey;
			bool didSucceed = crypto::secret_key_to_public_key(account_keys.m_view_secret_key, pub_viewKey);
			if (!didSucceed) { // this would be a strange error indicating an application code fault
				retVals.didError = true;
				retVals.err_string = "Invalid view key";
				return false;
			}
			address.m_view_public_key = pub_viewKey;
		}
		{
			crypto::public_key pub_spendKey;
			bool didSucceed = crypto::secret_key_to_public_key(account_keys.m_spend_secret_key, pub_spendKey);
			if (!didSucceed) { // this would be a strange error indicating an application code fault
				retVals.didError = true;
				retVals.err_string = "Invalid spend key";
				return false;
			}
			address.m_spend_public_key = pub_spendKey;
		}
		account_keys.m_account_address = address;
	}
	//
	// Detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
	// TODO: factor this into monero_paymentID_utils
	std::vector<uint8_t> extra;
	bool payment_id_seen = false;
	{
		if (args.optl__payment_id_string) {
			std::string payment_id_str = *args.optl__payment_id_string; // copy
			//
			crypto::hash payment_id;
			bool r = monero_paymentID_utils::parse_long_payment_id(payment_id_str, payment_id);
			if (r) {
				std::string extra_nonce;
				cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
				r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
			} else {
				crypto::hash8 payment_id8;
				r = monero_paymentID_utils::parse_short_payment_id(payment_id_str, payment_id8);
				if (r) {
					std::string extra_nonce;
					cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
					r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
				}
			}
			if (!r) {
				retVals.didError = true;
				retVals.err_string = "payment id has invalid format, expected 16 or 64 character hex string";
				return false;
			}
			payment_id_seen = true;
		}
	}
	//
	unsigned int original_output_index = 0;
	while (
		(!dsts.empty() && dsts[0].amount > 0) // - we have something to send
		   || adding_fee // - or we need to gather more fee
		   || should_pick_a_second_output( // - or we have just one input in that tx, which is rct (to try and make all/most rct txes 2/2)
				use_rct,
				transfers,
				txes.back().selected_transfers.size(),
				unused_transfers_indices,
				unused_dust_indices
			)
	) {
		TX &tx = txes.back();
		
		LOG_PRINT_L2("Start of loop with " << unused_transfers_indices.size() << " " << unused_dust_indices.size());
		LOG_PRINT_L2("unused_transfers_indices:");
		for (auto t: unused_transfers_indices)
			LOG_PRINT_L2("  " << t);
		LOG_PRINT_L2("unused_dust_indices:");
		for (auto t: unused_dust_indices)
		LOG_PRINT_L2("  " << t);
		LOG_PRINT_L2("dsts size " << dsts.size() << ", first " << (dsts.empty() ? -1 : dsts[0].amount));
		LOG_PRINT_L2("adding_fee " << adding_fee << ", use_rct " << use_rct);
		//
		// if we need to spend money and don't have any left, we fail
		if (unused_dust_indices.empty() && unused_transfers_indices.empty()) {
			LOG_PRINT_L2("No more outputs to choose from");
			retVals.didError = true;
			retVals.err_string = "Transaction not possible";
			// TODO: retVals += error::tx_not_possible, get_unlocked_balance(transfers, blockchain_size, is_testnet), needed_money, accumulated_fee + needed_fee
			return false;
		}
		//
		// get a random unspent output and use it to pay part (or all) of the current destination (and maybe next one, etc)
		// This could be more clever, but maybe at the cost of making probabilistic inferences easier
		size_t idx;
		if ((dsts.empty() || dsts[0].amount == 0) && !adding_fee) {
			// the "make rct txes 2/2" case - we pick a small value output to "clean up" the wallet too
			std::vector<size_t> indices = get_only_rct(transfers, unused_dust_indices, unused_transfers_indices);
			idx = pop_best_value_from(transfers, indices, tx.selected_transfers, true);
			// we might not want to add it if it's a large output and we don't have many left
			if (transfers[idx].amount() >= args.min_output_value) {
				if (get_count_above(transfers, unused_transfers_indices, args.min_output_value) < args.min_output_count) {
					LOG_PRINT_L2("Second output was not strictly needed, and we're running out of outputs above " << print_money(args.min_output_value) << ", not adding");
					break;
				}
			}
			// since we're trying to add a second output which is not strictly needed,
			// we only add it if it's unrelated enough to the first one
			float relatedness = get_output_relatedness(transfers[idx], transfers[tx.selected_transfers.front()]);
			if (relatedness > SECOND_OUTPUT_RELATEDNESS_THRESHOLD) {
				LOG_PRINT_L2("Second output was not strictly needed, and relatedness " << relatedness << ", not adding");
				break;
			}
			pop_if_present(unused_transfers_indices, idx);
			pop_if_present(unused_dust_indices, idx);
		} else if (!prefered_inputs.empty()) {
			idx = pop_back(prefered_inputs);
			pop_if_present(unused_transfers_indices, idx);
			pop_if_present(unused_dust_indices, idx);
		} else {
			idx = pop_best_value_from(transfers, unused_transfers_indices.empty() ? unused_dust_indices : unused_transfers_indices, tx.selected_transfers);
		}
		const transfer_details &td = transfers[idx];
		LOG_PRINT_L2("Picking output " << idx << ", amount " << print_money(td.amount()) << ", ki " << td.m_key_image);
		
		// add this output to the list to spend
		tx.selected_transfers.push_back(idx);
		uint64_t available_amount = td.amount();
		accumulated_outputs += available_amount;
		
		// clear any fake outs we'd already gathered, since we'll need a new set
		outs.clear();
		
		if (adding_fee) {
			LOG_PRINT_L2("We need more fee, adding it to fee");
			available_for_fee += available_amount;
		} else {
			// FIXME: loss precision warnings:
			while (!dsts.empty() && dsts[0].amount <= available_amount && estimated_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size()) < TX_SIZE_TARGET(upper_transaction_size_limit)) {
				// we can fully pay that destination
				LOG_PRINT_L2("We can fully pay " << get_account_address_as_str(is_testnet, dsts[0].addr) <<
							 " for " << print_money(dsts[0].amount));
				bool didAdd = tx.add(dsts[0].addr, dsts[0].amount, original_output_index, args.merge_destinations);
				if (!didAdd) {
					// TODO: error here?
					return false;
				}
				available_amount -= dsts[0].amount;
				dsts[0].amount = 0;
				pop_index(dsts, 0);
				++original_output_index;
			}
			
			if (available_amount > 0 && !dsts.empty() && estimated_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size()) < TX_SIZE_TARGET(upper_transaction_size_limit)) {
				// we can partially fill that destination
				LOG_PRINT_L2("We can partially pay " << get_account_address_as_str(is_testnet, dsts[0].addr) <<
							 " for " << print_money(available_amount) << "/" << print_money(dsts[0].amount));
				bool didAdd = tx.add(dsts[0].addr, available_amount, original_output_index, args.merge_destinations);
				if (!didAdd) {
					// TODO: error here?
					return false;
				}
				dsts[0].amount -= available_amount;
				available_amount = 0;
			}
		}
		
		// here, check if we need to sent tx and start a new one
		LOG_PRINT_L2("Considering whether to create a tx now, " << tx.selected_transfers.size() << " inputs, tx limit "
					 << upper_transaction_size_limit);
		bool try_tx;
		if (adding_fee) {
			/* might not actually be enough if adding this output bumps size to next kB, but we need to try */
			try_tx = available_for_fee >= needed_fee;
		} else {
			const size_t estimated_rct_tx_size = estimated_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size());
			try_tx = dsts.empty() || (estimated_rct_tx_size >= TX_SIZE_TARGET(upper_transaction_size_limit));
		}
		//
		if (try_tx) {
			cryptonote::transaction test_tx;
			pending_tx test_ptx;
			
			needed_fee = 0;
			LOG_PRINT_L2("Trying to create a tx now, with " << tx.dsts.size() << " destinations and " <<
						 tx.selected_transfers.size() << " outputs");
			bool didSucceed = false;
			TransferSelected_ErrRetVals transferSelected_err_retVals;
			if (use_rct) {
				didSucceed = _transfer_selected_rct(account_keys, transfers, tx.dsts, tx.selected_transfers, args.get_random_outs_fn, fake_outs_count, outs, unlock_time, needed_fee, extra, test_tx, test_ptx, is_testnet, transferSelected_err_retVals);
			} else {
				didSucceed = _transfer_selected_nonrct(account_keys, transfers, tx.dsts, tx.selected_transfers, args.get_random_outs_fn, fake_outs_count, outs, unlock_time, needed_fee, extra, detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx, is_testnet, transferSelected_err_retVals);
			}
			if (didSucceed == false) {
				if (transferSelected_err_retVals.didError != true) {
					// TODO/FIXME: this would be a code fault... a good place to use an exception.
					retVals.didError = true;
					retVals.err_string = "Code fault; transfer_selected failed but didError=false";
				} else {
					retVals.didError = true;
					retVals.err_string = transferSelected_err_retVals.err_string; // FIXME: do away with extra copy?
				}
				return false;
			}
			auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
			needed_fee = calculated_fee(fee_per_kb, txBlob, fee_multiplier);
			available_for_fee = test_ptx.fee + test_ptx.change_dts.amount + (!test_ptx.dust_added_to_fee ? test_ptx.dust : 0);
			LOG_PRINT_L2("Made a " << ((txBlob.size() + 1023) / 1024) << " kB tx, with " << print_money(available_for_fee) << " available for fee (" <<
						 print_money(needed_fee) << " needed)");
			//
			if (needed_fee > available_for_fee && dsts[0].amount > 0) {
				// we don't have enough for the fee, but we've only partially paid the current address,
				// so we can take the fee from the paid amount, since we'll have to make another tx anyway
				std::vector<cryptonote::tx_destination_entry>::iterator i;
				i = std::find_if(tx.dsts.begin(), tx.dsts.end(),
								 [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &dsts[0].addr, sizeof(dsts[0].addr)); });
				if (i == tx.dsts.end()) {
					retVals.didError = true;
					retVals.err_string = "paid address not found in outputs";
					// TODO error::wallet_internal_error
					//
					return false;
				}
				if (i->amount > needed_fee) {
					uint64_t new_paid_amount = i->amount /*+ test_ptx.fee*/ - needed_fee;
					LOG_PRINT_L2("Adjusting amount paid to " << get_account_address_as_str(is_testnet, i->addr) << " from " <<
								 print_money(i->amount) << " to " << print_money(new_paid_amount) << " to accomodate " <<
								 print_money(needed_fee) << " fee");
					dsts[0].amount += i->amount - new_paid_amount;
					i->amount = new_paid_amount;
					test_ptx.fee = needed_fee;
					available_for_fee = needed_fee;
				}
			}
			if (needed_fee > available_for_fee) {
				LOG_PRINT_L2("We could not make a tx, switching to fee accumulation");
				adding_fee = true;
			} else {
				LOG_PRINT_L2("We made a tx, adjusting fee and saving it");
				bool didSucceed = false;
				do {
					TransferSelected_ErrRetVals transferSelected_err_retVals;
					if (use_rct) {
						didSucceed = _transfer_selected_rct(account_keys, transfers, tx.dsts, tx.selected_transfers, args.get_random_outs_fn, fake_outs_count, outs, unlock_time, needed_fee, extra, test_tx, test_ptx, is_testnet, transferSelected_err_retVals);
					} else {
						didSucceed = _transfer_selected_nonrct(account_keys, transfers, tx.dsts, tx.selected_transfers, args.get_random_outs_fn, fake_outs_count, outs, unlock_time, needed_fee, extra, detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx, is_testnet, transferSelected_err_retVals);
					}
					if (didSucceed == false) {
						if (transferSelected_err_retVals.didError != true) {
							// TODO/FIXME: this would be a code fault... a good place to use an exception.
							retVals.didError = true;
							retVals.err_string = "Code fault; transfer_selected failed but didError=false";
						} else {
							retVals.didError = true;
							retVals.err_string = transferSelected_err_retVals.err_string; // FIXME: do away with extra copy?
						}
						return false;
					}
					txBlob = t_serializable_object_to_blob(test_ptx.tx);
					needed_fee = calculated_fee(fee_per_kb, txBlob, fee_multiplier);
					LOG_PRINT_L2("Made an attempt at a  final " << ((txBlob.size() + 1023)/1024) << " kB tx, with " << print_money(test_ptx.fee) <<
								 " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
				} while (needed_fee > test_ptx.fee);
				
				LOG_PRINT_L2("Made a final " << ((txBlob.size() + 1023)/1024) << " kB tx, with " << print_money(test_ptx.fee) <<
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
				}
			}
		}
	}
	if (adding_fee) {
		LOG_PRINT_L1("We ran out of outputs while trying to gather final fee");
		retVals.didError = true;
		retVals.err_string = "transaction not possible - ran out of inputs for final fee";
		// TODO error::tx_not_possible, get_unlocked_balance(transfers, blockchain_size, is_testnet), needed_money, accumulated_fee + needed_fee
		return false;
	}
	LOG_PRINT_L1("Done creating " << txes.size() << " transactions, " << print_money(accumulated_fee) <<
				 " total fee, " << print_money(accumulated_change) << " total change");
	
	std::vector<pending_tx> ptx_vector;
	for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i) {
		TX &tx = *i;
		uint64_t tx_money = 0;
		for (size_t idx: tx.selected_transfers)
			tx_money += transfers[idx].amount();
		LOG_PRINT_L1("  Transaction " << (1+std::distance(txes.begin(), i)) << "/" << txes.size() <<
					 ": " << (tx.bytes+1023)/1024 << " kB, sending " << print_money(tx_money) << " in " << tx.selected_transfers.size() <<
					 " outputs to " << tx.dsts.size() << " destination(s), including " <<
					 print_money(tx.ptx.fee) << " fee, " << print_money(tx.ptx.change_dts.amount) << " change");
		ptx_vector.push_back(tx.ptx);
	}
	
	// if we made it this far, we're OK to actually send the transactions
	// TODO: acquire signed_tx_set from ptx_vector
	
	
	return true;
}
//
template<typename T>
bool monero_transfer_utils::_transfer_selected_nonrct(
	const cryptonote::account_keys &account_keys,
	const transfer_container &transfers,
	const std::vector<cryptonote::tx_destination_entry>& dsts,
	const std::list<size_t> selected_transfers,
	const std::function<bool(std::vector<std::vector<get_outs_entry>> &, const std::list<size_t> &, size_t)> get_random_outs_fn,
	size_t fake_outs_count,
	std::vector<std::vector<get_outs_entry>> &outs,
	uint64_t unlock_time,
	uint64_t fee,
	const std::vector<uint8_t>& extra,
	T destination_split_strategy,
	const tx_dust_policy& dust_policy,
	cryptonote::transaction& tx,
	pending_tx &ptx,
	bool is_testnet,
	TransferSelected_ErrRetVals &err_retVals
) {
	err_retVals = {};
	//
	if (dsts.empty()) { // throw if attempting a transaction with no destinations
		err_retVals.didError = true;
		err_retVals.err_string = "No destinations";
		// TODO error::zero_destination
		return false;
	}
	uint64_t needed_money = fee;
	LOG_PRINT_L2("transfer: starting with fee " << print_money (needed_money));
	//
	// calculate total amount being sent to all destinations
	// throw if total amount overflows uint64_t
	for(auto& dt: dsts) {
		if (0 == dt.amount) {
			err_retVals.didError = true;
			err_retVals.err_string = "Zero destination";
			// error::zero_destination
			return false;
		}
		needed_money += dt.amount;
		LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
		if (needed_money < dt.amount) {
			err_retVals.didError = false;
			err_retVals.err_string = "Transaction sum overflow";
			//
			// TODO: error::tx_sum_overflow, dsts, fee, is_testnet
			return false;
		}
	}

	uint64_t found_money = 0;
	for(size_t idx: selected_transfers) {
		found_money += transfers[idx].amount();
	}
	
	LOG_PRINT_L2("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
	if (found_money < needed_money) {
		err_retVals.didError = true;
		err_retVals.err_string = "Not enough money";
		// TODO: error::not_enough_money, found_money, needed_money - fee, fee
		return false;
	}
	if (outs.empty()) {
		bool r = get_random_outs_fn(outs, selected_transfers, fake_outs_count);
		if (r != true) {
			err_retVals.didError = false;
			err_retVals.err_string = "Unable to get random outputs";
			// TODO: error:: code?
			return false;
		}
	}
	//prepare inputs
	LOG_PRINT_L2("preparing outputs");
	typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
	size_t i = 0, out_index = 0;
	std::vector<cryptonote::tx_source_entry> sources;
	for(size_t idx: selected_transfers) {
		sources.resize(sources.size()+1);
		cryptonote::tx_source_entry& src = sources.back();
		const transfer_details& td = transfers[idx];
		src.amount = td.amount();
		src.rct = td.is_rct();
		//paste keys (fake and real)
		for (size_t n = 0; n < fake_outs_count + 1; ++n) {
			tx_output_entry oe;
			oe.first = std::get<0>(outs[out_index][n]);
			oe.second.dest = rct::pk2rct(std::get<1>(outs[out_index][n]));
			oe.second.mask = std::get<2>(outs[out_index][n]);
			
			src.outputs.push_back(oe);
			++i;
		}
		//
		//paste real transaction to the random index
		auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
		{
			return a.first == td.m_global_output_index;
		});
		THROW_WALLET_EXCEPTION_IF(it_to_replace == src.outputs.end(), error::wallet_internal_error, "real output not found"); // TODO/FIXME: is this an appropriate usage of an exception? if the condition is indicative of code fault in consumer or previous code, should be
		//
		tx_output_entry real_oe;
		real_oe.first = td.m_global_output_index;
		real_oe.second.dest = rct::pk2rct(boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key);
		real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
		*it_to_replace = real_oe;
		src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
		src.real_output = it_to_replace - src.outputs.begin();
		src.real_output_in_tx_index = td.m_internal_output_index;
		detail::print_source_entry(src);
		++out_index;
	}
	LOG_PRINT_L2("outputs prepared");
	
	cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
	if (needed_money < found_money) {
		change_dts.addr = account_keys.m_account_address;
		change_dts.amount = found_money - needed_money;
	}
	
	std::vector<cryptonote::tx_destination_entry> splitted_dsts, dust_dsts;
	uint64_t dust = 0;
	destination_split_strategy(dsts, change_dts, dust_policy.dust_threshold, splitted_dsts, dust_dsts);
	for(auto& d: dust_dsts) {
		if (dust_policy.dust_threshold < d.amount) {
			err_retVals.didError = true;
			err_retVals.err_string = "invalid dust value: dust = " + std::to_string(d.amount) + ", dust_threshold = " + std::to_string(dust_policy.dust_threshold);
			// TODO: error::wallet_internal_error
			return false;
		}
	}
	for(auto& d: dust_dsts) {
		if (!dust_policy.add_to_fee) {
			splitted_dsts.push_back(cryptonote::tx_destination_entry(d.amount, dust_policy.addr_for_dust));
		}
		dust += d.amount;
	}
	
	crypto::secret_key tx_key;
	LOG_PRINT_L2("constructing tx");
	bool didSucceed = cryptonote::construct_tx_and_get_tx_key(account_keys, sources, splitted_dsts, extra, tx, unlock_time, tx_key);
	LOG_PRINT_L2("constructed tx, r="<<didSucceed);
	if (didSucceed == false) {
		err_retVals.didError = true;
		err_retVals.err_string = "Error; Transaction not constructed";
		// TODO error::tx_not_constructed, sources, splitted_dsts, unlock_time, is_testnet
		return false;
	}
	uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit();
	if (upper_transaction_size_limit <= cryptonote::get_object_blobsize(tx)) {
		err_retVals.didError = true;
		err_retVals.err_string = "Error: transaction too big";
		// TODO? error::tx_too_big, tx, upper_transaction_size_limit
		return false;
	}
	std::string key_images;
	bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
	{
		CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
		key_images += boost::to_string(in.k_image) + " ";
		return true;
	});
	if (all_are_txin_to_key == false) {
		err_retVals.didError = true;
		err_retVals.err_string = "Unexpected txin type";
		// TODO error::unexpected_txin_type, tx
		return false;
	}
	//
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
	ptx.dests = dsts;
	ptx.construction_data.sources = sources;
	ptx.construction_data.change_dts = change_dts;
	ptx.construction_data.splitted_dsts = splitted_dsts;
	ptx.construction_data.selected_transfers = selected_transfers;
	ptx.construction_data.extra = tx.extra;
	ptx.construction_data.unlock_time = unlock_time;
	ptx.construction_data.use_rct = false;
	ptx.construction_data.dests = dsts;
	LOG_PRINT_L2("transfer_selected done");
	//
	return true;
}
//
bool monero_transfer_utils::_transfer_selected_rct(
	const cryptonote::account_keys &account_keys,
	const transfer_container &transfers,
	std::vector<cryptonote::tx_destination_entry> dsts,
	const std::list<size_t> selected_transfers,
	const std::function<bool(std::vector<std::vector<get_outs_entry>> &, const std::list<size_t> &, size_t)> get_random_outs_fn,
	size_t fake_outs_count,
	std::vector<std::vector<get_outs_entry>> &outs,
	uint64_t unlock_time,
	uint64_t fee,
	const std::vector<uint8_t>& extra,
	cryptonote::transaction& tx,
	pending_tx &ptx,
	bool is_testnet,
	TransferSelected_ErrRetVals &err_retVals
) {
	err_retVals = {};
	
	// throw if attempting a transaction with no destinations
	if (dsts.empty()) {
		err_retVals.didError = true;
		err_retVals.err_string = "No destinations";
		// TODO error::zero_destination
		return false;
	}
	uint64_t needed_money = fee;
	LOG_PRINT_L2("transfer_selected_rct: starting with fee " << print_money (needed_money));
	LOG_PRINT_L0("selected transfers: ");
	for (auto t: selected_transfers) {
		LOG_PRINT_L2("  " << t);
	}
	// calculate total amount being sent to all destinations
	// throw if total amount overflows uint64_t
	for(auto& dt: dsts) {
		if (dt.amount == 0) {
			err_retVals.didError = true;
			err_retVals.err_string = "No destinations";
			// TODO error::zero_destination
			return false;
		}
		needed_money += dt.amount;
		LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
		if (needed_money < dt.amount) {
			err_retVals.didError = true;
			err_retVals.err_string = "Transaction sum overflow";
			// TODO error::tx_sum_overflow, dsts, fee, is_testnet
			return false;
		}
	}
	uint64_t found_money = 0;
	for(size_t idx: selected_transfers) {
		found_money += transfers[idx].amount();
	}
	LOG_PRINT_L2("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
	if (found_money < needed_money) {
		err_retVals.didError = true;
		err_retVals.err_string = "Not enough money";
		// TODO error::not_enough_money, found_money, needed_money - fee, fee
		return false;
	}
	if (outs.empty()) {
		bool r = get_random_outs_fn(outs, selected_transfers, fake_outs_count);
		if (r != true) {
			err_retVals.didError = false;
			err_retVals.err_string = "Unable to get random outputs";
			// TODO: error:: code?
			return false;
		}
	}
	// prepare inputs
	LOG_PRINT_L2("preparing outputs");
	size_t i = 0, out_index = 0;
	std::vector<cryptonote::tx_source_entry> sources;
	for(size_t idx: selected_transfers) {
		sources.resize(sources.size()+1);
		cryptonote::tx_source_entry& src = sources.back();
		const transfer_details& td = transfers[idx];
		src.amount = td.amount();
		src.rct = td.is_rct();
		//paste mixin transaction
		//
		typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
		for (size_t n = 0; n < fake_outs_count + 1; ++n) {
			tx_output_entry oe;
			oe.first = std::get<0>(outs[out_index][n]);
			oe.second.dest = rct::pk2rct(std::get<1>(outs[out_index][n]));
			oe.second.mask = std::get<2>(outs[out_index][n]);
			src.outputs.push_back(oe);
		}
		++i;
		//
		//paste real transaction to the random index
		auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
		{
			return a.first == td.m_global_output_index;
		});
		if (it_to_replace == src.outputs.end()) {
			err_retVals.didError = true;
			err_retVals.err_string = "real output not found";
			// TODO error::wallet_internal_error
			return false;
		}
		//
		tx_output_entry real_oe;
		real_oe.first = td.m_global_output_index;
		real_oe.second.dest = rct::pk2rct(boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key);
		real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
		*it_to_replace = real_oe;
		src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
		src.real_output = it_to_replace - src.outputs.begin();
		src.real_output_in_tx_index = td.m_internal_output_index;
		src.mask = td.m_mask;
		detail::print_source_entry(src);
		++out_index;
	}
	LOG_PRINT_L2("outputs prepared");
	//
	// we still keep a copy, since we want to keep dsts free of change for user feedback purposes
	std::vector<cryptonote::tx_destination_entry> splitted_dsts = dsts;
	cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
	change_dts.amount = found_money - needed_money;
	if (change_dts.amount == 0) {
		// If the change is 0, send it to a random address, to avoid confusing
		// the sender with a 0 amount output. We send a 0 amount in order to avoid
		// letting the destination be able to work out which of the inputs is the
		// real one in our rings
		LOG_PRINT_L2("generating dummy address for 0 change");
		cryptonote::account_base dummy;
		dummy.generate();
		change_dts.addr = dummy.get_keys().m_account_address;
		LOG_PRINT_L2("generated dummy address for 0 change");
	} else {
		change_dts.addr = account_keys.m_account_address;
	}
	splitted_dsts.push_back(change_dts);
	//
	crypto::secret_key tx_key;
	LOG_PRINT_L2("constructing tx");
	bool didSucceed = cryptonote::construct_tx_and_get_tx_key(account_keys, sources, splitted_dsts, extra, tx, unlock_time, tx_key, true);
	if (didSucceed == false) {
		err_retVals.didError = true;
		err_retVals.err_string = "Error; Transaction not constructed";
		// TODO error::tx_not_constructed, sources, dsts, unlock_time, m_testnet
		return false;
	}
	uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit();
	if (upper_transaction_size_limit <= cryptonote::get_object_blobsize(tx)) {
		err_retVals.didError = true;
		err_retVals.err_string = "Error: transaction too big";
		// TODO? error::tx_too_big, tx, upper_transaction_size_limit
		return false;
	}
	//
	LOG_PRINT_L2("gathering key images");
	std::string key_images;
	bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
	{
		CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
		key_images += boost::to_string(in.k_image) + " ";
		return true;
	});
	if (all_are_txin_to_key == false) {
		err_retVals.didError = true;
		err_retVals.err_string = "Unexpected txin type";
		// TODO error::unexpected_txin_type, tx
		return false;
	}
	LOG_PRINT_L2("gathered key images");
	//
	ptx.key_images = key_images;
	ptx.fee = fee;
	ptx.dust = 0;
	ptx.dust_added_to_fee = false;
	ptx.tx = tx;
	ptx.change_dts = change_dts;
	ptx.selected_transfers = selected_transfers;
	ptx.tx_key = tx_key;
	ptx.dests = dsts;
	ptx.construction_data.sources = sources;
	ptx.construction_data.change_dts = change_dts;
	ptx.construction_data.splitted_dsts = splitted_dsts;
	ptx.construction_data.selected_transfers = selected_transfers;
	ptx.construction_data.extra = tx.extra;
	ptx.construction_data.unlock_time = unlock_time;
	ptx.construction_data.use_rct = true;
	ptx.construction_data.dests = dsts;
	LOG_PRINT_L2("transfer_selected_rct done");
	//
	return true;
}
//
uint64_t monero_transfer_utils::get_upper_transaction_size_limit()
{
	uint64_t full_reward_zone = CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;//use_fork_rules(5, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 : cryptonote::use_fork_rules(2, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
	// FIXME/TODO: Community audit: Please confirm this is correct -------^
	//
	return full_reward_zone - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}


//----------------------------------------------------------------------------------------------------
uint64_t monero_transfer_utils::get_fee_multiplier(
	uint32_t priority,
	uint32_t default_priority,
	int fee_algorithm
) {
	static const uint64_t old_multipliers[3] = {1, 2, 3};
	static const uint64_t new_multipliers[3] = {1, 20, 166};
	static const uint64_t newer_multipliers[4] = {1, 4, 20, 166};
	//
	// 0 -> default (here, x1 till fee algorithm 2, x4 from it)
	if (priority == 0) {
		priority = default_priority;
	}
	if (priority == 0) {
		if (fee_algorithm >= 2) {
			priority = 2;
		} else {
			priority = 1;
		}
	}
	//
	// 1 to 3/4 are allowed as priorities
	uint32_t max_priority = (fee_algorithm >= 2) ? 4 : 3;
	if (priority >= 1 && priority <= max_priority) {
		switch (fee_algorithm) {
			case 0: return old_multipliers[priority-1];
			case 1: return new_multipliers[priority-1];
			case 2: return newer_multipliers[priority-1];
			default: THROW_WALLET_EXCEPTION_IF(true, error::invalid_priority);
		}
	}
	//
	// TODO: throw exception
	// error::invalid_priority
	return 1;
}
//----------------------------------------------------------------------------------------------------
uint64_t monero_transfer_utils::dynamic_per_kb_fee_estimate()
{
//	uint64_t fee;
//	boost::optional<std::string> result = m_node_rpc_proxy.get_dynamic_per_kb_fee_estimate(FEE_ESTIMATE_GRACE_BLOCKS, fee);
//	if (!result)
//		return fee;
	// TODO: ability to inject m_node_rpc_proxy or fee per kb estimate service dependency?
	LOG_PRINT_L1("Failed to query per kB fee, using " << print_money(FEE_PER_KB));
	return FEE_PER_KB;
}
//----------------------------------------------------------------------------------------------------
uint64_t monero_transfer_utils::per_kb_fee()
{
	// TODO: reinstate fork rules checks?
//	bool use_dyn_fee = use_fork_rules(HF_VERSION_DYNAMIC_FEE, -720 * 1);
//	if (!use_dyn_fee) {
//		return FEE_PER_KB;
//	}
	return dynamic_per_kb_fee_estimate();
}
//----------------------------------------------------------------------------------------------------
int monero_transfer_utils::fee_algorithm()
{
	// TODO: reinstate fork rules checks?
	// changes at v3 and v5
//	if (use_fork_rules(5, 0))
		return 2;
//	if (use_fork_rules(3, -720 * 14))
//		return 1;
//	return 0;
}
//
uint64_t monero_transfer_utils::calculated_fee(uint64_t fee_per_kb, size_t bytes, uint64_t fee_multiplier)
{
	uint64_t kB = (bytes + 1023) / 1024;
	return kB * fee_per_kb * fee_multiplier;
}
uint64_t monero_transfer_utils::calculated_fee(uint64_t fee_per_kb, const cryptonote::blobdata &blob, uint64_t fee_multiplier)
{
	return calculated_fee(fee_per_kb, blob.size(), fee_multiplier);
}
//
size_t monero_transfer_utils::estimated_rct_tx_size(int n_inputs, int mixin, int n_outputs)
{
	size_t size = 0;
	//
	// tx prefix
	// first few bytes
	size += 1 + 6;
	// vin
	size += n_inputs * (1+6+(mixin+1)*2+32);
	// vout
	size += n_outputs * (6+32);
	// extra
	size += 40;
	//
	// rct signatures
	// type
	size += 1;
	// rangeSigs
	size += (2*64*32+32+64*32) * n_outputs;
	// MGs
	size += n_inputs * (32 * (mixin+1) + 32);
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
	//
	LOG_PRINT_L2("estimated rct tx size for " << n_inputs << " at mixin " << mixin << " and " << n_outputs << ": " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
	return size;
}
size_t monero_transfer_utils::estimated_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs)
{
	if (use_rct) {
		return estimated_rct_tx_size(n_inputs, mixin, n_outputs + 1);
	} else {
		return n_inputs * (mixin+1) * APPROXIMATE_INPUT_BYTES;
	}
}
//
uint64_t monero_transfer_utils::num_rct_outputs()
{
//	epee::json_rpc::request<cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request> req_t = AUTO_VAL_INIT(req_t);
//	epee::json_rpc::response<cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response, std::string> resp_t = AUTO_VAL_INIT(resp_t);
//	m_daemon_rpc_mutex.lock();
//	req_t.jsonrpc = "2.0";
//	req_t.id = epee::serialization::storage_entry(0);
//	req_t.method = "get_output_histogram";
//	req_t.params.amounts.push_back(0);
//	req_t.params.min_count = 0;
//	req_t.params.max_count = 0;
//	bool r = net_utils::invoke_http_json("/json_rpc", req_t, resp_t, m_http_client, rpc_timeout);
//	m_daemon_rpc_mutex.unlock();
//	THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_num_rct_outputs");
//	THROW_WALLET_EXCEPTION_IF(resp_t.result.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "get_output_histogram");
//	THROW_WALLET_EXCEPTION_IF(resp_t.result.status != CORE_RPC_STATUS_OK, error::get_histogram_error, resp_t.result.status);
//	THROW_WALLET_EXCEPTION_IF(resp_t.result.histogram.size() != 1, error::get_histogram_error, "Expected exactly one response");
//	THROW_WALLET_EXCEPTION_IF(resp_t.result.histogram[0].amount != 0, error::get_histogram_error, "Expected 0 amount");
//
//	return resp_t.result.histogram[0].total_instances;
	return 2; // TODO: what must this be?
}
std::vector<size_t> monero_transfer_utils::picked_preferred_rct_inputs(const transfer_container &transfers, uint64_t needed_money, uint64_t blockchain_size, bool is_testnet)
{
	std::vector<size_t> picks;
	float current_output_relatdness = 1.0f;
	
	LOG_PRINT_L2("picked_preferred_rct_inputs: needed_money " << print_money(needed_money));
	
	// try to find a rct input of enough size
	for (size_t i = 0; i < transfers.size(); ++i)
	{
		const transfer_details& td = transfers[i];
		if (!td.m_spent && td.is_rct() && td.amount() >= needed_money && is_transfer_unlocked(td, blockchain_size, is_testnet))
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
		const transfer_details& td = transfers[i];
		if (!td.m_spent && td.is_rct() && is_transfer_unlocked(td, blockchain_size, is_testnet))
		{
			LOG_PRINT_L2("Considering input " << i << ", " << print_money(td.amount()));
			for (size_t j = i + 1; j < transfers.size(); ++j)
			{
				const transfer_details& td2 = transfers[j];
				if (!td2.m_spent && td2.is_rct() && td.amount() + td2.amount() >= needed_money && is_transfer_unlocked(td2, blockchain_size, is_testnet))
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
bool monero_transfer_utils::should_pick_a_second_output(
	bool use_rct,
	const transfer_container &transfers,
	size_t n_transfers,
	const std::vector<size_t> &unused_transfers_indices,
	const std::vector<size_t> &unused_dust_indices
) {
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
size_t monero_transfer_utils::pop_best_value_from(const transfer_container &transfers, std::vector<size_t> &unused_indices, const std::list<size_t>& selected_transfers, bool smallest)
{
	std::vector<size_t> candidates;
	float best_relatedness = 1.0f;
	for (size_t n = 0; n < unused_indices.size(); ++n)
	{
		const transfer_details &candidate = transfers[unused_indices[n]];
		float relatedness = 0.0f;
		for (std::list<size_t>::const_iterator i = selected_transfers.begin(); i != selected_transfers.end(); ++i)
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
			const transfer_details &td = transfers[unused_indices[candidates[n]]];
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
std::vector<size_t> monero_transfer_utils::get_only_rct(const transfer_container &transfers, const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices)
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
uint32_t monero_transfer_utils::get_count_above(const transfer_container &transfers, const std::vector<size_t> &indices, uint64_t threshold)
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
float monero_transfer_utils::get_output_relatedness(
	const transfer_details &td0,
	const transfer_details &td1
) {
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
	const transfer_details& td,
	uint64_t blockchain_size, /* extracting wallet2->m_blockchain.size() */
	bool is_testnet
) {
	if (!is_tx_spendtime_unlocked(td.m_tx.unlock_time, td.m_block_height, blockchain_size, is_testnet)) {
		return false;
	}
	if (td.m_block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > blockchain_size) {
		return false;
	}
	return true;
}
bool monero_transfer_utils::is_tx_spendtime_unlocked(
	uint64_t unlock_time,
	uint64_t block_height,
	uint64_t blockchain_size, /* extracting wallet2->m_blockchain.size() */
	bool is_testnet
) {
	if (unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER) {
		//interpret as block index
		if(blockchain_size-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time) {
			return true;
		} else {
			return false;
		}
	} else {
		//interpret as time
		uint64_t current_time = static_cast<uint64_t>(time(NULL));
		// XXX: this needs to be fast, so we'd need to get the starting heights
		// from the daemon to be correct once voting kicks in
		uint64_t v2height = is_testnet ? 624634 : 1009827;
		uint64_t leeway = block_height < v2height ? CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1 : CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2;
		if (current_time + leeway >= unlock_time) {
			return true;
		} else {
			return false;
		}
	}
	return false;
}
//
// Wallet accounting
uint64_t monero_transfer_utils::get_unlocked_balance(const transfer_container &transfers, uint64_t blockchain_size, bool is_testnet)
{
	uint64_t balance = 0;
	for (const transfer_details& td: transfers) {
		if(!td.m_spent && is_transfer_unlocked(td, blockchain_size, is_testnet)) {
			balance += td.amount();
		}
	}
	return balance;
}
