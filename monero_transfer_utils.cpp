//
//  monero_transfer_utils.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 12/2/17.
//  Copyright © 2017 MyMonero. All rights reserved.
//
//
#include <random>
//
#include "monero_transfer_utils.hpp"
#include "monero_key_utils.hpp"
#include "monero_paymentID_utils.hpp"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "monero_transfer_utils.hpp"
#include "include_base_utils.h"
#include "monero_fork_rules.hpp"
//
using namespace std;
using namespace epee;
using namespace cryptonote;
using namespace tools; // for error::
using namespace monero_transfer_utils;
using namespace monero_fork_rules;
//
bool monero_transfer_utils::create_signed_transaction(
	const CreateTx_Args &args,
	CreateTx_RetVals &retVals
) {
	retVals = {};
	//
	// Detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
	// TODO: factor this into monero_paymentID_utils
	std::vector<uint8_t> extra;
	bool payment_id_seen = false;
	{
		bool r = false;
		if (args.optl__payment_id_string) {
			crypto::hash payment_id;
			r = monero_paymentID_utils::parse_long_payment_id((*args.optl__payment_id_string), payment_id);
			if (r) {
				std::string extra_nonce;
				cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
				r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
			} else {
				crypto::hash8 payment_id8;
				r = monero_paymentID_utils::parse_short_payment_id((*args.optl__payment_id_string), payment_id8);
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
	std::vector<cryptonote::tx_destination_entry> dsts;
	cryptonote::tx_destination_entry de;
	{
		bool r = false;
		cryptonote::address_parse_info info;
		r = cryptonote::get_account_address_from_str(info, args.is_testnet, args.to_address_string);
		if (!r) {
			retVals.didError = true;
			retVals.err_string = "couldn't parse address.";
			return false;
		}
		de.addr = info.address;
		de.is_subaddress = info.is_subaddress;
		//
		if (info.has_payment_id) {
			if (payment_id_seen) {
				retVals.didError = true;
				retVals.err_string = "a single transaction cannot use more than one payment id";
				return false;
			}
			std::string extra_nonce;
			set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, info.payment_id);
			bool r = add_extra_nonce_to_tx_extra(extra, extra_nonce);
			if (!r) {
				retVals.didError = true;
				retVals.err_string = "failed to set up payment id, though it was decoded correctly";
				return false;
			}
			payment_id_seen = true;
		}
		//
		r = cryptonote::parse_amount(de.amount, args.amount_float_string);
		THROW_WALLET_EXCEPTION_IF(
			!r || 0 == de.amount, error::wallet_internal_error,
			"amount is wrong... expected number from 0 to " + print_money(std::numeric_limits<uint64_t>::max())
		);
	}
	dsts.push_back(de);
	//
	uint64_t unlock_block = args.unlock_time;
	// TODO: support locked txs
//	if (transfer_type == TransferLocked) {
//		bc_height = get_daemon_blockchain_height(err);
//		if (!err.empty()) {
//			fail_msg_writer() << tr("failed to get blockchain height: ") << err;
//			return false;
//		}
//		unlock_block = bc_height + locked_blocks;
//	}
	std::vector<tools::wallet2::pending_tx> ptx_vector;
	ptx_vector = monero_transfer_utils::create_transactions_3(
		args.transfers,
		dsts,
		monero_transfer_utils::fixed_mixinsize(),
		unlock_block,
		args.per_kb_fee,
		args.blockchain_size,
		args.priority,
		args.default_priority,
		extra,
		args.upper_transaction_size_limit__or_0,
		args.current_subaddr_account,
		args.subaddr_indices,
		args.is_trusted_daemon,
		args.is_testnet,
		args.is_lightwallet
	);
	if (ptx_vector.empty()) {
		retVals.didError = true;
		retVals.err_string = "No outputs found, or daemon is not ready"; // TODO: improve error message appropriateness
		return false;
	}
	// TODO: detect and prompt user for multiple tx transfer
	// TODO: commit / sign and return transaction
	//
	return true;
}
std::vector<wallet2::pending_tx> monero_transfer_utils::create_transactions_3(
	std::vector<wallet2::transfer_details> transfers,
	std::vector<cryptonote::tx_destination_entry> dsts,
	const size_t fake_outs_count,
	const uint64_t per_kb_fee,
	const uint64_t unlock_time,
	uint64_t blockchain_size,
	uint32_t priority,
	uint32_t default_priority,
	const std::vector<uint8_t>& extra,
	uint64_t upper_transaction_size_limit__or_0,
	uint32_t subaddr_account,
	std::set<uint32_t> subaddr_indices,
	bool trusted_daemon,
	bool is_testnet,
	bool is_lightwallet
) {

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
	uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit(upper_transaction_size_limit__or_0);
	const bool use_rct = use_fork_rules(4, 0);
	const bool bulletproof = use_fork_rules(get_bulletproof_fork(is_testnet), 0);
	const uint64_t fee_multiplier = get_fee_multiplier(priority, default_priority, get_fee_algorithm());
	
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
//	std::map<uint32_t, uint64_t> balance_per_subaddr = balance_per_subaddress(transfers, unconfirmed_txs, subaddr_account);

	
	
	
	////// TODO:
	
	
	
	
	
	
	
	std::vector<wallet2::pending_tx> ptx_vector;
	// TODO
//	for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
//	{
//		TX &tx = *i;
//		uint64_t tx_money = 0;
//		for (size_t idx: tx.selected_transfers)
//			tx_money += m_transfers[idx].amount();
//		LOG_PRINT_L1("  Transaction " << (1+std::distance(txes.begin(), i)) << "/" << txes.size() <<
//					 ": " << get_size_string(tx.bytes) << ", sending " << print_money(tx_money) << " in " << tx.selected_transfers.size() <<
//					 " outputs to " << tx.dsts.size() << " destination(s), including " <<
//					 print_money(tx.ptx.fee) << " fee, " << print_money(tx.ptx.change_dts.amount) << " change");
//		ptx_vector.push_back(tx.ptx);
//	}

	// if we made it this far, we're OK to actually send the transactions
	return ptx_vector;
}
//


















//
uint64_t monero_transfer_utils::get_upper_transaction_size_limit(uint64_t upper_transaction_size_limit__or_0)
{
	if (upper_transaction_size_limit__or_0 > 0)
		return upper_transaction_size_limit__or_0;
	uint64_t full_reward_zone = monero_fork_rules::use_fork_rules(5, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 : monero_fork_rules::use_fork_rules(2, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
	return full_reward_zone - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}
uint64_t monero_transfer_utils::get_fee_multiplier(
	uint32_t priority,
	uint32_t default_priority,
	int fee_algorithm
) {
	static const uint64_t old_multipliers[3] = {1, 2, 3};
	static const uint64_t new_multipliers[3] = {1, 20, 166};
	static const uint64_t newer_multipliers[4] = {1, 4, 20, 166};
	
	if (fee_algorithm == -1)
		fee_algorithm = get_fee_algorithm();
	
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

int monero_transfer_utils::get_fee_algorithm()
{
	// changes at v3 and v5
	if (monero_fork_rules::use_fork_rules(5, 0))
		return 2;
	if (monero_fork_rules::use_fork_rules(3, -720 * 14))
		return 1;
	return 0;
}
//
//size_t monero_transfer_utils::estimated_rct_tx_size(int n_inputs, int mixin, int n_outputs)
//{
//	size_t size = 0;
//	//
//	// tx prefix
//	// first few bytes
//	size += 1 + 6;
//	// vin
//	size += n_inputs * (1+6+(mixin+1)*2+32);
//	// vout
//	size += n_outputs * (6+32);
//	// extra
//	size += 40;
//	//
//	// rct signatures
//	// type
//	size += 1;
//	// rangeSigs
//	size += (2*64*32+32+64*32) * n_outputs;
//	// MGs
//	size += n_inputs * (32 * (mixin+1) + 32);
//	// mixRing - not serialized, can be reconstructed
//	/* size += 2 * 32 * (mixin+1) * n_inputs; */
//	// pseudoOuts
//	size += 32 * n_inputs;
//	// ecdhInfo
//	size += 2 * 32 * n_outputs;
//	// outPk - only commitment is saved
//	size += 32 * n_outputs;
//	// txnFee
//	size += 4;
//	//
//	LOG_PRINT_L2("estimated rct tx size for " << n_inputs << " at mixin " << mixin << " and " << n_outputs << ": " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
//	return size;
//}
//size_t monero_transfer_utils::estimated_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs)
//{
//	if (use_rct) {
//		return estimated_rct_tx_size(n_inputs, mixin, n_outputs + 1);
//	} else {
//		return n_inputs * (mixin+1) * APPROXIMATE_INPUT_BYTES;
//	}
//}
////
//uint64_t monero_transfer_utils::num_rct_outputs()
//{
////	epee::json_rpc::request<cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request> req_t = AUTO_VAL_INIT(req_t);
////	epee::json_rpc::response<cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response, std::string> resp_t = AUTO_VAL_INIT(resp_t);
////	m_daemon_rpc_mutex.lock();
////	req_t.jsonrpc = "2.0";
////	req_t.id = epee::serialization::storage_entry(0);
////	req_t.method = "get_output_histogram";
////	req_t.params.amounts.push_back(0);
////	req_t.params.min_count = 0;
////	req_t.params.max_count = 0;
////	bool r = net_utils::invoke_http_json("/json_rpc", req_t, resp_t, m_http_client, rpc_timeout);
////	m_daemon_rpc_mutex.unlock();
////	THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_num_rct_outputs");
////	THROW_WALLET_EXCEPTION_IF(resp_t.result.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "get_output_histogram");
////	THROW_WALLET_EXCEPTION_IF(resp_t.result.status != CORE_RPC_STATUS_OK, error::get_histogram_error, resp_t.result.status);
////	THROW_WALLET_EXCEPTION_IF(resp_t.result.histogram.size() != 1, error::get_histogram_error, "Expected exactly one response");
////	THROW_WALLET_EXCEPTION_IF(resp_t.result.histogram[0].amount != 0, error::get_histogram_error, "Expected 0 amount");
////
////	return resp_t.result.histogram[0].total_instances;
//	return 2; // TODO: what must this be?
//}
//std::vector<size_t> monero_transfer_utils::picked_preferred_rct_inputs(const transfer_container &transfers, uint64_t needed_money, uint64_t blockchain_size, bool is_testnet)
//{
//	std::vector<size_t> picks;
//	float current_output_relatdness = 1.0f;
//	
//	LOG_PRINT_L2("picked_preferred_rct_inputs: needed_money " << print_money(needed_money));
//	
//	// try to find a rct input of enough size
//	for (size_t i = 0; i < transfers.size(); ++i)
//	{
//		const transfer_details& td = transfers[i];
//		if (!td.m_spent && td.is_rct() && td.amount() >= needed_money && is_transfer_unlocked(td, blockchain_size, is_testnet))
//		{
//			LOG_PRINT_L2("We can use " << i << " alone: " << print_money(td.amount()));
//			picks.push_back(i);
//			return picks;
//		}
//	}
//	
//	// then try to find two outputs
//	// this could be made better by picking one of the outputs to be a small one, since those
//	// are less useful since often below the needed money, so if one can be used in a pair,
//	// it gets rid of it for the future
//	for (size_t i = 0; i < transfers.size(); ++i)
//	{
//		const transfer_details& td = transfers[i];
//		if (!td.m_spent && td.is_rct() && is_transfer_unlocked(td, blockchain_size, is_testnet))
//		{
//			LOG_PRINT_L2("Considering input " << i << ", " << print_money(td.amount()));
//			for (size_t j = i + 1; j < transfers.size(); ++j)
//			{
//				const transfer_details& td2 = transfers[j];
//				if (!td2.m_spent && td2.is_rct() && td.amount() + td2.amount() >= needed_money && is_transfer_unlocked(td2, blockchain_size, is_testnet))
//				{
//					// update our picks if those outputs are less related than any we
//					// already found. If the same, don't update, and oldest suitable outputs
//					// will be used in preference.
//					float relatedness = get_output_relatedness(td, td2);
//					LOG_PRINT_L2("  with input " << j << ", " << print_money(td2.amount()) << ", relatedness " << relatedness);
//					if (relatedness < current_output_relatdness)
//					{
//						// reset the current picks with those, and return them directly
//						// if they're unrelated. If they are related, we'll end up returning
//						// them if we find nothing better
//						picks.clear();
//						picks.push_back(i);
//						picks.push_back(j);
//						LOG_PRINT_L0("we could use " << i << " and " << j);
//						if (relatedness == 0.0f)
//							return picks;
//						current_output_relatdness = relatedness;
//					}
//				}
//			}
//		}
//	}
//	
//	return picks;
//}
//bool monero_transfer_utils::should_pick_a_second_output(
//	bool use_rct,
//	const transfer_container &transfers,
//	size_t n_transfers,
//	const std::vector<size_t> &unused_transfers_indices,
//	const std::vector<size_t> &unused_dust_indices
//) {
//	if (!use_rct)
//		return false;
//	if (n_transfers > 1)
//		return false;
//	if (unused_dust_indices.empty() && unused_transfers_indices.empty())
//		return false;
//	// we want at least one free rct output to avoid a corner case where
//	// we'd choose a non rct output which doesn't have enough "siblings"
//	// value-wise on the chain, and thus can't be mixed
//	bool found = false;
//	for (auto i: unused_dust_indices)
//	{
//		if (transfers[i].is_rct())
//		{
//			found = true;
//			break;
//		}
//	}
//	if (!found) for (auto i: unused_transfers_indices)
//	{
//		if (transfers[i].is_rct())
//		{
//			found = true;
//			break;
//		}
//	}
//	if (!found)
//		return false;
//	return true;
//}
//size_t monero_transfer_utils::pop_best_value_from(const transfer_container &transfers, std::vector<size_t> &unused_indices, const std::list<size_t>& selected_transfers, bool smallest)
//{
//	std::vector<size_t> candidates;
//	float best_relatedness = 1.0f;
//	for (size_t n = 0; n < unused_indices.size(); ++n)
//	{
//		const transfer_details &candidate = transfers[unused_indices[n]];
//		float relatedness = 0.0f;
//		for (std::list<size_t>::const_iterator i = selected_transfers.begin(); i != selected_transfers.end(); ++i)
//		{
//			float r = get_output_relatedness(candidate, transfers[*i]);
//			if (r > relatedness)
//			{
//				relatedness = r;
//				if (relatedness == 1.0f)
//					break;
//			}
//		}
//		
//		if (relatedness < best_relatedness)
//		{
//			best_relatedness = relatedness;
//			candidates.clear();
//		}
//		
//		if (relatedness == best_relatedness)
//			candidates.push_back(n);
//	}
//	
//	// we have all the least related outputs in candidates, so we can pick either
//	// the smallest, or a random one, depending on request
//	size_t idx;
//	if (smallest)
//	{
//		idx = 0;
//		for (size_t n = 0; n < candidates.size(); ++n)
//		{
//			const transfer_details &td = transfers[unused_indices[candidates[n]]];
//			if (td.amount() < transfers[unused_indices[candidates[idx]]].amount())
//				idx = n;
//		}
//	}
//	else
//	{
//		idx = crypto::rand<size_t>() % candidates.size();
//	}
//	return pop_index (unused_indices, candidates[idx]);
//}
//std::vector<size_t> monero_transfer_utils::get_only_rct(const transfer_container &transfers, const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices)
//{
//	std::vector<size_t> indices;
//	for (size_t n: unused_dust_indices)
//		if (transfers[n].is_rct())
//			indices.push_back(n);
//	for (size_t n: unused_transfers_indices)
//		if (transfers[n].is_rct())
//			indices.push_back(n);
//	return indices;
//}
//uint32_t monero_transfer_utils::get_count_above(const transfer_container &transfers, const std::vector<size_t> &indices, uint64_t threshold)
//{
//	uint32_t count = 0;
//	for (size_t idx: indices)
//		if (transfers[idx].amount() >= threshold)
//			++count;
//	return count;
//}
//// This returns a handwavy estimation of how much two outputs are related
//// If they're from the same tx, then they're fully related. From close block
//// heights, they're kinda related. The actual values don't matter, just
//// their ordering, but it could become more murky if we add scores later.
//float monero_transfer_utils::get_output_relatedness(
//	const transfer_details &td0,
//	const transfer_details &td1
//) {
//	int dh;
//	
//	// expensive test, and same tx will fall onto the same block height below
//	if (td0.m_txid == td1.m_txid)
//		return 1.0f;
//	
//	// same block height -> possibly tx burst, or same tx (since above is disabled)
//	dh = td0.m_block_height > td1.m_block_height ? td0.m_block_height - td1.m_block_height : td1.m_block_height - td0.m_block_height;
//	if (dh == 0)
//		return 0.9f;
//	
//	// adjacent blocks -> possibly tx burst
//	if (dh == 1)
//		return 0.8f;
//	
//	// could extract the payment id, and compare them, but this is a bit expensive too
//	
//	// similar block heights
//	if (dh < 10)
//		return 0.2f;
//	
//	// don't think these are particularly related
//	return 0.0f;
//}
////
////
//// Transfer parsing/derived properties
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
	uint64_t blockchain_size, /* extracting wallet2->m_blockchain.size() */
	bool is_testnet
) {
	return is_transfer_unlocked(td.m_tx.unlock_time, td.m_block_height, blockchain_size, is_testnet);
}
bool monero_transfer_utils::is_tx_spendtime_unlocked(
	uint64_t unlock_time,
	uint64_t block_height,
	uint64_t blockchain_size, /* extracting wallet2->m_blockchain.size() / m_local_bc_height */
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
