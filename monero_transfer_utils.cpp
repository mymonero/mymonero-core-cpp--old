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
	cryptonote::account_keys account_keys = {};
	{
		bool r = false;
		r = string_tools::hex_to_pod(args.sec_viewKey_string, account_keys.m_view_secret_key);
		if (!r) {
			retVals.didError = true;
			retVals.err_string = "Invalid secret view key";
			// TODO: code?
			return false;
		}
		r = string_tools::hex_to_pod(args.sec_spendKey_string, account_keys.m_spend_secret_key);
		if (!r) {
			retVals.didError = true;
			retVals.err_string = "Invalid secret spend key";
			// TODO: code?
			return false;
		}
		cryptonote::account_public_address address = {};
		{
			crypto::public_key pub_viewKey;
			r = crypto::secret_key_to_public_key(account_keys.m_view_secret_key, pub_viewKey);
			if (!r) { // this would be a strange error indicating an application code fault
				retVals.didError = true;
				retVals.err_string = "Invalid view key";
				return false;
			}
			address.m_view_public_key = pub_viewKey;
			//
			crypto::public_key pub_spendKey;
			r = crypto::secret_key_to_public_key(account_keys.m_spend_secret_key, pub_spendKey);
			if (!r) { // this would be a strange error indicating an application code fault
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
	ptx_vector = monero_transfer_utils::create_transactions_2(
		args.transfers,
		dsts,
		monero_transfer_utils::fixed_mixinsize(),
		unlock_block,
		args.blockchain_size,
		args.priority,
		args.default_priority,
		extra,
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
std::vector<wallet2::pending_tx> monero_transfer_utils::create_transactions_2(
	std::vector<wallet2::transfer_details> transfers,
	std::vector<cryptonote::tx_destination_entry> dsts,
	const size_t fake_outs_count,
	const uint64_t unlock_time,
	uint64_t blockchain_size,
	uint32_t priority,
	uint32_t default_priority,
	const std::vector<uint8_t>& extra,
	uint32_t subaddr_account,
	std::set<uint32_t> subaddr_indices,
	bool trusted_daemon,
	bool is_testnet,
	bool is_lightwallet
) {
//	if(m_light_wallet) {
//		// Populate m_transfers
//		light_wallet_get_unspent_outs();
//	}
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
	uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit();
	const bool use_rct = use_fork_rules(4, 0);
	const bool bulletproof = use_fork_rules(get_bulletproof_fork(is_testnet), 0);
	const uint64_t fee_per_kb  = get_per_kb_fee(is_lightwallet);
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
////
//	if (subaddr_indices.empty()) // "index=<N1>[,<N2>,...]" wasn't specified -> use all the indices with non-zero unlocked balance
//	{
//		for (const auto& i : balance_per_subaddr)
//			subaddr_indices.insert(i.first);
//	}
//
//	// early out if we know we can't make it anyway
//	// we could also check for being within FEE_PER_KB, but if the fee calculation
//	// ever changes, this might be missed, so let this go through
//	uint64_t balance_subtotal = 0;
//	uint64_t unlocked_balance_subtotal = 0;
//	for (uint32_t index_minor : subaddr_indices)
//	{
//		balance_subtotal += balance_per_subaddr[index_minor];
//		unlocked_balance_subtotal += unlocked_balance_per_subaddr[index_minor];
//	}
//	THROW_WALLET_EXCEPTION_IF(needed_money > balance_subtotal, error::not_enough_money,
//							  balance_subtotal, needed_money, 0);
//	// first check overall balance is enough, then unlocked one, so we throw distinct exceptions
//	THROW_WALLET_EXCEPTION_IF(needed_money > unlocked_balance_subtotal, error::not_enough_unlocked_money,
//							  unlocked_balance_subtotal, needed_money, 0);
//
//	for (uint32_t i : subaddr_indices)
//		LOG_PRINT_L2("Candidate subaddress index for spending: " << i);
//
//	// gather all dust and non-dust outputs belonging to specified subaddresses
//	size_t num_nondust_outputs = 0;
//	size_t num_dust_outputs = 0;
//	for (size_t i = 0; i < transfers.size(); ++i)
//	{
//		const transfer_details& td = transfers[i];
//		if (!td.m_spent && !td.m_key_image_partial && (use_rct ? true : !td.is_rct()) && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
//		{
//			const uint32_t index_minor = td.m_subaddr_index.minor;
//			auto find_predicate = [&index_minor](const std::pair<uint32_t, std::vector<size_t>>& x) { return x.first == index_minor; };
//			if ((td.is_rct()) || is_valid_decomposed_amount(td.amount()))
//			{
//				auto found = std::find_if(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), find_predicate);
//				if (found == unused_transfers_indices_per_subaddr.end())
//				{
//					unused_transfers_indices_per_subaddr.push_back({index_minor, {i}});
//				}
//				else
//				{
//					found->second.push_back(i);
//				}
//				++num_nondust_outputs;
//			}
//			else
//			{
//				auto found = std::find_if(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), find_predicate);
//				if (found == unused_dust_indices_per_subaddr.end())
//				{
//					unused_dust_indices_per_subaddr.push_back({index_minor, {i}});
//				}
//				else
//				{
//					found->second.push_back(i);
//				}
//				++num_dust_outputs;
//			}
//		}
//	}
//
//	// shuffle & sort output indices
//	{
//		std::random_device rd;
//		std::mt19937 g(rd());
//		std::shuffle(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), g);
//		std::shuffle(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), g);
//		auto sort_predicate = [&unlocked_balance_per_subaddr] (const std::pair<uint32_t, std::vector<size_t>>& x, const std::pair<uint32_t, std::vector<size_t>>& y)
//		{
//			return unlocked_balance_per_subaddr[x.first] > unlocked_balance_per_subaddr[y.first];
//		};
//		std::sort(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), sort_predicate);
//		std::sort(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), sort_predicate);
//	}
//
//	LOG_PRINT_L2("Starting with " << num_nondust_outputs << " non-dust outputs and " << num_dust_outputs << " dust outputs");
//
//	if (unused_dust_indices_per_subaddr.empty() && unused_transfers_indices_per_subaddr.empty())
//		return std::vector<wallet2::pending_tx>();
//
//	// if empty, put dummy entry so that the front can be referenced later in the loop
//	if (unused_dust_indices_per_subaddr.empty())
//		unused_dust_indices_per_subaddr.push_back({});
//	if (unused_transfers_indices_per_subaddr.empty())
//		unused_transfers_indices_per_subaddr.push_back({});
//
//	// start with an empty tx
//	txes.push_back(TX());
//	accumulated_fee = 0;
//	accumulated_outputs = 0;
//	accumulated_change = 0;
//	adding_fee = false;
//	needed_fee = 0;
//	std::vector<std::vector<get_outs_entry>> outs;
//
//	// for rct, since we don't see the amounts, we will try to make all transactions
//	// look the same, with 1 or 2 inputs, and 2 outputs. One input is preferable, as
//	// this prevents linking to another by provenance analysis, but two is ok if we
//	// try to pick outputs not from the same block. We will get two outputs, one for
//	// the destination, and one for change.
//	LOG_PRINT_L2("checking preferred");
//	std::vector<size_t> preferred_inputs;
//	uint64_t rct_outs_needed = 2 * (fake_outs_count + 1);
//	rct_outs_needed += 100; // some fudge factor since we don't know how many are locked
//	if (use_rct)
//	{
//		// this is used to build a tx that's 1 or 2 inputs, and 2 outputs, which
//		// will get us a known fee.
//		uint64_t estimated_fee = calculate_fee(fee_per_kb, estimate_rct_tx_size(2, fake_outs_count, 2, extra.size(), bulletproof), fee_multiplier);
//		preferred_inputs = pick_preferred_rct_inputs(needed_money + estimated_fee, subaddr_account, subaddr_indices);
//		if (!preferred_inputs.empty())
//		{
//			string s;
//			for (auto i: preferred_inputs) s += boost::lexical_cast<std::string>(i) + " (" + print_money(m_transfers[i].amount()) + ") ";
//			LOG_PRINT_L1("Found prefered rct inputs for rct tx: " << s);
//
//			// bring the list of available outputs stored by the same subaddress index to the front of the list
//			uint32_t index_minor = m_transfers[preferred_inputs[0]].m_subaddr_index.minor;
//			for (size_t i = 1; i < unused_transfers_indices_per_subaddr.size(); ++i)
//			{
//				if (unused_transfers_indices_per_subaddr[i].first == index_minor)
//				{
//					std::swap(unused_transfers_indices_per_subaddr[0], unused_transfers_indices_per_subaddr[i]);
//					break;
//				}
//			}
//			for (size_t i = 1; i < unused_dust_indices_per_subaddr.size(); ++i)
//			{
//				if (unused_dust_indices_per_subaddr[i].first == index_minor)
//				{
//					std::swap(unused_dust_indices_per_subaddr[0], unused_dust_indices_per_subaddr[i]);
//					break;
//				}
//			}
//		}
//	}
//	LOG_PRINT_L2("done checking preferred");
//
//	// while:
//	// - we have something to send
//	// - or we need to gather more fee
//	// - or we have just one input in that tx, which is rct (to try and make all/most rct txes 2/2)
//	unsigned int original_output_index = 0;
//	std::vector<size_t>* unused_transfers_indices = &unused_transfers_indices_per_subaddr[0].second;
//	std::vector<size_t>* unused_dust_indices      = &unused_dust_indices_per_subaddr[0].second;
//	while ((!dsts.empty() && dsts[0].amount > 0) || adding_fee || !preferred_inputs.empty() || should_pick_a_second_output(use_rct, txes.back().selected_transfers.size(), *unused_transfers_indices, *unused_dust_indices)) {
//		TX &tx = txes.back();
//
//		LOG_PRINT_L2("Start of loop with " << unused_transfers_indices->size() << " " << unused_dust_indices->size());
//		LOG_PRINT_L2("unused_transfers_indices: " << strjoin(*unused_transfers_indices, " "));
//		LOG_PRINT_L2("unused_dust_indices: " << strjoin(*unused_dust_indices, " "));
//		LOG_PRINT_L2("dsts size " << dsts.size() << ", first " << (dsts.empty() ? "-" : cryptonote::print_money(dsts[0].amount)));
//		LOG_PRINT_L2("adding_fee " << adding_fee << ", use_rct " << use_rct);
//
//		// if we need to spend money and don't have any left, we fail
//		if (unused_dust_indices->empty() && unused_transfers_indices->empty()) {
//			LOG_PRINT_L2("No more outputs to choose from");
//			THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance(subaddr_account), needed_money, accumulated_fee + needed_fee);
//		}
//
//		// get a random unspent output and use it to pay part (or all) of the current destination (and maybe next one, etc)
//		// This could be more clever, but maybe at the cost of making probabilistic inferences easier
//		size_t idx;
//		if (!preferred_inputs.empty()) {
//			idx = pop_back(preferred_inputs);
//			pop_if_present(*unused_transfers_indices, idx);
//			pop_if_present(*unused_dust_indices, idx);
//		} else if ((dsts.empty() || dsts[0].amount == 0) && !adding_fee) {
//			// the "make rct txes 2/2" case - we pick a small value output to "clean up" the wallet too
//			std::vector<size_t> indices = get_only_rct(*unused_dust_indices, *unused_transfers_indices);
//			idx = pop_best_value(indices, tx.selected_transfers, true);
//
//			// we might not want to add it if it's a large output and we don't have many left
//			if (m_transfers[idx].amount() >= m_min_output_value) {
//				if (get_count_above(m_transfers, *unused_transfers_indices, m_min_output_value) < m_min_output_count) {
//					LOG_PRINT_L2("Second output was not strictly needed, and we're running out of outputs above " << print_money(m_min_output_value) << ", not adding");
//					break;
//				}
//			}
//
//			// since we're trying to add a second output which is not strictly needed,
//			// we only add it if it's unrelated enough to the first one
//			float relatedness = get_output_relatedness(m_transfers[idx], m_transfers[tx.selected_transfers.front()]);
//			if (relatedness > SECOND_OUTPUT_RELATEDNESS_THRESHOLD)
//			{
//				LOG_PRINT_L2("Second output was not strictly needed, and relatedness " << relatedness << ", not adding");
//				break;
//			}
//			pop_if_present(*unused_transfers_indices, idx);
//			pop_if_present(*unused_dust_indices, idx);
//		} else
//			idx = pop_best_value(unused_transfers_indices->empty() ? *unused_dust_indices : *unused_transfers_indices, tx.selected_transfers);
//
//		const transfer_details &td = m_transfers[idx];
//		LOG_PRINT_L2("Picking output " << idx << ", amount " << print_money(td.amount()) << ", ki " << td.m_key_image);
//
//		// add this output to the list to spend
//		tx.selected_transfers.push_back(idx);
//		uint64_t available_amount = td.amount();
//		accumulated_outputs += available_amount;
//
//		// clear any fake outs we'd already gathered, since we'll need a new set
//		outs.clear();
//
//		if (adding_fee)
//		{
//			LOG_PRINT_L2("We need more fee, adding it to fee");
//			available_for_fee += available_amount;
//		}
//		else
//		{
//			while (!dsts.empty() && dsts[0].amount <= available_amount && estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof) < TX_SIZE_TARGET(upper_transaction_size_limit))
//			{
//				// we can fully pay that destination
//				LOG_PRINT_L2("We can fully pay " << get_account_address_as_str(m_testnet, dsts[0].is_subaddress, dsts[0].addr) <<
//							 " for " << print_money(dsts[0].amount));
//				tx.add(dsts[0].addr, dsts[0].is_subaddress, dsts[0].amount, original_output_index, m_merge_destinations);
//				available_amount -= dsts[0].amount;
//				dsts[0].amount = 0;
//				pop_index(dsts, 0);
//				++original_output_index;
//			}
//
//			if (available_amount > 0 && !dsts.empty() && estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof) < TX_SIZE_TARGET(upper_transaction_size_limit)) {
//				// we can partially fill that destination
//				LOG_PRINT_L2("We can partially pay " << get_account_address_as_str(m_testnet, dsts[0].is_subaddress, dsts[0].addr) <<
//							 " for " << print_money(available_amount) << "/" << print_money(dsts[0].amount));
//				tx.add(dsts[0].addr, dsts[0].is_subaddress, available_amount, original_output_index, m_merge_destinations);
//				dsts[0].amount -= available_amount;
//				available_amount = 0;
//			}
//		}
//
//		// here, check if we need to sent tx and start a new one
//		LOG_PRINT_L2("Considering whether to create a tx now, " << tx.selected_transfers.size() << " inputs, tx limit "
//					 << upper_transaction_size_limit);
//		bool try_tx = false;
//		// if we have preferred picks, but haven't yet used all of them, continue
//		if (preferred_inputs.empty())
//		{
//			if (adding_fee)
//			{
//				/* might not actually be enough if adding this output bumps size to next kB, but we need to try */
//				try_tx = available_for_fee >= needed_fee;
//			}
//			else
//			{
//				const size_t estimated_rct_tx_size = estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof);
//				try_tx = dsts.empty() || (estimated_rct_tx_size >= TX_SIZE_TARGET(upper_transaction_size_limit));
//			}
//		}
//
//		if (try_tx) {
//			cryptonote::transaction test_tx;
//			pending_tx test_ptx;
//
//			const size_t estimated_tx_size = estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof);
//			needed_fee = calculate_fee(fee_per_kb, estimated_tx_size, fee_multiplier);
//
//			LOG_PRINT_L2("Trying to create a tx now, with " << tx.dsts.size() << " outputs and " <<
//						 tx.selected_transfers.size() << " inputs");
//			if (use_rct)
//				transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
//									  test_tx, test_ptx, bulletproof);
//			else
//				transfer_selected(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
//								  detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx);
//			auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
//			needed_fee = calculate_fee(fee_per_kb, txBlob, fee_multiplier);
//			available_for_fee = test_ptx.fee + test_ptx.change_dts.amount + (!test_ptx.dust_added_to_fee ? test_ptx.dust : 0);
//			LOG_PRINT_L2("Made a " << get_size_string(txBlob) << " tx, with " << print_money(available_for_fee) << " available for fee (" <<
//						 print_money(needed_fee) << " needed)");
//
//			if (needed_fee > available_for_fee && !dsts.empty() && dsts[0].amount > 0)
//			{
//				// we don't have enough for the fee, but we've only partially paid the current address,
//				// so we can take the fee from the paid amount, since we'll have to make another tx anyway
//				std::vector<cryptonote::tx_destination_entry>::iterator i;
//				i = std::find_if(tx.dsts.begin(), tx.dsts.end(),
//								 [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &dsts[0].addr, sizeof(dsts[0].addr)); });
//				THROW_WALLET_EXCEPTION_IF(i == tx.dsts.end(), error::wallet_internal_error, "paid address not found in outputs");
//				if (i->amount > needed_fee)
//				{
//					uint64_t new_paid_amount = i->amount /*+ test_ptx.fee*/ - needed_fee;
//					LOG_PRINT_L2("Adjusting amount paid to " << get_account_address_as_str(m_testnet, i->is_subaddress, i->addr) << " from " <<
//								 print_money(i->amount) << " to " << print_money(new_paid_amount) << " to accommodate " <<
//								 print_money(needed_fee) << " fee");
//					dsts[0].amount += i->amount - new_paid_amount;
//					i->amount = new_paid_amount;
//					test_ptx.fee = needed_fee;
//					available_for_fee = needed_fee;
//				}
//			}
//
//			if (needed_fee > available_for_fee)
//			{
//				LOG_PRINT_L2("We could not make a tx, switching to fee accumulation");
//
//				adding_fee = true;
//			}
//			else
//			{
//				LOG_PRINT_L2("We made a tx, adjusting fee and saving it, we need " << print_money(needed_fee) << " and we have " << print_money(test_ptx.fee));
//				while (needed_fee > test_ptx.fee) {
//					if (use_rct)
//						transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
//											  test_tx, test_ptx, bulletproof);
//					else
//						transfer_selected(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
//										  detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx);
//					txBlob = t_serializable_object_to_blob(test_ptx.tx);
//					needed_fee = calculate_fee(fee_per_kb, txBlob, fee_multiplier);
//					LOG_PRINT_L2("Made an attempt at a  final " << get_size_string(txBlob) << " tx, with " << print_money(test_ptx.fee) <<
//								 " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
//				}
//
//				LOG_PRINT_L2("Made a final " << get_size_string(txBlob) << " tx, with " << print_money(test_ptx.fee) <<
//							 " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
//
//				tx.tx = test_tx;
//				tx.ptx = test_ptx;
//				tx.bytes = txBlob.size();
//				accumulated_fee += test_ptx.fee;
//				accumulated_change += test_ptx.change_dts.amount;
//				adding_fee = false;
//				if (!dsts.empty())
//				{
//					LOG_PRINT_L2("We have more to pay, starting another tx");
//					txes.push_back(TX());
//					original_output_index = 0;
//				}
//			}
//		}
//
//		// if unused_*_indices is empty while unused_*_indices_per_subaddr has multiple elements, and if we still have something to pay,
//		// pop front of unused_*_indices_per_subaddr and have unused_*_indices point to the front of unused_*_indices_per_subaddr
//		if ((!dsts.empty() && dsts[0].amount > 0) || adding_fee)
//		{
//			if (unused_transfers_indices->empty() && unused_transfers_indices_per_subaddr.size() > 1)
//			{
//				unused_transfers_indices_per_subaddr.erase(unused_transfers_indices_per_subaddr.begin());
//				unused_transfers_indices = &unused_transfers_indices_per_subaddr[0].second;
//			}
//			if (unused_dust_indices->empty() && unused_dust_indices_per_subaddr.size() > 1)
//			{
//				unused_dust_indices_per_subaddr.erase(unused_dust_indices_per_subaddr.begin());
//				unused_dust_indices = &unused_dust_indices_per_subaddr[0].second;
//			}
//		}
//	}
//
//	if (adding_fee)
//	{
//		LOG_PRINT_L1("We ran out of outputs while trying to gather final fee");
//		THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance(subaddr_account), needed_money, accumulated_fee + needed_fee);
//	}
//
//	LOG_PRINT_L1("Done creating " << txes.size() << " transactions, " << print_money(accumulated_fee) <<
//				 " total fee, " << print_money(accumulated_change) << " total change");

	std::vector<wallet2::pending_tx> ptx_vector;
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
uint64_t monero_transfer_utils::get_upper_transaction_size_limit()
{
//	if (m_upper_transaction_size_limit > 0)
//		return m_upper_transaction_size_limit;
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
//----------------------------------------------------------------------------------------------------
uint64_t monero_transfer_utils::get_dynamic_per_kb_fee_estimate()
{
	// TODO: pass std function for this or have consumer pass it in as arg … we're never going to use it in the lightwallet anyway
//	uint64_t fee;
//	boost::optional<std::string> result = m_node_rpc_proxy.get_dynamic_per_kb_fee_estimate(FEE_ESTIMATE_GRACE_BLOCKS, fee);
//	if (!result)
//		return fee;
	LOG_PRINT_L1("Failed to query per kB fee, using " << print_money(FEE_PER_KB));
	return FEE_PER_KB;
}
uint64_t monero_transfer_utils::get_per_kb_fee(bool is_light_wallet)
{
	if(is_light_wallet)
		return FEE_PER_KB; // aka m_light_wallet_per_kb_fee
	bool use_dyn_fee = use_fork_rules(HF_VERSION_DYNAMIC_FEE, -720 * 1);
	if (!use_dyn_fee)
		return FEE_PER_KB;
	
	return get_dynamic_per_kb_fee_estimate();
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

size_t monero_transfer_utils::fixed_ringsize()
{
	return 10; // TODO/FIXME: temporary…… for lightwallet code!
}
size_t monero_transfer_utils::fixed_mixinsize()
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
void monero_transfer_utils::set_spent(transfer_details &td, uint64_t height)
{
	LOG_PRINT_L2("Setting SPENT at " << height << ": ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
	td.m_spent = true;
	td.m_spent_height = height;
}
void monero_transfer_utils::set_unspent(transfer_details &td)
{
	LOG_PRINT_L2("Setting UNSPENT: ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
	td.m_spent = false;
	td.m_spent_height = 0;
}
