//
//  light_wallet3.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 1/17/18.
//  Copyright (c) 2014-2018, MyMonero.com
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are
//  permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of
//	conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list
//	of conditions and the following disclaimer in the documentation and/or other
//	materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be
//	used to endorse or promote products derived from this software without specific
//	prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
//  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
//  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
//  THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
//  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
//  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
//  THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "light_wallet3.hpp"
#include "include_base_utils.h"
#include "monero_transfer_utils.hpp"
#include <random>

using namespace epee;
using namespace tools;
using namespace crypto;
using namespace cryptonote;

static void emplace_or_replace( // TODO: factor…… where?
	std::unordered_multimap<crypto::hash,
	wallet2::pool_payment_details> &container,
	const crypto::hash &key,
	const wallet2::pool_payment_details &pd
) {
	auto range = container.equal_range(key);
	for (auto i = range.first; i != range.second; ++i)
	{
		if (i->second.m_pd.m_tx_hash == pd.m_pd.m_tx_hash && i->second.m_pd.m_subaddr_index == pd.m_pd.m_subaddr_index)
		{
			i->second = pd;
			return;
		}
	}
	container.emplace(key, pd);
}

light_wallet3::light_wallet3(bool testnet, bool restricted)
	: wallet3_base::wallet3_base(testnet, restricted),
	m_light_wallet_scanned_height(0),
	m_light_wallet_scanned_block_height(0),
	m_light_wallet_blockchain_height(0),
	m_light_wallet_scan_start_height(0),
	m_light_wallet_transaction_height(0),
	m_light_wallet_connected(false),
	m_light_wallet_locked_balance(0),
	m_light_wallet_total_received(0),
	m_light_wallet_total_sent(0)
{
}
//
void light_wallet3::ingest__get_address_info(
	bool did_error,
	const light_wallet3_server_api::COMMAND_RPC_GET_ADDRESS_INFO::response &res
) {
	if (did_error) {
		m_light_wallet_connected = false;
		return;
	}
	//
	// Last stored block height
	uint64_t prev_height = m_light_wallet_blockchain_height;
	//
	// Update lw heights
	m_light_wallet_scanned_height = res.scanned_height;
	m_light_wallet_scanned_block_height = res.scanned_block_height;
	m_light_wallet_blockchain_height = res.blockchain_height;
	m_light_wallet_scan_start_height = res.start_height;
	m_light_wallet_transaction_height = res.transaction_height;
	m_local_bc_height = res.blockchain_height;
	//
	// deprecated due to no usage
//	m_light_wallet_spent_outputs = res.spent_outputs; // copy ; TODO: is this ok or should we iterate and append?
	//
	m_light_wallet_locked_balance = res.locked_funds;
	m_light_wallet_total_received = res.total_received;
	// total_sent is set just below after derivation
	//
	uint64_t mutable__total_sent = res.total_sent; // to be finalized
	{ // Check key images - subtract fake outputs from mutable__total_sent
		for (const auto &so: res.spent_outputs) {
			crypto::public_key tx_public_key;
			crypto::key_image key_image;
			THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, so.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
			THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, so.key_image), error::wallet_internal_error, "Invalid key_image field");
			string_tools::hex_to_pod(so.tx_pub_key, tx_public_key);
			string_tools::hex_to_pod(so.key_image, key_image);
			
			if (!is_own_key_image(key_image, tx_public_key, so.out_index)) {
				THROW_WALLET_EXCEPTION_IF(so.amount > mutable__total_sent, error::wallet_internal_error, "Lightwallet: total sent is negative!");
				mutable__total_sent -= so.amount;
			}
		}
	}
	m_light_wallet_total_sent = mutable__total_sent; // final
	//
	m_light_wallet_connected = true;
	//
	// If new height - call new_block callback
	if(m_light_wallet_blockchain_height != prev_height) {
		if (0 != m_callback) {
			m_callback->on_lw_new_block(m_light_wallet_blockchain_height - 1);
		}
	}
}

void light_wallet3::ingest__get_address_txs(
	const light_wallet3_server_api::COMMAND_RPC_GET_ADDRESS_TXS::response &ires
) {
	// Update lw heights/properties
	m_light_wallet_scanned_height = ires.scanned_height;
	m_light_wallet_scanned_block_height = ires.scanned_block_height;
	m_light_wallet_blockchain_height = ires.blockchain_height;
	m_local_bc_height = ires.blockchain_height;
	//
	if(ires.transactions.empty())
		return; // FIXME: is it a good idea to return so early?
	
	// Create searchable vectors
	std::vector<crypto::hash> payments_txs;
	for(const auto &p: m_payments)
		payments_txs.push_back(p.second.m_tx_hash);
	std::vector<crypto::hash> unconfirmed_payments_txs;
	for(const auto &up: m_unconfirmed_payments)
		unconfirmed_payments_txs.push_back(up.second.m_pd.m_tx_hash);
	
	// for balance calculation
	uint64_t wallet_total_sent = 0;
	uint64_t wallet_total_unlocked_sent = 0;
	// txs in pool
	std::vector<crypto::hash> pool_txs;
	
	// TODO: update all this parsing
	//
	for (const auto &t: ires.transactions) {
		const uint64_t total_received = t.total_received;
		uint64_t total_sent = t.total_sent;
		//
		// Check key images - subtract fake outputs from total_sent
		for(const auto &so: t.spent_outputs) {
			crypto::public_key tx_public_key;
			crypto::key_image key_image;
			THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, so.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
			THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, so.key_image), error::wallet_internal_error, "Invalid key_image field");
			string_tools::hex_to_pod(so.tx_pub_key, tx_public_key);
			string_tools::hex_to_pod(so.key_image, key_image);
			//
			if(!is_own_key_image(key_image, tx_public_key, so.out_index)) {
				THROW_WALLET_EXCEPTION_IF(so.amount > t.total_sent, error::wallet_internal_error, "Lightwallet: total sent is negative!");
				total_sent -= so.amount;
			}
		}
		//
		// Do not add tx if empty.
		if(total_sent == 0 && total_received == 0) {
			continue;
		}
		crypto::hash tx_hash;
		THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, t.hash), error::wallet_internal_error, "Invalid hash field");
		string_tools::hex_to_pod(t.hash, tx_hash);
		//
		crypto::hash payment_id = null_hash;
		if (!t.payment_id.empty()) {
			THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, t.payment_id), error::wallet_internal_error, "Invalid payment_id field");
			string_tools::hex_to_pod(t.payment_id, payment_id);
		}
		//
		// must parse ISO 8601 formatted date to seconds-since-epoch
		time_t tx_timestamp_s_since_1970 = light_wallet3_server_api::epoch_time_by_parsing_date_string(t.timestamp);
		//
		// lightwallet specific info
		bool incoming = (total_received > total_sent);
		light_wallet3::address_tx address_tx;
		address_tx.m_tx_hash = tx_hash;
		address_tx.m_incoming = incoming;
		address_tx.m_amount  =  incoming ? total_received - total_sent : total_sent - total_received;
		address_tx.m_fee = 0; // TODO
		address_tx.m_block_height = t.height;
		address_tx.m_unlock_time  = t.unlock_time;
		address_tx.m_timestamp = tx_timestamp_s_since_1970; // this is actually a formatted string
		address_tx.m_coinbase  = t.coinbase;
		address_tx.m_mempool  = t.mempool;
		address_tx.m_mixin = t.mixin;
		address_tx.m_payment_id_string = t.payment_id;
		
		m_light_wallet_address_txs.emplace(tx_hash,address_tx);
		
		// populate data needed for history (m_payments, m_unconfirmed_payments, m_confirmed_txs)
		// INCOMING transfers
		if(total_received > total_sent) {
			wallet2::payment_details payment;
			payment.m_tx_hash = tx_hash;
			payment.m_amount       = total_received - total_sent;
			payment.m_fee = 0; // TODO
			payment.m_block_height = t.height;
			payment.m_unlock_time  = t.unlock_time;
			payment.m_timestamp = tx_timestamp_s_since_1970;
			//
			if (t.mempool) {
				if (std::find(unconfirmed_payments_txs.begin(), unconfirmed_payments_txs.end(), tx_hash) == unconfirmed_payments_txs.end()) {
					pool_txs.push_back(tx_hash);
					// assume false as we don't get that info from the light wallet server
					crypto::hash payment_id;
					THROW_WALLET_EXCEPTION_IF(!epee::string_tools::hex_to_pod(t.payment_id, payment_id),
											  error::wallet_internal_error, "Failed to parse payment id");
					emplace_or_replace(m_unconfirmed_payments, payment_id, wallet2::pool_payment_details{payment, false});
					if (0 != m_callback) {
						m_callback->on_lw_unconfirmed_money_received(t.height, payment.m_tx_hash, payment.m_amount);
					}
				}
			} else {
				if (std::find(payments_txs.begin(), payments_txs.end(), tx_hash) == payments_txs.end()) {
					m_payments.emplace(tx_hash, payment);
					if (0 != m_callback) {
						m_callback->on_lw_money_received(t.height, payment.m_tx_hash, payment.m_amount);
					}
				}
			}
		} else { // Outgoing transfers
			uint64_t amount_sent = total_sent - total_received;
			cryptonote::transaction dummy_tx; // not used by light wallet
			// increase wallet total sent
			wallet_total_sent += total_sent;
			if (t.mempool) {
				// Handled by add_unconfirmed_tx in commit_tx
				// If sent from another wallet instance we need to add it
				if (m_unconfirmed_txs.find(tx_hash) == m_unconfirmed_txs.end()) {
					wallet2::unconfirmed_transfer_details utd;
					utd.m_amount_in = amount_sent;
					utd.m_amount_out = amount_sent;
					utd.m_change = 0;
					utd.m_payment_id = payment_id;
					utd.m_timestamp = tx_timestamp_s_since_1970;
					utd.m_state = wallet2::unconfirmed_transfer_details::pending;
					m_unconfirmed_txs.emplace(tx_hash,utd);
				}
			} else {
				// Only add if new
				auto confirmed_tx = m_confirmed_txs.find(tx_hash);
				if (confirmed_tx == m_confirmed_txs.end()) {
					// tx is added to m_unconfirmed_txs - move to confirmed
					if (m_unconfirmed_txs.find(tx_hash) != m_unconfirmed_txs.end()) {
						process_unconfirmed(tx_hash, dummy_tx, t.height);
					} else { // Tx sent by another wallet instance
						wallet2::confirmed_transfer_details ctd;
						ctd.m_amount_in = amount_sent;
						ctd.m_amount_out = amount_sent;
						ctd.m_change = 0;
						ctd.m_payment_id = payment_id;
						ctd.m_block_height = t.height;
						ctd.m_timestamp = tx_timestamp_s_since_1970;
						m_confirmed_txs.emplace(tx_hash,ctd);
					}
					if (0 != m_callback) {
						m_callback->on_lw_money_spent(t.height, tx_hash, amount_sent);
					}
				} else {
					// If not new - check the amount and update if necessary.
					// when sending a tx to same wallet the receiving amount has to be credited
					if(confirmed_tx->second.m_amount_in != amount_sent || confirmed_tx->second.m_amount_out != amount_sent) {
						MDEBUG("Adjusting amount sent/received for tx: <" + t.hash + ">. Is tx sent to own wallet? " << print_money(amount_sent) << " != " << print_money(confirmed_tx->second.m_amount_in));
						confirmed_tx->second.m_amount_in = amount_sent;
						confirmed_tx->second.m_amount_out = amount_sent;
						confirmed_tx->second.m_change = 0;
					}
				}
			}
		}
	}
	// TODO: purge old unconfirmed_txs
	remove_obsolete_pool_txs(pool_txs);
}

void light_wallet3::ingest__get_unspent_outs(
	const light_wallet3_server_api::COMMAND_RPC_GET_UNSPENT_OUTS::response &ores,
	size_t light_wallet_requested_outputs_count
) {
	MDEBUG("Getting unspent outs");

	m_light_wallet_per_kb_fee = ores.per_kb_fee;
	
	std::unordered_map<crypto::hash,bool> transfers_txs;
	for(const auto &t: m_transfers)
		transfers_txs.emplace(t.m_txid,t.m_spent);
	
	MDEBUG("FOUND " << ores.outputs.size() <<" outputs");
	
	// return if no outputs found
	if(ores.outputs.empty())
		return;
	
	// Clear old outputs
	m_transfers.clear();
	
	for (const auto &o: ores.outputs) {
		bool spent = false;
		bool add_transfer = true;
		crypto::key_image unspent_key_image;
		crypto::public_key tx_public_key = AUTO_VAL_INIT(tx_public_key);
		THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, o.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
		string_tools::hex_to_pod(o.tx_pub_key, tx_public_key);
		
		for (const std::string &ski: o.spend_key_images) {
			spent = false;
			
			// Check if key image is ours
			THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, ski), error::wallet_internal_error, "Invalid key image");
			string_tools::hex_to_pod(ski, unspent_key_image);
			if(is_own_key_image(unspent_key_image, tx_public_key, o.index)){
				MTRACE("Output " << o.public_key << " is spent. Key image: " <<  ski);
				spent = true;
				break;
			} {
				MTRACE("Unspent output found. " << o.public_key);
			}
		}
		
		// Check if tx already exists in m_transfers.
		crypto::hash txid;
		crypto::public_key tx_pub_key;
		crypto::public_key public_key;
		THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, o.tx_hash), error::wallet_internal_error, "Invalid tx_hash field");
		THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, o.public_key), error::wallet_internal_error, "Invalid public_key field");
		THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, o.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
		string_tools::hex_to_pod(o.tx_hash, txid);
		string_tools::hex_to_pod(o.public_key, public_key);
		string_tools::hex_to_pod(o.tx_pub_key, tx_pub_key);
		
		for(auto &t: m_transfers){
			if(t.get_public_key() == public_key) {
				t.m_spent = spent;
				add_transfer = false;
				break;
			}
		}
		
		if(!add_transfer)
			continue;
		
		m_transfers.push_back(boost::value_initialized<wallet2::transfer_details>());
		wallet2::transfer_details& td = m_transfers.back();
		
		td.m_block_height = o.height;
		td.m_global_output_index = o.global_index;
		td.m_txid = txid;
		
		// Add to extra
		add_tx_pub_key_to_extra(td.m_tx, tx_pub_key);
		
		td.m_key_image = unspent_key_image;
		td.m_key_image_known = !m_watch_only;
		td.m_amount = o.amount;
		td.m_pk_index = 0;
		td.m_internal_output_index = o.index;
		td.m_spent = spent;
		
		tx_out txout;
		txout.target = txout_to_key(public_key);
		txout.amount = td.m_amount;
		
		td.m_tx.vout.resize(td.m_internal_output_index + 1);
		td.m_tx.vout[td.m_internal_output_index] = txout;
		
		// Add unlock time and coinbase bool got from get_address_txs api call
		std::unordered_map<crypto::hash,light_wallet3::address_tx>::const_iterator found = m_light_wallet_address_txs.find(txid);
		THROW_WALLET_EXCEPTION_IF(found == m_light_wallet_address_txs.end(), error::wallet_internal_error, "Lightwallet: tx not found in m_light_wallet_address_txs");
		bool miner_tx = found->second.m_coinbase;
		td.m_tx.unlock_time = found->second.m_unlock_time;
		
		if (!o.rct.empty()) {
			// Coinbase tx's
			if (miner_tx) {
				td.m_mask = rct::identity();
			} else {
				// rct txs
				// decrypt rct mask, calculate commit hash and compare against blockchain commit hash
				rct::key rct_commit;
				parse_rct_str(o.rct, tx_pub_key, td.m_internal_output_index, td.m_mask, rct_commit, true);
				bool valid_commit = (rct_commit == rct::commit(td.amount(), td.m_mask));
				if (!valid_commit) {
					MDEBUG("output index: " << o.global_index);
					MDEBUG("mask: " + string_tools::pod_to_hex(td.m_mask));
					MDEBUG("calculated commit: " + string_tools::pod_to_hex(rct::commit(td.amount(), td.m_mask)));
					MDEBUG("expected commit: " + string_tools::pod_to_hex(rct_commit));
					MDEBUG("amount: " << td.amount());
				}
				THROW_WALLET_EXCEPTION_IF(!valid_commit, error::wallet_internal_error, "Lightwallet: rct commit hash mismatch!");
			}
			td.m_rct = true;
		} else {
			td.m_mask = rct::identity();
			td.m_rct = false;
		}
		if (!spent) {
			monero_transfer_utils::set_unspent(m_transfers, m_transfers.size()-1);
		}
		m_key_images[td.m_key_image] = m_transfers.size()-1;
		m_pub_keys[td.get_public_key()] = m_transfers.size()-1;
	}
}

bool light_wallet3::populate_from__get_random_outs(const light_wallet3_server_api::COMMAND_RPC_GET_RANDOM_OUTS::response &ores, std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, size_t requested_outputs_count, tools::RetVals_base &retVals) const
{
	retVals = {}; // must initialize
	//
	if (ores.amount_outs.empty()) {
		retVals.did_error = true;
		retVals.err_string = "No outputs received from server.";
		return false;
	}
	
	// Check if we got enough outputs for each amount
	for(auto& out: ores.amount_outs) {
		if (out.outputs.size() < requested_outputs_count) {
			retVals.did_error = true;
			retVals.err_string = "Not enough outputs for amount: " + boost::lexical_cast<std::string>(out.amount);
			return false;
		}
		MDEBUG(out.outputs.size() << " outputs for amount "+ boost::lexical_cast<std::string>(out.amount) + " received from light wallet node");
	}
	
	MDEBUG("selected transfers size: " << selected_transfers.size());
	
	for(size_t idx: selected_transfers)
	{
		// Create new index
		outs.push_back(std::vector<wallet2::get_outs_entry>());
		outs.back().reserve(fake_outputs_count + 1);
		
		// add real output first
		const wallet2::transfer_details &td = m_transfers[idx];
		const uint64_t amount = td.is_rct() ? 0 : td.amount();
		outs.back().push_back(std::make_tuple(td.m_global_output_index, td.get_public_key(), rct::commit(td.amount(), td.m_mask)));
		MDEBUG("added real output " << string_tools::pod_to_hex(td.get_public_key()));
		
		// Even if the lightwallet server returns random outputs, we pick them randomly.
		std::vector<size_t> order;
		order.resize(requested_outputs_count);
		for (size_t n = 0; n < order.size(); ++n)
			order[n] = n;
		std::shuffle(order.begin(), order.end(), std::default_random_engine(crypto::rand<unsigned>()));
		
		
		LOG_PRINT_L2("Looking for " << (fake_outputs_count+1) << " outputs with amounts " << print_money(td.is_rct() ? 0 : td.amount()));
		MDEBUG("OUTS SIZE: " << outs.back().size());
		for (size_t o = 0; o < requested_outputs_count && outs.back().size() < fake_outputs_count + 1; ++o)
		{
			// Random pick
			size_t i = order[o];
			
			// Find which random output key to use
			bool found_amount = false;
			size_t amount_key;
			for(amount_key = 0; amount_key < ores.amount_outs.size(); ++amount_key)
			{
				if(boost::lexical_cast<uint64_t>(ores.amount_outs[amount_key].amount) == amount) {
					found_amount = true;
					break;
				}
			}
			THROW_WALLET_EXCEPTION_IF(!found_amount , error::wallet_internal_error, "Outputs for amount " + boost::lexical_cast<std::string>(ores.amount_outs[amount_key].amount) + " not found" );
			
			LOG_PRINT_L2("Index " << i << "/" << requested_outputs_count << ": idx " << ores.amount_outs[amount_key].outputs[i].global_index << " (real " << td.m_global_output_index << "), unlocked " << "(always in light)" << ", key " << ores.amount_outs[0].outputs[i].public_key);
			
			// Convert light wallet string data to proper data structures
			crypto::public_key tx_public_key;
			rct::key mask = AUTO_VAL_INIT(mask); // decrypted mask - not used here
			rct::key rct_commit = AUTO_VAL_INIT(rct_commit);
			THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, ores.amount_outs[amount_key].outputs[i].public_key), error::wallet_internal_error, "Invalid public_key");
			string_tools::hex_to_pod(ores.amount_outs[amount_key].outputs[i].public_key, tx_public_key);
			const uint64_t global_index = ores.amount_outs[amount_key].outputs[i].global_index;
			if(!parse_rct_str(ores.amount_outs[amount_key].outputs[i].rct, tx_public_key, 0, mask, rct_commit, false))
				rct_commit = rct::zeroCommit(td.amount());
			
			if (tx_add_fake_output(outs, global_index, tx_public_key, rct_commit, td.m_global_output_index, true)) {
				MDEBUG("added fake output " << ores.amount_outs[amount_key].outputs[i].public_key);
				MDEBUG("index " << global_index);
			}
		}
		
		THROW_WALLET_EXCEPTION_IF(outs.back().size() < fake_outputs_count + 1 , error::wallet_internal_error, "Not enough fake outputs found" );
		
		// Real output is the first. Shuffle outputs
		MTRACE(outs.back().size() << " outputs added. Sorting outputs by index:");
		std::sort(outs.back().begin(), outs.back().end(), [](const wallet2::get_outs_entry &a, const wallet2::get_outs_entry &b) { return std::get<0>(a) < std::get<0>(b); });
		
		// Print output order
		for(auto added_out: outs.back())
			MTRACE(std::get<0>(added_out));
		
	}
	
	return true;
}

bool light_wallet3::is_own_key_image(const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index) 
{
	// Lookup key image from cache
	std::map<uint64_t, crypto::key_image> index_keyimage_map;
	std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> >::const_iterator found_pub_key = m_key_image_cache.find(tx_public_key);
	if(found_pub_key != m_key_image_cache.end()) {
		// pub key found. key image for index cached?
		index_keyimage_map = found_pub_key->second;
		std::map<uint64_t,crypto::key_image>::const_iterator index_found = index_keyimage_map.find(out_index);
		if(index_found != index_keyimage_map.end())
			return key_image == index_found->second;
	}
	
	// Not in cache - calculate key image
	crypto::key_image calculated_key_image;
	cryptonote::keypair in_ephemeral;
	
	// Subaddresses aren't supported in mymonero/openmonero yet. Roll out the original scheme:
	//   compute D = a*R
	//   compute P = Hs(D || i)*G + B
	//   compute x = Hs(D || i) + b      (and check if P==x*G)
	//   compute I = x*Hp(P)
	const account_keys& ack = get_account().get_keys();
	crypto::key_derivation derivation;
	bool r = crypto::generate_key_derivation(tx_public_key, ack.m_view_secret_key, derivation);
	CHECK_AND_ASSERT_MES(r, false, "failed to generate_key_derivation(" << tx_public_key << ", " << ack.m_view_secret_key << ")");
	
	r = crypto::derive_public_key(derivation, out_index, ack.m_account_address.m_spend_public_key, in_ephemeral.pub);
	CHECK_AND_ASSERT_MES(r, false, "failed to derive_public_key (" << derivation << ", " << out_index << ", " << ack.m_account_address.m_spend_public_key << ")");
	
	crypto::derive_secret_key(derivation, out_index, ack.m_spend_secret_key, in_ephemeral.sec);
	crypto::public_key out_pkey_test;
	r = crypto::secret_key_to_public_key(in_ephemeral.sec, out_pkey_test);
	CHECK_AND_ASSERT_MES(r, false, "failed to secret_key_to_public_key(" << in_ephemeral.sec << ")");
	CHECK_AND_ASSERT_MES(in_ephemeral.pub == out_pkey_test, false, "derived secret key doesn't match derived public key");
	
	crypto::generate_key_image(in_ephemeral.pub, in_ephemeral.sec, calculated_key_image);
	
	index_keyimage_map.emplace(out_index, calculated_key_image);
	m_key_image_cache.emplace(tx_public_key, index_keyimage_map);
	return key_image == calculated_key_image;
}
//
bool light_wallet3::parse_rct_str(const std::string& rct_string, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key& decrypted_mask, rct::key& rct_commit, bool decrypt) const
{
	// rct string is empty if output is non RCT
	if (rct_string.empty())
		return false;
	// rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
	rct::key encrypted_mask;
	std::string rct_commit_str = rct_string.substr(0,64);
	std::string encrypted_mask_str = rct_string.substr(64,64);
	THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, rct_commit_str), error::wallet_internal_error, "Invalid rct commit hash: " + rct_commit_str);
	THROW_WALLET_EXCEPTION_IF(!string_tools::validate_hex(64, encrypted_mask_str), error::wallet_internal_error, "Invalid rct mask: " + encrypted_mask_str);
	string_tools::hex_to_pod(rct_commit_str, rct_commit);
	string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);
	if (decrypt) {
		// Decrypt the mask
		crypto::key_derivation derivation;
		bool r = generate_key_derivation(tx_pub_key, get_account().get_keys().m_view_secret_key, derivation);
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
		crypto::secret_key scalar;
		crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
		sc_sub(decrypted_mask.bytes,encrypted_mask.bytes,rct::hash_to_scalar(rct::sk2rct(scalar)).bytes);
	}
	return true;
}
//
// Accessors - Overrides
uint64_t light_wallet3::balance(uint32_t index_major) const
{
	return m_light_wallet_total_received - m_light_wallet_total_sent;
}
uint64_t light_wallet3::unlocked_balance(uint32_t index_major) const
{
	return (m_light_wallet_total_received - m_light_wallet_total_sent) - m_light_wallet_locked_balance; // FIXME: verify correctness
}
uint64_t light_wallet3::get_dynamic_per_kb_fee_estimate() const
{
	THROW_WALLET_EXCEPTION_IF(true, error::wallet_internal_error, "Calls to light_wallet3::get_dynamic_per_kb_fee_estimate are not expected");
	
	return FEE_PER_KB;
}
uint64_t light_wallet3::get_per_kb_fee() const
{
	return m_light_wallet_per_kb_fee;
}
//
uint64_t light_wallet3::blockchain_height() const
{
	return m_light_wallet_blockchain_height; // NOTE: overridden from m_local_bc_height … although we DO set m_local_bc_height to the same value at all relevan times so it'd be fine to remove this override … but m_local_bc_height may be deprecated 
}

//
//
// Transferring
//
bool light_wallet3::create_signed_transaction(
	const std::string &to_address_string,
	const std::string &amount_float_string,
	const std::string *optl__payment_id_string, // TODO: pass this as ref?
	uint32_t simple_priority,
	monero_transfer_utils::get_random_outs_fn_type get_random_outs_fn,
	//
	monero_transfer_utils::CreateSignedTxs_RetVals &retVals
) const {
	 // TODO: support subaddresses - currently disabled due to time it takes to expand on wallet generate()
	std::set<uint32_t> subaddr_indices;
	uint32_t current_subaddress_account_idx = 0;
	//
	return base__create_signed_transaction(
		to_address_string,
		amount_float_string,
		optl__payment_id_string,
		monero_transfer_utils::fixed_mixinsize(),
		simple_priority,
		subaddr_indices,
		current_subaddress_account_idx,
		get_random_outs_fn,
		retVals
	);
}
void light_wallet3::populate_amount_strings_for_get_random_outs(
	const std::vector<size_t> &selected_transfers, // select from
	std::vector<std::string> &amounts // to fill
) const {
	for (size_t idx: selected_transfers) {
		const uint64_t ask_amount = m_transfers[idx].is_rct() ? 0 : m_transfers[idx].amount();
		std::ostringstream amount_ss;
		amount_ss << ask_amount;
		amounts.push_back(amount_ss.str());
	}
}
uint32_t light_wallet3::requested_outputs_count(size_t fake_outputs_count) const
{
	return (uint32_t)((fake_outputs_count + 1) * 1.5 + 1); // "we ask for more, to have spares if some outputs are still locked"
}
