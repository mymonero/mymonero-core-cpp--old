//
//  wallet2_base.cpp
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

#include "wallet3_base.hpp"
#include "monero_transfer_utils.hpp"

#define SUBADDRESS_LOOKAHEAD_MAJOR 50
#define SUBADDRESS_LOOKAHEAD_MINOR 200

namespace tools
{
	wallet3_base::wallet3_base(bool testnet, bool restricted):
		m_multisig_rescan_info(NULL),
		m_multisig_rescan_k(NULL),
	//	m_run(true),
		m_callback(0),
		m_testnet(testnet),
	//	m_always_confirm_transfers(true),
	//	m_print_ring_members(false),
	//	m_store_tx_info(true),
	//	m_default_mixin(0),
	//	m_default_priority(0),
	//	m_refresh_type(RefreshOptimizeCoinbase),
	//	m_auto_refresh(true),
	//	m_refresh_from_block_height(0),
	//	m_confirm_missing_payment_id(true),
	//	m_ask_password(true),
		m_min_output_count(0),
		m_min_output_value(0),
		m_merge_destinations(false),
	//	m_confirm_backlog(true),
	//	m_confirm_backlog_threshold(0),
		m_is_initialized(false),
		m_restricted(restricted),
	//	is_old_file_format(false),
	//	m_node_rpc_proxy(m_http_client, m_daemon_rpc_mutex),
		m_subaddress_lookahead_major(SUBADDRESS_LOOKAHEAD_MAJOR),
		m_subaddress_lookahead_minor(SUBADDRESS_LOOKAHEAD_MINOR)
	{
	}

	bool wallet3_base::deinit()
	{
		m_is_initialized=false;
		return true;
	}
	
	bool wallet3_base::clear()
	{
	//	m_blockchain.clear();
		m_transfers.clear();
		m_key_images.clear();
		m_pub_keys.clear();
		m_unconfirmed_txs.clear();
		m_payments.clear();
		m_tx_keys.clear();
	//	m_additional_tx_keys.clear();
		m_confirmed_txs.clear();
		m_unconfirmed_payments.clear();
	//	m_scanned_pool_txs[0].clear();
	//	m_scanned_pool_txs[1].clear();
	//	m_address_book.clear();
		m_local_bc_height = 1;
		m_subaddresses.clear();
		m_subaddresses_inv.clear();
		m_subaddress_labels.clear();
		return true;
	}
	//
	crypto::secret_key wallet3_base::generate(
		const crypto::secret_key& recovery_param, bool recover, bool two_random, bool from_legacy16B_lw_seed
	) {
		clear();
		
		crypto::secret_key retval = m_account.generate(recovery_param, recover, two_random, from_legacy16B_lw_seed);
		
		m_account_public_address = m_account.get_keys().m_account_address;
		m_watch_only = false;
		m_multisig = false;
		m_multisig_threshold = 0;
		m_multisig_signers.clear();
		
		// -1 month for fluctuations in block time and machine date/time setup.
		// avg seconds per block
	//	const int seconds_per_block = DIFFICULTY_TARGET_V2;
		// ~num blocks per month
	//	const uint64_t blocks_per_month = 60*60*24*30/seconds_per_block;
		
	//	// try asking the daemon first
	//	if(m_refresh_from_block_height == 0 && !recover){
	//		uint64_t height = estimate_blockchain_height();
	//		m_refresh_from_block_height = height >= blocks_per_month ? height - blocks_per_month : 0;
	//	}
	//
	//	cryptonote::block b;
	//	generate_genesis(b);
	//	m_blockchain.push_back(get_block_hash(b));
//		add_subaddress_account(tr("Primary account"));
		
		return retval;
	}

	void wallet3_base::generate(
		const cryptonote::account_public_address &account_public_address,
		const crypto::secret_key& spendkey, const crypto::secret_key& viewkey
	) {
		clear();
		
		m_account.create_from_keys(account_public_address, spendkey, viewkey);
		m_account_public_address = account_public_address;
		m_watch_only = false;
		m_multisig = false;
		m_multisig_threshold = 0;
		m_multisig_signers.clear();
		
	//	cryptonote::block b;
	//	generate_genesis(b);
	//	m_blockchain.push_back(get_block_hash(b));
	}
	//
	// Accessors
	uint64_t wallet3_base::balance(uint32_t index_major) const
	{
		uint64_t amount = 0;
		for (const auto& i : balance_per_subaddress(index_major))
			amount += i.second;
		return amount;
	}
	uint64_t wallet3_base::unlocked_balance(uint32_t index_major) const
	{
		uint64_t amount = 0;
		for (const auto& i : unlocked_balance_per_subaddress(index_major))
			amount += i.second;
		return amount;
	}
	//----------------------------------------------------------------------------------------------------
	std::map<uint32_t, uint64_t> wallet3_base::balance_per_subaddress(uint32_t index_major) const
	{
		std::map<uint32_t, uint64_t> amount_per_subaddr;
		for (const auto& td: m_transfers)
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
		for (const auto& utx: m_unconfirmed_txs)
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
	//----------------------------------------------------------------------------------------------------
	std::map<uint32_t, uint64_t> wallet3_base::unlocked_balance_per_subaddress(uint32_t index_major) const
	{
		std::map<uint32_t, uint64_t> amount_per_subaddr;
		for(const wallet2::transfer_details& td: m_transfers)
		{
			if(td.m_subaddr_index.major == index_major && !td.m_spent && monero_transfer_utils::is_transfer_unlocked(td, blockchain_height()))
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
	uint64_t wallet3_base::blockchain_height() const
	{
		return m_local_bc_height;
	}
	//
	// Imperatives
	void wallet3_base::remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes)
	{
		// remove pool txes to us that aren't in the pool anymore
		std::unordered_multimap<crypto::hash, wallet2::pool_payment_details>::iterator uit = m_unconfirmed_payments.begin();
		while (uit != m_unconfirmed_payments.end())
		{
			const crypto::hash &txid = uit->second.m_pd.m_tx_hash;
			bool found = false;
			for (const auto &it2: tx_hashes)
			{
				if (it2 == txid)
				{
					found = true;
					break;
				}
			}
			auto pit = uit++;
			if (!found)
			{
				MDEBUG("Removing " << txid << " from unconfirmed payments, not found in pool");
				m_unconfirmed_payments.erase(pit);
				if (0 != m_callback)
					m_callback->on_pool_tx_removed(txid);
			}
		}
	}

	void wallet3_base::process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height)
	{
		if (m_unconfirmed_txs.empty())
			return;
		
		auto unconf_it = m_unconfirmed_txs.find(txid);
		if(unconf_it != m_unconfirmed_txs.end()) {
	//		if (m_store_tx_info) {
				try {
					m_confirmed_txs.insert(std::make_pair(txid, wallet2::confirmed_transfer_details(unconf_it->second, height)));
				}
				catch (...) {
					// can fail if the tx has unexpected input types
					LOG_PRINT_L0("Failed to add outgoing transaction to confirmed transaction map");
				}
	//		}
			m_unconfirmed_txs.erase(unconf_it);
		}
	}
	
	//
	// Transferring
	bool wallet3_base::base__create_signed_transaction()
	{
		// TODO
		//	monero_transfer_utils::CreateTx_Args args =
		//	{
		//		sec_viewKey_string,
		//		sec_spendKey_string,
		//		//
		//		to_address_string,
		//		amount_float_string,
		//		//
		//		transfers,
		//		get_random_outs_fn,
		//		//
		//		blockchain_size,
		//		0, // unlock_time
		//		priority,
		//		1, // default_priority
		//		//
		//		0, // min_output_count
		//		0, // min_output_value
		//		false, // merge_destinations - apparent default from wallet2
		//		//
		//		paymentID_string__ptr,
		//		//
		//		0, // current_subaddress_account TODO??
		//		subaddr_indices,
		//		//
		//		false, // is_testnet
		//		true, // is_trusted_daemon
		//		true // is_lightwallet
		//	};
		//	monero_transfer_utils::CreateTx_RetVals retVals = {};
		//	BOOL didSucceed = monero_transfer_utils::create_signed_transaction(args, retVals);
		//	if (retVals.didError) {
		//		NSString *errStr = [NSString stringWithUTF8String:retVals.err_string.c_str()];
		//		_doFn_withErrStr(errStr);
		//		return;
		//	}
		//	NSAssert(didSucceed, @"Found unexpectedly didSucceed=false without an error");
		return true;
	}
}
