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
#include "common/i18n.h"
//
#include "monero_transfer_utils.hpp"
#include "monero_fork_rules.hpp"
using namespace monero_transfer_utils;
using namespace monero_fork_rules;

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

	bool wallet3_base::init(
//		std::string daemon_address,
//		boost::optional<epee::net_utils::http::login> daemon_login,
		uint64_t upper_transaction_size_limit//,
//		bool ssl
	) {
//		m_checkpoints.init_default_checkpoints(m_testnet);
//		if(m_http_client.is_connected())
//			m_http_client.disconnect();
		m_is_initialized = true;
		m_upper_transaction_size_limit = upper_transaction_size_limit;
//		m_daemon_address = std::move(daemon_address);
//		m_daemon_login = std::move(daemon_login);
		// When switching from light wallet to full wallet, we need to reset the height we got from lw node.
//		if(m_light_wallet)
//			m_local_bc_height = m_blockchain.size();
//		return m_http_client.set_server(get_daemon_address(), get_daemon_login(), ssl);
		return true;
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
		//
		// NOTE: commented to avoid performance hit for now
//		add_subaddress_account(tools::wallet3_base::tr("Primary account"));
		
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
	std::map<uint32_t, uint64_t> wallet3_base::balance_per_subaddress(uint32_t index_major) const
	{
		return monero_transfer_utils::balance_per_subaddress(m_transfers, m_unconfirmed_txs, index_major);
	}
	std::map<uint32_t, uint64_t> wallet3_base::unlocked_balance_per_subaddress(uint32_t index_major) const
	{
		return monero_transfer_utils::unlocked_balance_per_subaddress(m_transfers, index_major, blockchain_height(), m_testnet);
	}
	//
	uint64_t wallet3_base::get_dynamic_per_kb_fee_estimate() const
	{
		THROW_WALLET_EXCEPTION_IF(true, error::wallet_internal_error, "Override and implement get_dynamic_per_kb_fee_estimate");

		return FEE_PER_KB;
	}
	uint64_t wallet3_base::get_per_kb_fee() const
	{
		bool use_dyn_fee = use_fork_rules(HF_VERSION_DYNAMIC_FEE, -720 * 1);
		if (!use_dyn_fee)
			return FEE_PER_KB;
		
		return get_dynamic_per_kb_fee_estimate();
	}
	cryptonote::account_public_address wallet3_base::get_subaddress(const cryptonote::subaddress_index& index) const
	{
		const cryptonote::account_keys& keys = m_account.get_keys();
		if (index.is_zero())
			return keys.m_account_address;
		
		crypto::public_key D = get_subaddress_spend_public_key(index);
		
		// C = a*D
		crypto::public_key C = rct::rct2pk(rct::scalarmultKey(rct::pk2rct(D), rct::sk2rct(keys.m_view_secret_key)));   // could have defined secret_key_mult_public_key() under src/crypto
		
		// result: (C, D)
		cryptonote::account_public_address address;
		address.m_view_public_key  = C;
		address.m_spend_public_key = D;
		return address;
	}
	//----------------------------------------------------------------------------------------------------
	crypto::public_key wallet3_base::get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const
	{
		const cryptonote::account_keys& keys = m_account.get_keys();
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
	//----------------------------------------------------------------------------------------------------
	std::string wallet3_base::get_subaddress_as_str(const cryptonote::subaddress_index& index) const
	{
		cryptonote::account_public_address address = get_subaddress(index);
		return cryptonote::get_account_address_as_str(m_testnet, !index.is_zero(), address);
	}
	//----------------------------------------------------------------------------------------------------
	std::string wallet3_base::get_integrated_address_as_str(const crypto::hash8& payment_id) const
	{
		return cryptonote::get_account_integrated_address_as_str(m_testnet, get_address(), payment_id);
	}
	//
	uint64_t wallet3_base::blockchain_height() const
	{
		return m_local_bc_height;
	}
	const char* wallet3_base::tr(const char* str) { return i18n_translate(str, "tools::wallet2"); } // keeping old string for compatibility
	//
	// Imperatives - Subaddresses
	void wallet3_base::add_subaddress_account(const std::string& label)
	{
		uint32_t index_major = (uint32_t)get_num_subaddress_accounts();
		expand_subaddresses({index_major, 0});
		m_subaddress_labels[index_major][0] = label;
	}
	//----------------------------------------------------------------------------------------------------
	void wallet3_base::add_subaddress(uint32_t index_major, const std::string& label)
	{
		THROW_WALLET_EXCEPTION_IF(index_major >= m_subaddress_labels.size(), error::account_index_outofbound);
		uint32_t index_minor = (uint32_t)get_num_subaddresses(index_major);
		expand_subaddresses({index_major, index_minor});
		m_subaddress_labels[index_major][index_minor] = label;
	}
	//----------------------------------------------------------------------------------------------------
	void wallet3_base::expand_subaddresses(const cryptonote::subaddress_index& index)
	{
		if (m_subaddress_labels.size() <= index.major)
		{
			// add new accounts
			cryptonote::subaddress_index index2;
			for (index2.major = m_subaddress_labels.size(); index2.major < index.major + m_subaddress_lookahead_major; ++index2.major)
			{
				for (index2.minor = 0; index2.minor < (index2.major == index.major ? index.minor : 0) + m_subaddress_lookahead_minor; ++index2.minor)
				{
					if (m_subaddresses_inv.count(index2) == 0)
					{
						crypto::public_key D = get_subaddress_spend_public_key(index2);
						m_subaddresses[D] = index2;
						m_subaddresses_inv[index2] = D;
					}
				}
			}
			m_subaddress_labels.resize(index.major + 1, {"Untitled account"});
			m_subaddress_labels[index.major].resize(index.minor + 1);
		}
		else if (m_subaddress_labels[index.major].size() <= index.minor)
		{
			// add new subaddresses
			cryptonote::subaddress_index index2 = index;
			for (index2.minor = m_subaddress_labels[index.major].size(); index2.minor < index.minor + m_subaddress_lookahead_minor; ++index2.minor)
			{
				if (m_subaddresses_inv.count(index2) == 0)
				{
					crypto::public_key D = get_subaddress_spend_public_key(index2);
					m_subaddresses[D] = index2;
					m_subaddresses_inv[index2] = D;
				}
			}
			m_subaddress_labels[index.major].resize(index.minor + 1);
		}
	}
	//----------------------------------------------------------------------------------------------------
	std::string wallet3_base::get_subaddress_label(const cryptonote::subaddress_index& index) const
	{
		if (index.major >= m_subaddress_labels.size() || index.minor >= m_subaddress_labels[index.major].size())
		{
			MERROR("Subaddress label doesn't exist");
			return "";
		}
		return m_subaddress_labels[index.major][index.minor];
	}
	//----------------------------------------------------------------------------------------------------
	void wallet3_base::set_subaddress_label(const cryptonote::subaddress_index& index, const std::string &label)
	{
		THROW_WALLET_EXCEPTION_IF(index.major >= m_subaddress_labels.size(), error::account_index_outofbound);
		THROW_WALLET_EXCEPTION_IF(index.minor >= m_subaddress_labels[index.major].size(), error::address_index_outofbound);
		m_subaddress_labels[index.major][index.minor] = label;
	}
	//----------------------------------------------------------------------------------------------------
	void wallet3_base::set_subaddress_lookahead(size_t major, size_t minor)
	{
		m_subaddress_lookahead_major = major;
		m_subaddress_lookahead_minor = minor;
	}
	//
	// Imperatives - Transactions
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
	bool wallet3_base::base__create_signed_transaction(
		const std::string &to_address_string,
		const std::string &amount_float_string,
		const std::string *optl__payment_id_string_ptr,
		uint32_t simple_priority,
		std::set<uint32_t> subaddr_indices,
		uint32_t current_subaddress_account_idx,
		std::function<bool(std::vector<std::vector<tools::wallet2::get_outs_entry>> &, const std::list<size_t> &, size_t)> get_random_outs_fn,
		//
		monero_transfer_utils::CreateSignedTxs_RetVals &retVals
	) {
		CreateSignedTxs_Args args =
		{
			m_account.get_keys(),
			//
			to_address_string,
			amount_float_string,
			optl__payment_id_string_ptr,
			//
			current_subaddress_account_idx,
			subaddr_indices,
			unlocked_balance(current_subaddress_account_idx),
			m_subaddresses,
			//
			m_transfers,
			m_unconfirmed_txs,
			//
			get_random_outs_fn,
			//
			get_per_kb_fee(),
			blockchain_height(),
			0, // unlock_time
			simple_priority,
			1, // default_priority
			//
			m_upper_transaction_size_limit,
			//
			0, // min_output_count
			0, // min_output_value
			//
			m_multisig_threshold,
			m_multisig_signers,
			//
			false, // merge_destinations - apparent default from wallet2
			false, // is_testnet
			true, // is_trusted_daemon
			m_multisig // is_wallet_multisig
		};
		bool r = monero_transfer_utils::create_signed_transaction(
			args,
			retVals // passing retVals ref through from fn args
		);
		if (retVals.did_error) {
			return false; // retVals already populated with err values
		}
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Unexpected !did_succeed=false without an error");
		return true;
	}
}
