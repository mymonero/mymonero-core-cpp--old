//
//  wallet2_base.hpp
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
//
#pragma once

#include <memory>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/deque.hpp>
#include <atomic>

#include "include_base_utils.h"
#include "cryptonote_basic/account.h"
//#include "cryptonote_basic/account_boost_serialization.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "net/http_client.h"
#include "storages/http_abstract_invoke.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
//#include "common/unordered_containers_boost_serialization.h"
//#include "crypto/chacha.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"
#include "ringct/rctOps.h"
#include "checkpoints/checkpoints.h"

#include "wallet_errors.h"
#include "common/password.h"
#include "node_rpc_proxy.h"
//
#include "wallet2_transfer_utils.h" // for types
#include "monero_transfer_utils.hpp"

namespace tools
{
	class i_wallet3_callback
	{
	public:
		// Full wallet callbacks
		virtual void on_new_block(uint64_t height, const cryptonote::block& block) {}
		virtual void on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) {}
		virtual void on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) {}
		virtual void on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx, const cryptonote::subaddress_index& subaddr_index) {}
		virtual void on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx) {}
		// Light wallet callbacks - TODO: factor these out somehow… or so they only appear if light_wallet3 or derivation thereof
		virtual void on_lw_new_block(uint64_t height) {}
		virtual void on_lw_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
		virtual void on_lw_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
		virtual void on_lw_money_spent(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
		// Common callbacks
		virtual void on_pool_tx_removed(const crypto::hash &txid) {}
		virtual ~i_wallet3_callback() {}
	};
	
	class wallet3_base
	{
	public:
		//
		// Static
		static const char* tr(const char* str);
		//
		// Instance
		wallet3_base(bool testnet = false, bool restricted = false); // designated initializer
		
		
		bool deinit();
		bool init(uint64_t upper_transaction_size_limit = 0);
		

		// Then call one of the generate functions

		/*!
		 * \brief Generates a wallet or restores one.
		 * \param  recovery_param If it is a restore, the recovery key
		 * \param  recover        Whether it is a restore
		 * \param  two_random     Whether it is a non-deterministic wallet
		 * \param from_legacy16B_lw_seed Whether it's a 13 word / 16 byte legacy lightweight wallet seed
		 * \return                The secret key of the generated wallet
		 */
		crypto::secret_key generate(const crypto::secret_key& recovery_param = crypto::secret_key(), bool recover = false, bool two_random = false, bool from_legacy16B_lw_seed = false);
		/*!
		 * \brief Creates a wallet from a public address and a spend/view secret key pair.
		 * \param  viewkey        view secret key
		 * \param  spendkey       spend secret key
		 */
		void generate(const cryptonote::account_public_address &account_public_address,
					  const crypto::secret_key& spendkey, const crypto::secret_key& viewkey);
		//
		i_wallet3_callback* callback() const { return m_callback; }
		void callback(i_wallet3_callback* callback) { m_callback = callback; }
		//
		cryptonote::account_base& get_account(){return m_account;}
		const cryptonote::account_base& get_account()const{return m_account;}
		//
		bool testnet() const { return m_testnet; }
		bool restricted() const { return m_restricted; }
		bool watch_only() const { return m_watch_only; }
		bool multisig(bool *ready = NULL, uint32_t *threshold = NULL, uint32_t *total = NULL) const;
		bool has_multisig_partial_key_images() const;
		bool get_multisig_seed(std::string& seed, const epee::wipeable_string &passphrase = std::string(), bool raw = true) const;
		//
		uint64_t blockchain_height() const;
		//
		// Subaddress scheme
		cryptonote::account_public_address get_subaddress(const cryptonote::subaddress_index& index) const;
		cryptonote::account_public_address get_address() const { return get_subaddress({0,0}); }
		crypto::public_key get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const;
		std::string get_subaddress_as_str(const cryptonote::subaddress_index& index) const;
		std::string get_address_as_str() const { return get_subaddress_as_str({0, 0}); }
		std::string get_integrated_address_as_str(const crypto::hash8& payment_id) const;
		void add_subaddress_account(const std::string& label);
		size_t get_num_subaddress_accounts() const { return m_subaddress_labels.size(); }
		size_t get_num_subaddresses(uint32_t index_major) const { return index_major < m_subaddress_labels.size() ? m_subaddress_labels[index_major].size() : 0; }
		void add_subaddress(uint32_t index_major, const std::string& label); // throws when index is out of bound
		void expand_subaddresses(const cryptonote::subaddress_index& index);
		std::string get_subaddress_label(const cryptonote::subaddress_index& index) const;
		void set_subaddress_label(const cryptonote::subaddress_index &index, const std::string &label);
		void set_subaddress_lookahead(size_t major, size_t minor);
		//
		// locked & unlocked balance of given or current subaddress account
		uint64_t balance(uint32_t subaddr_index_major) const;
		uint64_t unlocked_balance(uint32_t subaddr_index_major) const;
		// locked & unlocked balance per subaddress of given or current subaddress account
		std::map<uint32_t, uint64_t> balance_per_subaddress(uint32_t subaddr_index_major) const;
		std::map<uint32_t, uint64_t> unlocked_balance_per_subaddress(uint32_t subaddr_index_major) const;
		//
		virtual uint64_t get_per_kb_fee() const; // may be overridden
		virtual uint64_t get_dynamic_per_kb_fee_estimate() const =0; // must be overridden
		//
		void remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes);
		void process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height);
		//
		// Transferring
		bool base__create_signed_transaction(
			const std::string &to_address_string,
			const std::string &amount_float_string,
			const std::string *optl__payment_id_string_ptr,
			uint32_t mixin,
			uint32_t simple_priority,
			std::set<uint32_t> subaddr_indices,
			uint32_t current_subaddress_account_idx,
			monero_transfer_utils::get_random_outs_fn_type get_random_outs_fn, // this function MUST be synchronous
			//
			monero_transfer_utils::CreateSignedTxs_RetVals &retVals
		) const; // have your concrete subclass call this with special parameters
		//
    	bool tx_add_fake_output(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& tx_public_key, const rct::key& mask, uint64_t real_index, bool unlocked) const;
		//
		//
	protected: // formerly private; changed to enable subclassing
		
		bool clear();
		//
		cryptonote::account_base m_account;
	//		boost::optional<epee::net_utils::http::login> m_daemon_login;
	//		std::string m_daemon_address;
	//		std::string m_wallet_file;
	//		std::string m_keys_file;
	//		epee::net_utils::http::http_simple_client m_http_client;
	//		hashchain m_blockchain;
		std::atomic<uint64_t> m_local_bc_height; //temporary workaround; not used by lightwallet
		std::unordered_map<crypto::hash, wallet2::unconfirmed_transfer_details> m_unconfirmed_txs;
		std::unordered_map<crypto::hash, wallet2::confirmed_transfer_details> m_confirmed_txs;
		std::unordered_multimap<crypto::hash, wallet2::pool_payment_details> m_unconfirmed_payments;
		std::unordered_map<crypto::hash, crypto::secret_key> m_tx_keys;
	//		cryptonote::checkpoints m_checkpoints;
//		std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> m_additional_tx_keys;
		
		wallet2::transfer_container m_transfers;
		wallet2::payment_container m_payments;
		std::unordered_map<crypto::key_image, size_t> m_key_images;
		std::unordered_map<crypto::public_key, size_t> m_pub_keys;
		cryptonote::account_public_address m_account_public_address;
		std::unordered_map<crypto::public_key, cryptonote::subaddress_index> m_subaddresses;
		std::unordered_map<cryptonote::subaddress_index, crypto::public_key> m_subaddresses_inv;
		std::vector<std::vector<std::string>> m_subaddress_labels;
	//		std::unordered_map<crypto::hash, std::string> m_tx_notes;
	//		std::unordered_map<std::string, std::string> m_attributes;
		/* to remove std::vector<tools::wallet2::address_book_row> m_address_book; */
	//		std::pair<std::map<std::string, std::string>, std::vector<std::string>> m_account_tags;
		uint64_t m_upper_transaction_size_limit; //TODO: auto-calc this value or request from daemon, now use some fixed value
		const std::vector<std::vector<tools::wallet2::multisig_info>> *m_multisig_rescan_info;
		const std::vector<std::vector<rct::key>> *m_multisig_rescan_k;
		
	//		std::atomic<bool> m_run;
		
	//		boost::mutex m_daemon_rpc_mutex;
		
		i_wallet3_callback* m_callback;
		bool m_testnet;
		bool m_restricted;
		std::string seed_language; /*!< Language of the mnemonics (seed). */
	//		bool is_old_file_format; /*!< Whether the wallet file is of an old file format */
		bool m_watch_only; /*!< no spend key */
		bool m_multisig; /*!< if > 1 spend secret key will not match spend public key */
		uint32_t m_multisig_threshold;
		std::vector<crypto::public_key> m_multisig_signers;
		// TODO: these seem like client-lvl parameters/preferences
	//		bool m_always_confirm_transfers;
	//		bool m_print_ring_members;
//		bool m_store_tx_info; /*!< request txkey to be returned in RPC, and store in the wallet cache file */
	//		uint32_t m_default_mixin;
	//		uint32_t m_default_priority;
	//		RefreshType m_refresh_type;
	//		bool m_auto_refresh;
	//		uint64_t m_refresh_from_block_height;
	//		bool m_confirm_missing_payment_id;
	//		bool m_ask_password;
		uint32_t m_min_output_count;
		uint64_t m_min_output_value;
		bool m_merge_destinations;
	//		bool m_confirm_backlog;
	//		uint32_t m_confirm_backlog_threshold;
		bool m_is_initialized;
	//		NodeRPCProxy m_node_rpc_proxy;
//		std::unordered_set<crypto::hash> m_scanned_pool_txs[2];
		size_t m_subaddress_lookahead_major, m_subaddress_lookahead_minor;
	};
}
BOOST_CLASS_VERSION(tools::wallet3_base, 1)

