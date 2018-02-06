//
//  monero_transfer_utils.hpp
//  MyMonero
//
//  Created by Paul Shapiro on 12/2/17.
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
#ifndef monero_transfer_utils_hpp
#define monero_transfer_utils_hpp
//
#include "string_tools.h"
#include <boost/program_options/options_description.hpp>
//#include <boost/program_options/variables_map.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include "crypto.h"
#include "cryptonote_tx_utils.h"
#include "wallet_errors.h"
//
using namespace tools;
#include "tools__ret_vals.hpp"
#include "wallet2_transfer_utils.h" // to be renamed / phased out after moving relevant types
//
#define SECOND_OUTPUT_RELATEDNESS_THRESHOLD 0.0f
// used to choose when to stop adding outputs to a tx
#define APPROXIMATE_INPUT_BYTES 80
// used to target a given block size (additional outputs may be added on top to build fee)
#define TX_SIZE_TARGET(bytes) (bytes*2/3)
//
namespace monero_transfer_utils
{
	//
	// Interface - Constructing new transactions
	struct get_random_outs_fn_RetVals: RetVals_base
	{ // no other params necessary for now - this is for passing the err str back
	};
	typedef std::function<bool(std::vector<std::vector<tools::wallet2::get_outs_entry>> &, const std::vector<size_t> &, size_t, get_random_outs_fn_RetVals &)> get_random_outs_fn_type; // this function MUST be synchronous; it must also initialize a get_random_outs_fn_RetVals (e.g. 'retVals = {};')
	//
	struct CreateSignedTxs_Args
	{
		CreateSignedTxs_Args() = delete; // disallow `Args foo;` default constructor
		//
		const cryptonote::account_keys &account_keys;
		//
		std::string to_address_string;
		std::string amount_float_string; // passed as string b/c function wants to parse amount
		const std::string *optl__payment_id_string;
		uint32_t mixin; // aka fake_outs_count
		//
		uint32_t current_subaddr_account;
		const std::set<uint32_t> &subaddr_indices;
		uint64_t unlocked_balance_for_subaddr_index; // this is passed in b/c light_wallet3 wants to calculate it in its own way (which raises questions)
		const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses;
		//
		const wallet2::transfer_container &transfers;
		std::unordered_map<crypto::hash, tools::wallet2::unconfirmed_transfer_details> unconfirmed_txs;
		//
		monero_transfer_utils::get_random_outs_fn_type get_random_outs_fn; // this function MUST be synchronous - a std::promise may be used
		//
		const uint64_t per_kb_fee;
		uint64_t blockchain_size;
		const uint64_t unlock_time;
		uint32_t priority;
		uint32_t default_priority;
		//
		uint64_t upper_transaction_size_limit__or_0_for_default;
		//
		uint32_t min_output_count;
		uint64_t min_output_value;
		//
		uint32_t multisig_threshold;
		std::vector<crypto::public_key> multisig_signers;
		//
		bool merge_destinations;
		bool is_testnet;
		bool is_trusted_daemon;
		bool is_wallet_multisig;
	};
	struct CreateSignedTxs_RetVals: RetVals_base
	{
		boost::optional<tools::wallet2::signed_tx_set> signed_tx_set;
	};
	bool create_signed_transaction( // returns !did_error
		const CreateSignedTxs_Args &args,
		CreateSignedTxs_RetVals &retVals // initializes a retVals for you
	);
	//
	//
	// Shared - create_transactions_*
	//
	struct CreatePendingTx_RetVals: RetVals_base
	{
		boost::optional<std::vector<tools::wallet2::pending_tx>> pending_txs;
	};
	bool create_pending_transactions_3( // aka create_transactions_3, from create_transactions_2
		const cryptonote::account_keys &account_keys,
		const std::vector<wallet2::transfer_details> &transfers,
		std::unordered_map<crypto::hash, tools::wallet2::unconfirmed_transfer_details> unconfirmed_txs,
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
		std::vector<crypto::public_key> multisig_signers,
		//
		bool merge_destinations,
		bool trusted_daemon,
		bool is_testnet,
		bool is_wallet_multisig,
		//
		monero_transfer_utils::get_random_outs_fn_type get_random_outs_fn, // this function MUST be synchronous
		//
		CreatePendingTx_RetVals &retVals // initializes a retVals for you
	);	
	//
	//
	// Shared - Utilities
	//
	template<typename T>
	void transfer_selected(
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
		const tools::tx_dust_policy& dust_policy,
		cryptonote::transaction& tx,
		tools::wallet2::pending_tx &ptx,
		//
		monero_transfer_utils::get_random_outs_fn_type get_random_outs_fn, // this function MUST be synchronous
		tools::RetVals_base &retVals
	);
	void transfer_selected_rct(
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
		tools::wallet2::pending_tx &ptx,
		bool bulletproof,
		//
		monero_transfer_utils::get_random_outs_fn_type get_random_outs_fn, // this function MUST be synchronous
		tools::RetVals_base &retVals
	);
	//
	uint64_t num_rct_outputs(); // TODO: migrate to standard function
	uint64_t get_upper_transaction_size_limit(uint64_t upper_transaction_size_limit__or_0_for_default);
	uint64_t get_fee_multiplier(uint32_t priority, uint32_t default_priority, int fee_algorithm);
	int get_fee_algorithm();
	//
	uint64_t calculate_fee(uint64_t fee_per_kb, size_t bytes, uint64_t fee_multiplier);
	uint64_t calculate_fee(uint64_t fee_per_kb, const cryptonote::blobdata &blob, uint64_t fee_multiplier);
	//
	size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof);
	size_t estimate_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof);
	//
	//
	std::vector<size_t> pick_preferred_rct_inputs(const tools::wallet2::transfer_container &transfers, uint64_t needed_money, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices, uint64_t blockchain_size, bool is_testnet);
	//
	bool should_pick_a_second_output(bool use_rct, const tools::wallet2::transfer_container &transfers, size_t n_transfers, const std::vector<size_t> &unused_transfers_indices, const std::vector<size_t> &unused_dust_indices);
	
	size_t pop_best_value_from(const tools::wallet2::transfer_container &transfers, std::vector<size_t> &unused_dust_indices, const std::vector<size_t>& selected_transfers, bool smallest = false);
	
	std::vector<size_t> get_only_rct(const tools::wallet2::transfer_container &transfers, const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices);
	uint32_t get_count_above(const tools::wallet2::transfer_container &transfers, const std::vector<size_t> &indices, uint64_t threshold);
	float get_output_relatedness(const tools::wallet2::transfer_details &td0, const tools::wallet2::transfer_details &td1);
	//
	bool is_transfer_unlocked(const tools::wallet2::transfer_details& td, uint64_t blockchain_size, bool is_testnet = false);
	bool is_transfer_unlocked(uint64_t unlock_time, uint64_t block_height, uint64_t blockchain_size, bool is_testnet = false);
	bool is_tx_spendtime_unlocked(uint64_t unlock_time, uint64_t block_height, uint64_t blockchain_size, bool is_testnet = false);
	uint64_t unlocked_balance(const tools::wallet2::transfer_container &transfers, uint64_t blockchain_size, bool is_testnet);
	
	std::map<uint32_t, uint64_t> balance_per_subaddress(
		std::vector<wallet2::transfer_details> transfers,
		std::unordered_map<crypto::hash, wallet2::unconfirmed_transfer_details> unconfirmed_txs,
		uint32_t index_major
	);
	std::map<uint32_t, uint64_t> unlocked_balance_per_subaddress(
		std::vector<wallet2::transfer_details> transfers,
		uint32_t index_major,														 
		uint64_t blockchain_size,
		bool is_testnet
	);
	//
	//
	uint32_t fixed_ringsize(); // not mixinsize, which would be ringsize-1
	uint32_t fixed_mixinsize(); // not ringsize, which would be mixinsize+1
	//
	std::string new_dummy_address_string_for_rct_tx(bool isTestnet = false);
	//
	void set_spent(wallet2::transfer_details &td, uint64_t height);
	void set_unspent(wallet2::transfer_details &td);
	void set_spent(std::vector<wallet2::transfer_details> &transfers, size_t idx, uint64_t height);
	void set_unspent(std::vector<wallet2::transfer_details> &transfers, size_t idx);
	//
	crypto::public_key get_tx_pub_key_from_received_outs(const tools::wallet2::transfer_details &td, const cryptonote::account_keys& keys, const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses);
	void check_acc_out_precomp(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, tools::wallet2::tx_scan_info_t &tx_scan_info, const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses);
	
	cryptonote::account_public_address get_subaddress(const cryptonote::subaddress_index& index, const cryptonote::account_keys& keys);
	crypto::public_key get_subaddress_spend_public_key(const cryptonote::subaddress_index& index, const cryptonote::account_keys& keys);
}
	
#endif /* monero_transfer_utils_hpp */
