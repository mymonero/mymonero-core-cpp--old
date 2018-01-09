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
#define SECOND_OUTPUT_RELATEDNESS_THRESHOLD 0.0f
// used to choose when to stop adding outputs to a tx
#define APPROXIMATE_INPUT_BYTES 80
// used to target a given block size (additional outputs may be added on top to build fee)
#define TX_SIZE_TARGET(bytes) (bytes*2/3)
//
namespace monero_transfer_utils
{	
//	//
//	// Common - Types
//	struct transfer_details
//	{
//		uint64_t m_block_height;
//		cryptonote::transaction_prefix m_tx;
//		crypto::hash m_txid;
//		size_t m_internal_output_index;
//		uint64_t m_global_output_index;
//		bool m_spent;
//		uint64_t m_spent_height;
//		crypto::key_image m_key_image; //TODO: key_image stored twice :(
//		rct::key m_mask;
//		uint64_t m_amount;
//		bool m_rct;
//		bool m_key_image_known;
//		size_t m_pk_index;
//		//
//		bool is_rct() const { return m_rct; }
//		uint64_t amount() const { return m_amount; }
//		const crypto::public_key &get_public_key() const {
//			return boost::get<const cryptonote::txout_to_key>(m_tx.vout[m_internal_output_index].target).key;
//		}
//		BEGIN_SERIALIZE_OBJECT()
//			FIELD(m_block_height)
//			FIELD(m_tx)
//			FIELD(m_txid)
//			FIELD(m_internal_output_index)
//			FIELD(m_global_output_index)
//			FIELD(m_spent)
//			FIELD(m_spent_height)
//			FIELD(m_key_image)
//			FIELD(m_mask)
//			FIELD(m_amount)
//			FIELD(m_rct)
//			FIELD(m_key_image_known)
//			FIELD(m_pk_index)
//		END_SERIALIZE()
//	};
//	struct payment_details
//	{
//		crypto::hash m_tx_hash;
//		uint64_t m_amount;
//		uint64_t m_block_height;
//		uint64_t m_unlock_time;
//		uint64_t m_timestamp;
//	};
//	typedef std::tuple<uint64_t, crypto::public_key, rct::key> get_outs_entry;
//	struct unconfirmed_transfer_details
//	{
//		cryptonote::transaction_prefix m_tx;
//		uint64_t m_amount_in;
//		uint64_t m_amount_out;
//		uint64_t m_change;
//		time_t m_sent_time;
//		std::vector<cryptonote::tx_destination_entry> m_dests;
//		crypto::hash m_payment_id;
//		enum { pending, pending_not_in_pool, failed } m_state;
//		uint64_t m_timestamp;
//	};
//	struct confirmed_transfer_details
//	{
//		uint64_t m_amount_in;
//		uint64_t m_amount_out;
//		uint64_t m_change;
//		uint64_t m_block_height;
//		std::vector<cryptonote::tx_destination_entry> m_dests;
//		crypto::hash m_payment_id;
//		uint64_t m_timestamp;
//		//
//		confirmed_transfer_details(): m_amount_in(0), m_amount_out(0), m_change((uint64_t)-1), m_block_height(0), m_payment_id(cryptonote::null_hash) {}
//		confirmed_transfer_details(const unconfirmed_transfer_details &utd, uint64_t height):
//		m_amount_in(utd.m_amount_in), m_amount_out(utd.m_amount_out), m_change(utd.m_change), m_block_height(height), m_dests(utd.m_dests), m_payment_id(utd.m_payment_id), m_timestamp(utd.m_timestamp) {}
//	};
//	struct tx_construction_data
//	{
//		std::vector<cryptonote::tx_source_entry> sources;
//		cryptonote::tx_destination_entry change_dts;
//		std::vector<cryptonote::tx_destination_entry> splitted_dsts; // split, includes change
//		std::list<size_t> selected_transfers;
//		std::vector<uint8_t> extra;
//		uint64_t unlock_time;
//		bool use_rct;
//		std::vector<cryptonote::tx_destination_entry> dests; // original setup, does not include change
//	};
//	typedef std::vector<transfer_details> transfer_container;
//	struct tx_dust_policy
//	{
//		uint64_t dust_threshold;
//		bool add_to_fee;
//		cryptonote::account_public_address addr_for_dust;
//		
//		tx_dust_policy(uint64_t a_dust_threshold = 0, bool an_add_to_fee = true, cryptonote::account_public_address an_addr_for_dust = cryptonote::account_public_address())
//		: dust_threshold(a_dust_threshold)
//		, add_to_fee(an_add_to_fee)
//		, addr_for_dust(an_addr_for_dust)
//		{
//		}
//	};
//	//
//	// The convention for destinations is:
//	// dests does not include change
//	// splitted_dsts (in construction_data) does
//	struct pending_tx
//	{
//		cryptonote::transaction tx;
//		uint64_t dust, fee;
//		bool dust_added_to_fee;
//		cryptonote::tx_destination_entry change_dts;
//		std::list<size_t> selected_transfers;
//		std::string key_images;
//		crypto::secret_key tx_key;
//		std::vector<cryptonote::tx_destination_entry> dests;
//		
//		tx_construction_data construction_data;
//	};
//	// The term "Unsigned tx" is not really a tx since it's not signed yet.
//	// It doesnt have tx hash, key and the integrated address is not separated into addr + payment id.
//	struct unsigned_tx_set
//	{
//		std::vector<tx_construction_data> txes;
//		transfer_container transfers;
//	};
//	struct signed_tx_set
//	{
//		std::vector<pending_tx> ptx;
//		std::vector<crypto::key_image> key_images;
//	};
//	//
//	// Interface - Constructing new transactions
//	struct CreateTx_Args
//	{
//		CreateTx_Args() = delete; // disallow `CreateTx_Args foo;` default constructor
//		//
//		std::string sec_viewKey_string;
//		std::string sec_spendKey_string;
//		//
//		std::vector<cryptonote::tx_destination_entry> dsts;
//		std::vector<transfer_details> transfers;
//		std::function<bool(std::vector<std::vector<get_outs_entry>> &, const std::list<size_t> &, size_t)> get_random_outs_fn;
//		//
//		uint64_t blockchain_size;
//		const uint64_t unlock_time;
//		uint32_t priority;
//		uint32_t default_priority;
//		//
//		uint32_t min_output_count;
//		uint64_t min_output_value;
//		bool merge_destinations;
//		//
//		const std::string *optl__payment_id_string;
//		//
//		bool is_testnet;
//	};
//	struct CreateTx_RetVals
//	{
//		CreateTx_RetVals() = delete; // disallow `CreateTx_RetVals foo;` default constructor
//		//
//		bool didError;
//		std::string err_string; // this is not defined when didError!=true
//		//
//		signed_tx_set signed_tx_set;
//	};
//	bool create_signed_transaction( // returns !didError
//		const CreateTx_Args &args,
//		CreateTx_RetVals &retVals // initializes retVals for you
//	);
//	//
//	// Shared / Utility / Common - Functions
//	struct TransferSelected_ErrRetVals
//	{
//		bool didError;
//		std::string err_string;
//	};
//	bool _transfer_selected_rct(
//		const cryptonote::account_keys &account_keys,
//		const transfer_container &transfers,
//		std::vector<cryptonote::tx_destination_entry> dsts,
//		const std::list<size_t> selected_transfers,
//		const std::function<bool(std::vector<std::vector<get_outs_entry>> &, const std::list<size_t> &, size_t)> get_random_outs_fn,
//		size_t fake_outputs_count,
//		std::vector<std::vector<get_outs_entry>> &outs,
//		uint64_t unlock_time,
//		uint64_t fee,
//		const std::vector<uint8_t>& extra,
//		cryptonote::transaction& tx,
//		pending_tx &ptx,
//		bool is_testnet,
//		TransferSelected_ErrRetVals &err_retVals
//	);
//	template<typename T>
//	bool _transfer_selected_nonrct(
//		const cryptonote::account_keys &account_keys,
//		const transfer_container &transfers,
//		const std::vector<cryptonote::tx_destination_entry>& dsts,
//		const std::list<size_t> selected_transfers,
//		const std::function<bool(std::vector<std::vector<get_outs_entry>> &, const std::list<size_t> &, size_t)> get_random_outs_fn,
//		size_t fake_outputs_count,
//		std::vector<std::vector<get_outs_entry>> &outs,
//		uint64_t unlock_time,
//		uint64_t fee,
//		const std::vector<uint8_t>& extra,
//		T destination_split_strategy,
//		const tx_dust_policy& dust_policy,
//		cryptonote::transaction& tx,
//		pending_tx &ptx,
//		bool is_testnet,
//		TransferSelected_ErrRetVals &err_retVals
//	);
//	//
//	// NOTE/FIXME: Some of these fee methods have been temporarily internally modified and do not currently behave the same as wallet2.cpp's - compare and (constructively) normalize to integrate
//	uint64_t get_upper_transaction_size_limit();
//	uint64_t get_fee_multiplier(uint32_t priority, uint32_t default_priority, int fee_algorithm);
//	uint64_t dynamic_per_kb_fee_estimate();
//	uint64_t per_kb_fee();
//	int fee_algorithm();
//	uint64_t calculated_fee(uint64_t fee_per_kb, size_t bytes, uint64_t fee_multiplier);
//	uint64_t calculated_fee(uint64_t fee_per_kb, const cryptonote::blobdata &blob, uint64_t fee_multiplier);
//	//
//	size_t estimated_rct_tx_size(int n_inputs, int mixin, int n_outputs);
//	size_t estimated_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs);
//	//
//	uint64_t num_rct_outputs();
//	std::vector<size_t> picked_preferred_rct_inputs(const transfer_container &transfers, uint64_t needed_money, uint64_t blockchain_size, bool is_testnet);
//	bool should_pick_a_second_output(bool use_rct, const transfer_container &transfers, size_t n_transfers, const std::vector<size_t> &unused_transfers_indices, const std::vector<size_t> &unused_dust_indices);
//	size_t pop_best_value_from(const transfer_container &transfers, std::vector<size_t> &unused_indices, const std::list<size_t>& selected_transfers, bool smallest = false);
//	size_t pop_best_value(std::vector<size_t> &unused_indices, const std::list<size_t>& selected_transfers, bool smallest);
//	std::vector<size_t> get_only_rct(const transfer_container &transfers, const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices);
//	uint32_t get_count_above(const transfer_container &transfers, const std::vector<size_t> &indices, uint64_t threshold);
//	float get_output_relatedness(const transfer_details &td0, const transfer_details &td1);
//	//
//	bool is_transfer_unlocked(const transfer_details& td, uint64_t blockchain_size, bool is_testnet = false);
//	bool is_tx_spendtime_unlocked(uint64_t unlock_time, uint64_t block_height, uint64_t blockchain_size, bool is_testnet = false);
//	uint64_t get_unlocked_balance(const transfer_container &transfers, uint64_t blockchain_size, bool is_testnet);
//	//
	size_t fixed_ringsize(); // not mixinsize, which would be ringsize-1
	size_t fixed_mixinsize(); // not ringsize, which would be mixinsize+1
	
	std::string new_dummy_address_string_for_rct_tx(bool isTestnet = false);

//	//
//	namespace detail
//	{
//		//----------------------------------------------------------------------------------------------------
//		inline void digit_split_strategy(
//			const std::vector<cryptonote::tx_destination_entry>& dsts,
//			const cryptonote::tx_destination_entry& change_dst, uint64_t dust_threshold,
//			std::vector<cryptonote::tx_destination_entry>& splitted_dsts,
//			std::vector<cryptonote::tx_destination_entry> &dust_dsts
//		) {
//			splitted_dsts.clear();
//			dust_dsts.clear();
//			//
//			for(auto& de: dsts) {
//				cryptonote::decompose_amount_into_digits(
//					de.amount, 0,
//					[&](uint64_t chunk) { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, de.addr)); },
//					[&](uint64_t a_dust) { splitted_dsts.push_back(cryptonote::tx_destination_entry(a_dust, de.addr)); }
//				);
//			}
//			cryptonote::decompose_amount_into_digits(
//				change_dst.amount, 0,
//				[&](uint64_t chunk) {
//					if (chunk <= dust_threshold) {
//						dust_dsts.push_back(cryptonote::tx_destination_entry(chunk, change_dst.addr));
//					} else {
//						splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, change_dst.addr));
//					}
//				},
//				[&](uint64_t a_dust) { dust_dsts.push_back(cryptonote::tx_destination_entry(a_dust, change_dst.addr)); }
//			);
//		}
//		inline void null_split_strategy(
//			const std::vector<cryptonote::tx_destination_entry>& dsts,
//			const cryptonote::tx_destination_entry& change_dst, uint64_t dust_threshold,
//			std::vector<cryptonote::tx_destination_entry>& splitted_dsts,
//			std::vector<cryptonote::tx_destination_entry> &dust_dsts
//		) {
//			splitted_dsts = dsts;
//			//
//			dust_dsts.clear();
//			uint64_t change = change_dst.amount;
//			//
//			if (0 != change) {
//				splitted_dsts.push_back(cryptonote::tx_destination_entry(change, change_dst.addr));
//			}
//		}
//		inline void print_source_entry(
//			const cryptonote::tx_source_entry& src
//		) {
//			std::string indexes;
//			std::for_each(src.outputs.begin(), src.outputs.end(), [&](const cryptonote::tx_source_entry::output_entry& s_e) { indexes += boost::to_string(s_e.first) + " "; });
//			LOG_PRINT_L0("amount=" << cryptonote::print_money(src.amount) << ", real_output=" <<src.real_output << ", real_output_in_tx_index=" << src.real_output_in_tx_index << ", indexes: " << indexes);
//		}
//	}
}
	
#endif /* monero_transfer_utils_hpp */
