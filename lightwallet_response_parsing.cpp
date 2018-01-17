//
//  lightwallet_response_parsing.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 1/16/18.
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
//
#include <unordered_map>
#include "lightwallet_response_parsing.hpp"
#include "monero_transfer_utils.hpp"
#include "wallet2_transfer_utils.h" // for now
//
#include "string_tools.h"
using namespace epee;
//
#include "wallet_errors.h"
using namespace tools;
using namespace cryptonote;
//
bool lightwallet_response_parsing::parse__get_unspent_outs(
														   const Parse_UnspentOuts_Args &args,
														   Parse_UnspentOuts_RetVals &retVals // initializes retVals for you
) {
	retVals = {};
	//
	if(args.ores.outputs.empty()) {
		retVals.didError = true;
		retVals.err_string = "No outputs found in response";
		return false;
	}
	std::vector<tools::wallet2::transfer_details> transfers{};
	
	uint64_t light_wallet_per_kb_fee = args.ores.per_kb_fee;
	
	std::unordered_map<crypto::hash, bool> transfers_txs;
	for(const auto &t: transfers) {
		transfers_txs.emplace(t.m_txid, t.m_spent);
	}
	MDEBUG("FOUND " << args.ores.outputs.size() <<" outputs");
	
	for (const auto &o: args.ores.outputs) {
		bool spent = false;
		bool add_transfer = true;
		crypto::key_image unspent_key_image;
		crypto::public_key tx_public_key = AUTO_VAL_INIT(tx_public_key);
		THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, o.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
		string_tools::hex_to_pod(o.tx_pub_key, tx_public_key);
		
		for (const std::string &ski: o.spend_key_images) {
			spent = false;
			
			// Check if key image is ours
			THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, ski), error::wallet_internal_error, "Invalid key image");
			string_tools::hex_to_pod(ski, unspent_key_image);
			if(is_own_key_image(args.ack, unspent_key_image, tx_public_key, o.index, args.key_image_cache_ptr)){
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
		THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, o.tx_hash), error::wallet_internal_error, "Invalid tx_hash field");
		THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, o.public_key), error::wallet_internal_error, "Invalid public_key field");
		THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, o.tx_pub_key), error::wallet_internal_error, "Invalid tx_pub_key field");
		string_tools::hex_to_pod(o.tx_hash, txid);
		string_tools::hex_to_pod(o.public_key, public_key);
		string_tools::hex_to_pod(o.tx_pub_key, tx_pub_key);
		
		for(auto &t: transfers){
			if(t.get_public_key() == public_key) {
				t.m_spent = spent;
				add_transfer = false;
				break;
			}
		}
		
		if(!add_transfer)
			continue;
		
		transfers.push_back(boost::value_initialized<wallet2::transfer_details>());
		wallet2::transfer_details& td = transfers.back();
		
		td.m_block_height = o.height;
		td.m_global_output_index = o.global_index;
		td.m_txid = txid;
		
		// Add to extra
		add_tx_pub_key_to_extra(td.m_tx, tx_pub_key);
		
		td.m_key_image = unspent_key_image;
		td.m_key_image_known = !args.is_wallet_watch_only;
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
		std::unordered_map<crypto::hash,wallet2::address_tx>::const_iterator found = args.light_wallet_address_txs.find(txid);
		THROW_WALLET_EXCEPTION_IF(found == args.light_wallet_address_txs.end(), error::wallet_internal_error, "Lightwallet: tx not found in args.light_wallet_address_txs");
		bool miner_tx = found->second.m_coinbase;
		td.m_tx.unlock_time = found->second.m_unlock_time;
		
		if (!o.rct.empty())
		{
			// Coinbase tx's
			if(miner_tx)
			{
				td.m_mask = rct::identity();
			}
			else
			{
				// rct txs
				// decrypt rct mask, calculate commit hash and compare against blockchain commit hash
				rct::key rct_commit;
				lightwallet_response_parsing::parse_rct_str(args.ack, o.rct, tx_pub_key, td.m_internal_output_index, td.m_mask, rct_commit, true);
				bool valid_commit = (rct_commit == rct::commit(td.amount(), td.m_mask));
				if(!valid_commit)
				{
					MDEBUG("output index: " << o.global_index);
					MDEBUG("mask: " + string_tools::pod_to_hex(td.m_mask));
					MDEBUG("calculated commit: " + string_tools::pod_to_hex(rct::commit(td.amount(), td.m_mask)));
					MDEBUG("expected commit: " + string_tools::pod_to_hex(rct_commit));
					MDEBUG("amount: " << td.amount());
				}
				THROW_WALLET_EXCEPTION_IF(!valid_commit, error::wallet_internal_error, "Lightwallet: rct commit hash mismatch!");
			}
			td.m_rct = true;
		}
		else
		{
			td.m_mask = rct::identity();
			td.m_rct = false;
		}
		if(!spent)
			monero_transfer_utils::set_unspent(transfers, transfers.size()-1);
		(*args.key_images)[td.m_key_image] = transfers.size()-1;
		(*args.pub_keys)[td.get_public_key()] = transfers.size()-1;
	}
	//
	return true;
}
//
bool lightwallet_response_parsing::parse_rct_str(const account_keys &ack, const std::string& rct_string, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key& decrypted_mask, rct::key& rct_commit, bool decrypt)
{
	// rct string is empty if output is non RCT
	if (rct_string.empty())
		return false;
	// rct_string is a string with length 64+64+64 (<rct commit> + <encrypted mask> + <rct amount>)
	rct::key encrypted_mask;
	std::string rct_commit_str = rct_string.substr(0,64);
	std::string encrypted_mask_str = rct_string.substr(64,64);
	THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, rct_commit_str), error::wallet_internal_error, "Invalid rct commit hash: " + rct_commit_str);
	THROW_WALLET_EXCEPTION_IF(string_tools::validate_hex(64, encrypted_mask_str), error::wallet_internal_error, "Invalid rct mask: " + encrypted_mask_str);
	string_tools::hex_to_pod(rct_commit_str, rct_commit);
	string_tools::hex_to_pod(encrypted_mask_str, encrypted_mask);
	if (decrypt) {
		// Decrypt the mask
		crypto::key_derivation derivation;
		bool r = generate_key_derivation(tx_pub_key, ack.m_view_secret_key, derivation);
		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
		crypto::secret_key scalar;
		crypto::derivation_to_scalar(derivation, internal_output_index, scalar);
		sc_sub(decrypted_mask.bytes,encrypted_mask.bytes,rct::hash_to_scalar(rct::sk2rct(scalar)).bytes);
	}
	return true;
}
//
bool lightwallet_response_parsing::is_own_key_image(const account_keys &ack, const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index, std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> > *key_image_cache_ptr)
{
	// Lookup key image from cache
	std::map<uint64_t, crypto::key_image> index_keyimage_map;
	std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> >::const_iterator found_pub_key = (*key_image_cache_ptr).find(tx_public_key);
	if(found_pub_key != (*key_image_cache_ptr).end()) {
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
	(*key_image_cache_ptr).emplace(tx_public_key, index_keyimage_map);
	return key_image == calculated_key_image;
}

