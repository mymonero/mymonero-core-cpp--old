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
#include "monero_paymentID_utils.hpp"
//
using namespace monero_transfer_utils;
using namespace monero_fork_rules;
using namespace cryptonote;
using namespace std;
using namespace crypto;

#define SUBADDRESS_LOOKAHEAD_MAJOR 50
#define SUBADDRESS_LOOKAHEAD_MINOR 200

namespace tools
{
	wallet3_base::wallet3_base(cryptonote::network_type nettype, bool restricted)
	  : tools::wallet2(nettype, restricted)
	{
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
		m_key_on_device = false;
		
//		// calculate a starting refresh height
//		if(m_refresh_from_block_height == 0 && !recover){
//			m_refresh_from_block_height = estimate_blockchain_height();
//		}
		
		cryptonote::block b;
		generate_genesis(b);
		m_blockchain.push_back(get_block_hash(b));
		add_subaddress_account(tr("Primary account"));
		
		return retval;
		
	}

	void wallet3_base::generate(
	  const cryptonote::account_public_address &account_public_address,
	  const crypto::secret_key& spendkey, const crypto::secret_key& viewkey)
	{
	  clear();

	  m_account.create_from_keys(account_public_address, spendkey, viewkey);
	  m_account_public_address = account_public_address;
	  m_watch_only = false;
	  m_multisig = false;
	  m_multisig_threshold = 0;
	  m_multisig_signers.clear();
	  m_key_on_device = false;

	  cryptonote::block b;
	  generate_genesis(b);
	  m_blockchain.push_back(get_block_hash(b));
	  add_subaddress_account(tr("Primary account"));
	}
	//
	// Transferring
	bool wallet3_base::base__create_signed_transaction(
		const std::string &to_address_string,
		const std::string &amount_float_string,
		const std::string *optl__payment_id_string_ptr,
		uint32_t mixin,
		uint32_t priority,
		std::set<uint32_t> subaddr_indices,
		uint32_t current_subaddress_account_idx,
		monero_transfer_utils::get_random_outs_fn_type get_random_outs_fn,
		monero_transfer_utils::use_fork_rules_fn_type use_fork_rules_fn,
		bool is_trusted_daemon,
		//
		wallet3_base::CreateTx_RetVals &retVals
	) {
		retVals = {};
		//
		// Detect hash8 or hash32 char hex string as pid and configure 'extra' accordingly
		std::vector<uint8_t> extra;
		bool payment_id_seen = false;
		{
			bool r = false;
			if (optl__payment_id_string_ptr) {
				crypto::hash payment_id;
				r = monero_paymentID_utils::parse_long_payment_id((*optl__payment_id_string_ptr), payment_id);
				if (r) {
					std::string extra_nonce;
					cryptonote::set_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
					r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
				} else {
					crypto::hash8 payment_id8;
					r = monero_paymentID_utils::parse_short_payment_id((*optl__payment_id_string_ptr), payment_id8);
					if (r) {
						std::string extra_nonce;
						cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id8);
						r = cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce);
					}
				}
				if (!r) {
					retVals.did_error = true;
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
			r = cryptonote::get_account_address_from_str(info, nettype(), to_address_string);
			if (!r) {
				retVals.did_error = true;
				retVals.err_string = "couldn't parse address.";
				return false;
			}
			de.addr = info.address;
			de.is_subaddress = info.is_subaddress;
			//
			if (info.has_payment_id) {
				if (payment_id_seen) {
					retVals.did_error = true;
					retVals.err_string = "a single transaction cannot use more than one payment id";
					return false;
				}
				std::string extra_nonce;
				set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, info.payment_id);
				bool r = add_extra_nonce_to_tx_extra(extra, extra_nonce);
				if (!r) {
					retVals.did_error = true;
					retVals.err_string = "failed to set up payment id, though it was decoded correctly";
					return false;
				}
				payment_id_seen = true;
			}
			//
			r = cryptonote::parse_amount(de.amount, amount_float_string);
			THROW_WALLET_EXCEPTION_IF(!r || 0 == de.amount, error::wallet_internal_error, "amount is wrong... expected number from 0 to " + print_money(std::numeric_limits<uint64_t>::max()));
		}
		dsts.push_back(de);
		//
		uint64_t unlock_block = 0; // aka unlock_time
		// TODO: support locked txs
		//	if (transfer_type == TransferLocked) {
		//		bc_height = get_daemon_blockchain_height(err);
		//		if (!err.empty()) {
		//			fail_msg_writer() << tr("failed to get blockchain height: ") << err;
		//			return false;
		//		}
		//		unlock_block = bc_height + locked_blocks;
		//	}
		bool merge_destinations = false; // apparent default from wallet2
		//
		std::vector<wallet2::pending_tx> pending_txs = create_transactions_2(dsts, mixin, unlock_block, priority, extra, current_subaddress_account_idx, subaddr_indices, is_trusted_daemon);
		//
		// ^- TODO: this could throw; handled?
		// previous:
//		if (pendingTxs_retVals.did_error) {
//			retVals.did_error = true;
//			retVals.err_string = *pendingTxs_retVals.err_string;
//			//
//			return false;
//		}
//		THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Unexpected !did_succeed=false without an error");
		if (pending_txs.empty()) {
			retVals.did_error = true;
			retVals.err_string = "No outputs found, or daemon is not ready"; // TODO: improve error message appropriateness; return code instead of string
			return false;
		}
		//
		retVals.pending_txs = pending_txs;
		//
		return true;
	}
}
