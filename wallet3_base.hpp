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
//
#include "wallet2-BORROWED.h"
#include "monero_transfer_utils.hpp"

namespace tools
{
	class wallet3_base : public wallet2
	{
	public:
		//
		// Instance
		wallet3_base(cryptonote::network_type nettype, bool restricted);
		

		crypto::secret_key generate(const crypto::secret_key& recovery_param = crypto::secret_key(), bool recover = false, bool two_random = false, bool from_legacy16B_lw_seed = false);
		
		void generate(
		  const cryptonote::account_public_address &account_public_address,
		  const crypto::secret_key& spendkey, const crypto::secret_key& viewkey);
		
		void generate(
		  const cryptonote::account_public_address &account_public_address,
		  const crypto::secret_key& viewkey = crypto::secret_key());
		
		//
		//
		// Transferring
		struct CreateTx_RetVals: RetVals_base
		{
			boost::optional<std::vector<tools::wallet2::pending_tx>> pending_txs;
		};
		bool base__create_signed_transaction(
			const std::string &to_address_string,
			const std::string &amount_float_string,
			const std::string *optl__payment_id_string_ptr,
			uint32_t mixin,
			uint32_t simple_priority,
			std::set<uint32_t> subaddr_indices,
			uint32_t current_subaddress_account_idx,
			monero_transfer_utils::get_random_outs_fn_type get_random_outs_fn, // this function MUST be synchronous
			monero_transfer_utils::use_fork_rules_fn_type use_fork_rules_fn,
			//
			bool is_trusted_daemon,
			//
			wallet3_base::CreateTx_RetVals &retVals
		); // have your concrete subclass call this with special parameters
		//
	protected: // formerly private; changed to enable subclassing

	};
}
BOOST_CLASS_VERSION(tools::wallet3_base, 1)

