//
//  monero_multisig_utils.hpp
//  MyMonero
//
//  Created by Paul Shapiro on 1/30/17.
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
#ifndef monero_multisig_utils_hpp
#define monero_multisig_utils_hpp
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
#include "wallet2_transfer_utils.h" // to be renamed / phased out after moving relevant types
using namespace tools;
//
//
namespace monero_multisig_utils
{
	// Wallet-public values
	crypto::public_key get_multisig_signer_public_key(const crypto::secret_key &spend_skey, bool is_wallet_multisig);
	crypto::public_key get_multisig_signer_public_key(bool is_wallet_multisig, const cryptonote::account_keys &account_keys);
	crypto::public_key get_multisig_signing_public_key(size_t idx, bool is_wallet_multisig, const std::vector<crypto::secret_key> &account_multisig_keys);
	crypto::public_key get_multisig_signing_public_key(const crypto::secret_key &skey, bool is_wallet_multisig);
	//
	// Wallet-private values
	crypto::key_image get_multisig_composite_key_image(size_t n, const std::vector<wallet2::transfer_details> &transfers, const cryptonote::account_keys &account_keys, const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses);
	rct::multisig_kLRki get_multisig_composite_kLRki(size_t n, const crypto::public_key &ignore, std::unordered_set<rct::key> &used_L, std::unordered_set<rct::key> &new_used_L, const std::vector<wallet2::transfer_details> &transfers, uint32_t multisig_threshold);
	rct::multisig_kLRki get_multisig_kLRki(size_t n, const rct::key &k, const std::vector<wallet2::transfer_details> &transfers);
	rct::key get_multisig_k(size_t idx, const std::unordered_set<rct::key> &used_L, bool is_wallet_multisig, const std::vector<wallet2::transfer_details> &transfers);

}
	
#endif /* monero_multisig_utils_hpp */
