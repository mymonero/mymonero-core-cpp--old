//
//  lightwallet_response_parsing.hpp
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

#ifndef lightwallet_response_parsing_hpp
#define lightwallet_response_parsing_hpp

#import "core_rpc_server_commands_defs.h" // for response structures
#include "wallet2_transfer_utils.h" // for now

namespace lightwallet_response_parsing
{
	using namespace tools;
	using namespace cryptonote;
	//
	//
	// Parsing - "get_unspent_outs"
	//
	struct Parse_UnspentOuts_Args
	{
		Parse_UnspentOuts_Args() = delete; // disallow `Args foo;` default constructor
		//
		const cryptonote::COMMAND_RPC_GET_UNSPENT_OUTS::response &ores;
		//
		bool is_wallet_watch_only;
		const account_keys &ack;
		std::unordered_map<crypto::key_image, size_t> *key_images; // pointer to m_key_images for mutability
		std::unordered_map<crypto::public_key, size_t> *pub_keys; // pointer to m_pub_keys for mutability
		const std::unordered_map<crypto::hash, wallet2::address_tx> light_wallet_address_txs; // Light wallet info needed to populate m_payment requires 2 separate api calls (get_address_txs and get_unspent_outs); We save the info from the first call in m_light_wallet_address_txs for easier lookup.
		// store calculated key image for faster lookup
		std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> > *key_image_cache_ptr;
	};
	struct Parse_UnspentOuts_RetVals
	{
		Parse_UnspentOuts_RetVals() = delete; // disallow `RetVals foo;` default constructor
		//
		bool didError;
		std::string err_string; // this is not defined when didError!=true
		//
	};
	bool parse__get_unspent_outs( // returns !didError
		const Parse_UnspentOuts_Args &args,
		Parse_UnspentOuts_RetVals &retVals // initializes retVals for you
	);
	//
	//
	// Shared utility functions
	//
	bool parse_rct_str(const account_keys &ack, const std::string& rct_string, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key& decrypted_mask, rct::key& rct_commit, bool decrypt);
	//
	bool is_own_key_image(const account_keys &ack, const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index, std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> > *key_image_cache_ptr);
}

#endif /* lightwallet_response_parsing_hpp */
