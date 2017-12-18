//
//  monero_address_utils.hpp
//  MyMonero
//
//  Created by Paul Shapiro on 11/28/17.
//  Copyright (c) 2014-2017, MyMonero.com
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

#ifndef monero_address_utils_hpp
#define monero_address_utils_hpp

#include <boost/optional.hpp>
#include "crypto.h"
#include "cryptonote_basic.h"
#include "cryptonote_basic_impl.h"
//
namespace monero_address_utils
{
	//
	// Decoding addresses
	struct DecodedAddress
	{
		cryptonote::account_public_address address_components;
		boost::optional<crypto::hash8> optl__payment_id;
	};
	boost::optional<DecodedAddress> decoded_address(
		const std::string &address_string // normal wallet or integrated address
	);
	//
	// Building transactions
	std::string new_dummy_address_string_for_rct_tx(bool isTestnet = false); // in case there is no change to be returned and an extra destination is needed
	// ^- TODO: when able to return address object, do so, for consumption by wallet2
}
#endif /* monero_address_utils_hpp */
