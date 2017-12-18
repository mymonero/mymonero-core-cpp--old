//
//  monero_address_utils.cpp
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
//
#include "monero_address_utils.hpp"
#include "cryptonote_basic/account.h"
//
#include "include_base_utils.h"
using namespace epee;
//
using namespace monero_address_utils;
//
boost::optional<monero_address_utils::DecodedAddress> monero_address_utils::decoded_address(
	const std::string &address_string
)
{
	bool has_payment_id;
	crypto::hash8 payment_id;
	cryptonote::account_public_address address_components;
	bool didSucceed = cryptonote::get_account_integrated_address_from_str(
		address_components,
		has_payment_id,
		payment_id,
		false/*isTestnet*/,
		address_string
	);
	if (didSucceed == false) {
		return boost::none;
	}
	monero_address_utils::DecodedAddress decoded_address =
	{
		address_components,
		boost::make_optional(has_payment_id, payment_id)
	};
	//
	return decoded_address;
}
//
std::string monero_address_utils::new_dummy_address_string_for_rct_tx(bool isTestnet)
{
	cryptonote::account_base account;
	account.generate();
	//
	return account.get_public_address_str(isTestnet);
}
