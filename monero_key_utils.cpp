//
//  monero_key_utils.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 11/29/17.
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
#include "monero_key_utils.hpp"
#include "cryptonote_basic.h"
#include "cryptonote_protocol/blobdatatype.h"
//
#include "include_base_utils.h"
using namespace epee;
//
boost::optional<crypto::secret_key> monero_key_utils::valid_sec_key_from(
	const std::string &key_string__ref
)
{
	std::string sec_key_string = key_string__ref;
	if (sec_key_string.empty()) {
		return boost::none;
	}
	cryptonote::blobdata sec_key_data;
	bool didParse = epee::string_tools::parse_hexstr_to_binbuff(sec_key_string, sec_key_data);
	if(!didParse || sec_key_data.size() != sizeof(crypto::secret_key)) {
		return boost::none; // TODO: return wrapped error "invalid view key"
	}
	crypto::secret_key sec;
	std::memcpy(&sec, sec_key_data.data(), sizeof(crypto::secret_key));
	//
	return sec;
}
