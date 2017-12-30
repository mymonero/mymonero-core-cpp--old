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
#include "cryptonote_basic/blobdatatype.h"
#include "string_tools.h"
//
using namespace epee;
//
void monero_key_utils::coerce_valid_sec_key_from(
	const crypto::legacy16B_secret_key &legacy16B_mymonero_sec_seed,
	crypto::secret_key &dst__sec_seed
) { // cn_fast_hash legacy16B_sec_seed in order to 'pad' it to 256 bits so it can be chopped to ec_scalar
	crypto::secret_key nonLegacy32B_sec_seed{};
	keccak((uint8_t *)&legacy16B_mymonero_sec_seed, sizeof(crypto::legacy16B_secret_key),
		   (uint8_t *)&dst__sec_seed, sizeof(crypto::secret_key));
}
