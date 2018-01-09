//
//  monero_key_utils.hpp
//  MyMonero
//
//  Created by Paul Shapiro on 11/29/17.
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
//
#ifndef monero_key_utils_hpp
#define monero_key_utils_hpp
//
#include <boost/utility/value_init.hpp>
#include <boost/optional.hpp>
#include "crypto.h"
//
// MyMonero legacy (16 byte) seed extensions to crypto
namespace crypto
{
	POD_CLASS nonscalar_16Byte { // TODO/FIXME: improve name (more concrete)
		char data[16];
	};
	using legacy16B_secret_key = tools::scrubbed<nonscalar_16Byte>;
	static_assert(sizeof(legacy16B_secret_key) == 16, "Invalid structure size");
	inline std::ostream &operator <<(std::ostream &o, const crypto::legacy16B_secret_key &v) {
		epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
	}
	const static crypto::legacy16B_secret_key null_legacy16B_skey = boost::value_initialized<crypto::legacy16B_secret_key>();
	//
	static unsigned long sec_seed_bytes_length = 32;
	static unsigned long legacy16B__sec_seed_bytes_length = 16;
	static unsigned long sec_seed_hex_string_length = sec_seed_bytes_length * 2;
	static unsigned long legacy16B__sec_seed_hex_string_length = legacy16B__sec_seed_bytes_length * 2;
}
CRYPTO_MAKE_HASHABLE(legacy16B_secret_key)
namespace monero_key_utils
{
	void coerce_valid_sec_key_from(
		const crypto::legacy16B_secret_key &legacy16B_mymonero_sec_seed,
		crypto::secret_key &dst__sec_seed
	);
}
//
// Shared
namespace monero_key_utils
{
}
//
#endif /* monero_key_utils_hpp */
