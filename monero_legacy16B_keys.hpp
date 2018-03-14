//
//  monero_legacy16B_keys.hpp
//  MyMonero
//
//  Created by Paul Shapiro on 3/13/18.
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
#ifndef monero_legacy16B_keys_hpp
#define monero_legacy16B_keys_hpp
//
#include "crypto.h"
#include <boost/utility/value_init.hpp>
#include "mnemonics/electrum-words.h"
#include "cryptonote_basic/account.h"
//
namespace crypto // extension
{
	POD_CLASS ec_nonscalar_16Byte {
		// extension to support old deprecated 16B/13-word seeds
		char data[16];
	};
	using legacy16B_secret_key = tools::scrubbed<ec_nonscalar_16Byte>;
	static_assert(
		sizeof(ec_nonscalar_16Byte) == 16
		&& sizeof(legacy16B_secret_key) == 16,
		"Invalid structure size"
	);

	inline std::ostream &operator <<(std::ostream &o, const legacy16B_secret_key &v) {
		epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
	}
	const static legacy16B_secret_key null_legacy16B_skey = boost::value_initialized<legacy16B_secret_key>();

	const static unsigned long sec_seed_hex_string_length = sizeof(secret_key) * 2;
	const static unsigned long legacy16B__sec_seed_hex_string_length = sizeof(legacy16B_secret_key) * 2;
	
	namespace ElectrumWords
	{
		static unsigned long legacy_16B_seed_mnemonic_word_count = 12 + 1;
		static unsigned long stable_32B_seed_mnemonic_word_count = crypto::ElectrumWords::seed_length + 1;

		/*!
		 * \brief Converts seed words to bytes (secret key).
		 * \param  words           String containing 13 words separated by spaces.
		 * \param  dst             To put the 16-byte secret key restored from the words.
		 * \param  language_name   Language of the seed as found gets written here.
		 * \return                 false if not a multiple of 3 words, or if word is not in the words list
		 */
		bool words_to_bytes(std::string words, legacy16B_secret_key& dst, std::string &language_name);
	}
}
CRYPTO_MAKE_HASHABLE(legacy16B_secret_key)
namespace monero_legacy16B_keys
{
	/* Normalizes a 16-byte, 13-word seed to a crypto::secret_key
	*/
	void coerce_valid_sec_key_from(
		const crypto::legacy16B_secret_key &legacy16B_mymonero_sec_seed,
		crypto::secret_key &dst__sec_seed
	);
}
//
#endif /* monero_legacy16B_keys_hpp */
