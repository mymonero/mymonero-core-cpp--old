//
//  monero_legacy16B_keys.cpp
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

#include "monero_legacy16B_keys.hpp"
#include "keccak.h"
//
using namespace crypto;
//
void cn_pad_by_fast_hash__C(
	const uint8_t *in, size_t inlen,
	uint8_t *md, int mdlen
) {
	keccak(in, inlen, md, mdlen);
}
inline void cn_pad_by_fast_hash(const uint8_t *indata, std::size_t inlen, uint8_t *outdata, std::size_t outlen)
{
	cn_pad_by_fast_hash__C(indata, inlen, outdata, (int)outlen);
}
//
void monero_legacy16B_keys::coerce_valid_sec_key_from(
	const legacy16B_secret_key &legacy16B_mymonero_sec_seed,
	secret_key &dst__sec_seed
) { // cn_fast_hash legacy16B_sec_seed in order to 'pad' it to 256 bits so it can be chopped to ec_scalar
	static_assert(!epee::has_padding<legacy16B_secret_key>(), "potential hash of padding data");
	static_assert(!epee::has_padding<secret_key>(), "writing to struct with extra data");
	cn_pad_by_fast_hash(
		(uint8_t *)&legacy16B_mymonero_sec_seed, sizeof(legacy16B_secret_key),
		(uint8_t *)&dst__sec_seed, sizeof(secret_key)
	);
}
//
bool crypto::ElectrumWords::words_to_bytes(std::string words, legacy16B_secret_key& dst, std::string &language_name)
{
	std::string s;
	if (!words_to_bytes(words, s, sizeof(dst), true, language_name))
		return false;
	if (s.size() != sizeof(dst))
		return false;
	memcpy(dst.data, s.data(), sizeof(dst.data));
	return true;
}
bool bytes_to_words(const legacy16B_secret_key& src, std::string& words, const std::string &language_name)
{
	return crypto::ElectrumWords::bytes_to_words(src.data, sizeof(src), words, language_name);
}
