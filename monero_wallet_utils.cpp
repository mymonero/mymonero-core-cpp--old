//
//  monero_wallet_utils.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 11/23/17.
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
#include "monero_wallet_utils.hpp"
#include <boost/algorithm/string.hpp>
#include "cryptonote_basic/account.h"
#include "monero_key_utils.hpp"
//
#include "string_tools.h"
using namespace epee;
//
extern "C" {
	#include "crypto-ops.h"
}
//
using namespace monero_wallet_utils;
//
boost::optional<monero_wallet_utils::WalletDescription> monero_wallet_utils::new_wallet(
    const std::string &mnemonic_language__ref,
	bool isTestnet
)
{
	cryptonote::account_base account{}; // this initializes the wallet and should call the default constructor
	crypto::secret_key sec_seed = account.generate(); // NOTE: this is actually returning 'first' BUT apparently 'first' in Monero core is /actually/ the "seed" in legacy MyMonero monero_wallet_utils.js / cryptonote_utils.js (!!)… while the same legacy cryptonote_utils.js create_address(…) appears to use the name 'first' to describe the first reduction (or else hashing) of the rng seed – since the 'seed' given to cryptonote_utils.create_address(…) has already been sc_reduce32'd
	//
	const cryptonote::account_keys& keys = account.get_keys();
	std::string address_string = account.get_public_address_str(isTestnet); // getting the string here instead of leaving it to the consumer b/c get_public_address_str could potentially change in implementation (see TODO) so it's not right to duplicate that here
	boost::optional<std::string> optl__mnemonic_string = monero_wallet_utils::mnemonic_string_from(sec_seed, mnemonic_language__ref);
	if (!optl__mnemonic_string) {
		return boost::none; // TODO: return error string? e.g. 'unable to obtain mnemonic - check language'
	}
	const WalletDescription walletDescription =
	{
		sec_seed,
		//
		address_string,
		//
		keys.m_spend_secret_key,
		keys.m_view_secret_key,
		keys.m_account_address.m_spend_public_key,
		keys.m_account_address.m_view_public_key,
		//
		std::move(*optl__mnemonic_string)
	};
	//
	return walletDescription;	
}
//
boost::optional<std::string> monero_wallet_utils::mnemonic_string_from(
	const crypto::secret_key sec_seed,
	const std::string &mnemonic_language__ref
)
{
	std::string mnemonic_string;
	bool didSucceed = crypto::ElectrumWords::bytes_to_words(sec_seed, mnemonic_string, mnemonic_language__ref);
	if (didSucceed == false) {
		return boost::none; // returning 'nil' … TODO: any error (msg) to relay in future?
	}
	//
	return {std::move(mnemonic_string)}; /*return mnemonic_string;*/ // <- returning optional containing moved str b/c "the compiler will implicitly construct boost::optional<std::string> by copying mnemonic_string then move the implicitly constructed object."
}
//
boost::optional<crypto::secret_key> monero_wallet_utils::sec_seed_from(
	const std::string &mnemonic_string,
	std::string mnemonic_language // not sure why ElectrumWords::words_to_bytes can't take a ref
)
{
	crypto::secret_key sec_seed;
	bool didSucceed = crypto::ElectrumWords::words_to_bytes(mnemonic_string, sec_seed, mnemonic_language);
	if (didSucceed == false) {
		return boost::none; // returning 'nil' … TODO: any error (msg) to relay in future?
	}
	//
	return boost::optional<crypto::secret_key>{sec_seed};
}
//
boost::optional<WalletDescription> monero_wallet_utils::wallet_with(
	const std::string &mnemonic_string_ref,
	const std::string &mnemonic_language__ref,
	bool isTestnet
)
{
	// sanitize inputs
	std::string mnemonic_string = mnemonic_string_ref; // copy for to_lower… TODO: any better way?
	boost::algorithm::to_lower(mnemonic_string);
	//
	boost::optional<crypto::secret_key> optl__sec_seed = monero_wallet_utils::sec_seed_from(mnemonic_string, mnemonic_language__ref);
	if (!optl__sec_seed) {
		return boost::none; // TODO: return err value as well?
	}
	crypto::secret_key sec_seed = *optl__sec_seed;
	cryptonote::account_base account{}; // this initializes the wallet and should call the default constructor
	account.generate(sec_seed, true/*recover*/, false/*two_random*/);
	std::string address_string = account.get_public_address_str(isTestnet);
	const cryptonote::account_keys& keys = account.get_keys();
	const WalletDescription walletDescription =
	{
		sec_seed,
		//
		address_string,
		//
		keys.m_spend_secret_key,
		keys.m_view_secret_key,
		keys.m_account_address.m_spend_public_key,
		keys.m_account_address.m_view_public_key,
		//
		mnemonic_string // copy for purposes of return…
	};
	//
	return walletDescription;
}

bool monero_wallet_utils::validate_wallet_components_with(
	const monero_wallet_utils::WalletComponentsToValidate &inputs,
	monero_wallet_utils::WalletComponentsValidationResults &outputs
)
{ // TODO: how can the err_strings be prepared for localization?
	outputs = {};
	bool r;
	//
	// Address
	cryptonote::address_parse_info decoded_address_info;
	r = cryptonote::get_account_address_from_str(
		decoded_address_info,
		inputs.isTestnet,
		inputs.address_string
	);
	if (r == false) {
		outputs.didError = true;
		outputs.err_string = "Invalid address";
		//
		return false;
	}
	//
	// View key:
	boost::optional<crypto::secret_key> sec_viewKey__orNil = monero_key_utils::valid_sec_key_from(inputs.sec_viewKey_string);
	if (!sec_viewKey__orNil) {
		outputs.didError = true;
		outputs.err_string = "Invalid view key";
		//
		return false;
	}
	crypto::secret_key sec_viewKey = *sec_viewKey__orNil; // so we can use it (FIXME: does this cause a copy?)
	// Validate pub key derived from sec view key matches decoded_address-cached pub key
	crypto::public_key expected_pub_viewKey;
	r = crypto::secret_key_to_public_key(sec_viewKey, expected_pub_viewKey);
	if (r == false) {
		outputs.didError = true;
		outputs.err_string = "Invalid view key";
		//
		return false;
	}
	if (decoded_address_info.address.m_view_public_key != expected_pub_viewKey) {
		outputs.didError = true;
		outputs.err_string = "View key does not match address";
		//
		return false;
	}
	//
	// View-only vs spend-key/seed
	outputs.isInViewOnlyMode = true; // setting the ground state
	//
	crypto::secret_key sec_spendKey; // may be initialized
	if (inputs.optl__sec_spendKey_string) {
		// First check if spend key content actually exists before passing to valid_sec_key_from - so that a spend key decode error can be treated as a failure instead of detecting empty spend keys too
		if ((*inputs.optl__sec_spendKey_string).empty() == false) {
			boost::optional<crypto::secret_key> sec_spendKey_orNil = monero_key_utils::valid_sec_key_from(*inputs.optl__sec_spendKey_string);
			if (!sec_spendKey_orNil) { // this is an actual parse error exit condition
				outputs.didError = true;
				outputs.err_string = "Invalid spend key";
				//
				return false;
			}
			sec_spendKey = *sec_spendKey_orNil; // so we can use it below in possible seed validation (FIXME: does this cause a copy?)
			// Validate pub key derived from sec spend key matches decoded_address_info-cached pub key
			crypto::public_key expected_pub_spendKey;
			r = crypto::secret_key_to_public_key(sec_spendKey, expected_pub_spendKey);
			if (r == false) {
				outputs.didError = true;
				outputs.err_string = "Invalid spend key";
				//
				return false;
			}
			if (decoded_address_info.address.m_spend_public_key != expected_pub_spendKey) {
				outputs.didError = true;
				outputs.err_string = "Spend key does not match address";
				//
				return false;
			}
			outputs.isInViewOnlyMode = false;
		}
	}
	if (inputs.optl__sec_seed_string) {
		if ((*inputs.optl__sec_seed_string).empty() == false) {
			boost::optional<crypto::secret_key> sec_seed_orNil = monero_key_utils::valid_sec_key_from(*inputs.optl__sec_seed_string);
			if (!sec_seed_orNil) { // this is an actual parse error exit condition bc we ensured it's not empty
				outputs.didError = true;
				outputs.err_string = "Invalid seed";
				//
				return false;
			}
			crypto::secret_key sec_seed = *sec_seed_orNil; // so we can use it (FIXME: does this cause a copy?)
			cryptonote::account_base expected_account{}; // this initializes the wallet and should call the default constructor
			expected_account.generate(sec_seed, true/*recover*/, false/*two_random*/);
			const cryptonote::account_keys& expected_account_keys = expected_account.get_keys();
			crypto::secret_key expected_account__sec_viewKey = expected_account_keys.m_view_secret_key;
			crypto::secret_key expected_account__sec_spendKey = expected_account_keys.m_spend_secret_key;
			// TODO: assert sec_spendKey initialized?
			if (expected_account__sec_viewKey != sec_viewKey
				|| expected_account__sec_spendKey != sec_spendKey
				|| expected_account_keys.m_account_address.m_view_public_key != decoded_address_info.address.m_view_public_key
				|| expected_account_keys.m_account_address.m_spend_public_key != decoded_address_info.address.m_spend_public_key) {
				outputs.didError = true;
				outputs.err_string = "Seed does not match generated keys";
				//
				return false;
			}
			//
			outputs.isInViewOnlyMode = false; // TODO: should this ensure that sec_spendKey is not nil? spendKey should always be available if the seed is…
		}
	}
	outputs.pub_viewKey_string = string_tools::pod_to_hex(decoded_address_info.address.m_view_public_key);
	outputs.pub_spendKey_string = string_tools::pod_to_hex(decoded_address_info.address.m_spend_public_key);
	outputs.isValid = true;
	//
	return true;
}
