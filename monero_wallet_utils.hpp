//
//  monero_wallet_utils.hpp
//  MyMonero
//
//  Created by Paul Shapiro on 11/23/17.
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

#ifndef monero_wallet_utils_hpp
#define monero_wallet_utils_hpp

#include <boost/optional.hpp>
#include "crypto.h"
#include "monero_key_utils.hpp" // for the legacy 16 byte seed type support
#include "cryptonote_basic.h"
#include "cryptonote_basic_impl.h"
#include "electrum-words.h"
#include "mnemonics/singleton.h"
#include "mnemonics/english.h"
//
//
// Legacy seed / mnemonic utils fns
namespace crypto
{
	namespace ElectrumWords
	{
		bool bytes_to_words(const crypto::legacy16B_secret_key& src,
							std::string& words,
							const std::string &language_name);
		bool words_to_bytes(std::string words,
							crypto::legacy16B_secret_key& dst,
							std::string &language_name);
		//
		static unsigned long legacy_16B_seed_mnemonic_word_count = 13;
		static unsigned long stable_32B_seed_mnemonic_word_count = 25;
	}
}
//
namespace monero_wallet_utils
{
	//
	// Accounts
	struct MnemonicDecodedSeed_RetVals
	{
		bool did_error = false;
		boost::optional<std::string> optl__err_string = boost::none;
		//
		boost::optional<crypto::secret_key> optl__sec_seed = boost::none;
		boost::optional<std::string> optl__sec_seed_string = boost::none;
		boost::optional<std::string> optl__mnemonic_string = boost::none;
		bool from_legacy16B_lw_seed = false;
	};
	bool decoded_seed(
		const std::string &mnemonic_string,
		const std::string &mnemonic_language_string,
		//
		MnemonicDecodedSeed_RetVals &retVals
	);
	//
	// Convenience functions - Wallets
	struct WalletDescription
	{
		std::string sec_seed_string; // as string bc it might by legacy 16B style aside from crypto::secret_key
		//
		std::string address_string;
		//
		crypto::secret_key sec_spendKey;
		crypto::secret_key sec_viewKey;
		crypto::public_key pub_spendKey;
		crypto::public_key pub_viewKey;
		//
		std::string mnemonic_string; // mnemonic_language is not returned because it must be provided to all functions which can return a WalletDescription
	};
	struct WalletDescriptionRetVals
	{
		bool did_error = false;
		boost::optional<std::string> optl__err_string = boost::none;
		//
		boost::optional<WalletDescription> optl__desc = boost::none;
	};
	bool new_wallet(
		const std::string &mnemonic_language,
		WalletDescriptionRetVals &retVals,
		bool isTestnet = false
	);
	bool wallet_with(
		const std::string &mnemonic_string,
		const std::string &mnemonic_language__ptr,
		WalletDescriptionRetVals &retVals,
		bool isTestnet = false
	);
	//
	struct WalletComponentsToValidate
	{
		std::string address_string; // Required
		std::string sec_viewKey_string; // Required
		const std::string *optl__sec_spendKey_string;
		const std::string *optl__sec_seed_string;
		bool isTestnet;
	};
	struct WalletComponentsValidationResults
	{
		bool didError;
		std::string err_string;
		bool isValid; // this will naturally remain false if didError=true
		std::string pub_spendKey_string;
		std::string pub_viewKey_string;
		bool isInViewOnlyMode; // !sec_seed && !sec_spendKey
	};
	bool validate_wallet_components_with( // returns !didError
		const WalletComponentsToValidate &inputs,
		WalletComponentsValidationResults &outputs
	);
}

#endif /* monero_wallet_utils_hpp */
