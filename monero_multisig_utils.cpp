//
//  monero_multisig_utils.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 1/30/17.
//  Copyright © 2017 MyMonero. All rights reserved.
//
//
#include <random>
//
#include "monero_multisig_utils.hpp"
#include "monero_transfer_utils.hpp"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "multisig.h"
#include "include_base_utils.h"
#include "misc_log_ex.h"
//
using namespace std;
using namespace epee;
using namespace cryptonote;
using namespace tools; // for error::
//
using namespace monero_multisig_utils;
//
//
crypto::public_key monero_multisig_utils::get_multisig_signer_public_key(const crypto::secret_key &spend_skey, bool is_wallet_multisig)
{
	crypto::public_key pkey;
	crypto::secret_key_to_public_key(get_multisig_blinded_secret_key(spend_skey), pkey);
	return pkey;
}
crypto::public_key monero_multisig_utils::get_multisig_signer_public_key(bool is_wallet_multisig, const cryptonote::account_keys &account_keys)
{
	CHECK_AND_ASSERT_THROW_MES(is_wallet_multisig, "Wallet is not multisig");
	crypto::public_key signer;
	CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(account_keys.m_spend_secret_key, signer), "Failed to generate signer public key");
	return signer;
}
//
crypto::public_key monero_multisig_utils::get_multisig_signing_public_key(const crypto::secret_key &msk, bool is_wallet_multisig)
{
	CHECK_AND_ASSERT_THROW_MES(is_wallet_multisig, "Wallet is not multisig");
	crypto::public_key pkey;
	CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(msk, pkey), "Failed to derive public key");
	return pkey;
}
crypto::public_key monero_multisig_utils::get_multisig_signing_public_key(size_t idx, bool is_wallet_multisig, const std::vector<crypto::secret_key> &account_multisig_keys)
{
	CHECK_AND_ASSERT_THROW_MES(is_wallet_multisig, "Wallet is not multisig");
	CHECK_AND_ASSERT_THROW_MES(idx < account_multisig_keys.size(), "Multisig signing key index out of range");
	return get_multisig_signing_public_key(account_multisig_keys[idx], is_wallet_multisig);
}
//
rct::key monero_multisig_utils::get_multisig_k(size_t idx, const std::unordered_set<rct::key> &used_L, bool is_wallet_multisig, const std::vector<wallet2::transfer_details> &transfers)
{
	CHECK_AND_ASSERT_THROW_MES(is_wallet_multisig, "Wallet is not multisig");
	CHECK_AND_ASSERT_THROW_MES(idx < transfers.size(), "idx out of range");
	for (const auto &k: transfers[idx].m_multisig_k)
	{
		rct::key L;
		rct::scalarmultBase(L, k);
		if (used_L.find(L) != used_L.end())
			return k;
	}
	THROW_WALLET_EXCEPTION(tools::error::multisig_export_needed);
	return rct::zero();
}
//----------------------------------------------------------------------------------------------------
rct::multisig_kLRki monero_multisig_utils::get_multisig_kLRki(size_t n, const rct::key &k, const std::vector<wallet2::transfer_details> &transfers)
{
	CHECK_AND_ASSERT_THROW_MES(n < transfers.size(), "Bad transfers index");
	rct::multisig_kLRki kLRki;
	kLRki.k = k;
	cryptonote::generate_multisig_LR(transfers[n].get_public_key(), rct::rct2sk(kLRki.k), (crypto::public_key&)kLRki.L, (crypto::public_key&)kLRki.R);
	kLRki.ki = rct::ki2rct(transfers[n].m_key_image);
	return kLRki;
}
//----------------------------------------------------------------------------------------------------
rct::multisig_kLRki monero_multisig_utils::get_multisig_composite_kLRki(size_t n, const crypto::public_key &ignore, std::unordered_set<rct::key> &used_L, std::unordered_set<rct::key> &new_used_L, const std::vector<wallet2::transfer_details> &transfers, uint32_t multisig_threshold)
{
	CHECK_AND_ASSERT_THROW_MES(n < transfers.size(), "Bad transfer index");
	
	const wallet2::transfer_details &td = transfers[n]; // TODO/FIXME: can this be removed?
	rct::multisig_kLRki kLRki = get_multisig_kLRki(n, rct::skGen(), transfers);
	
	// pick a L/R pair from every other participant but one
	size_t n_signers_used = 1;
	for (const auto &p: transfers[n].m_multisig_info)
	{
		if (p.m_signer == ignore)
			continue;
		for (const auto &lr: p.m_LR)
		{
			if (used_L.find(lr.m_L) != used_L.end())
				continue;
			used_L.insert(lr.m_L);
			new_used_L.insert(lr.m_L);
			rct::addKeys(kLRki.L, kLRki.L, lr.m_L);
			rct::addKeys(kLRki.R, kLRki.R, lr.m_R);
			++n_signers_used;
			break;
		}
	}
	CHECK_AND_ASSERT_THROW_MES(n_signers_used >= multisig_threshold, "LR not found for enough participants");
	
	return kLRki;
}
//----------------------------------------------------------------------------------------------------
crypto::key_image monero_multisig_utils::get_multisig_composite_key_image(size_t n, const std::vector<wallet2::transfer_details> &transfers, const cryptonote::account_keys &account_keys, const std::unordered_map<crypto::public_key, cryptonote::subaddress_index> &subaddresses
) {
	CHECK_AND_ASSERT_THROW_MES(n < transfers.size(), "Bad output index");
	
	const wallet2::transfer_details &td = transfers[n];
	const crypto::public_key tx_key = monero_transfer_utils::get_tx_pub_key_from_received_outs(td, account_keys, subaddresses);
	const std::vector<crypto::public_key> additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(td.m_tx);
	crypto::key_image ki;
	std::vector<crypto::key_image> pkis;
	for (const auto &info: td.m_multisig_info)
		for (const auto &pki: info.m_partial_key_images)
			pkis.push_back(pki);
	bool r = cryptonote::generate_multisig_composite_key_image(account_keys, subaddresses, td.get_public_key(), tx_key, additional_tx_keys, td.m_internal_output_index, pkis, ki);
	THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
	return ki;
}

