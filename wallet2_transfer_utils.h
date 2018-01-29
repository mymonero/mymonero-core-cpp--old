// Copyright (c) 2014-2017, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <memory>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/deque.hpp>
#include <atomic>
//
#include "cryptonote_basic_impl.h"
#include "cryptonote_format_utils.h"
#include "cryptonote_tx_utils.h"
//
namespace tools
{

  struct tx_dust_policy
  {
    uint64_t dust_threshold;
    bool add_to_fee;
    cryptonote::account_public_address addr_for_dust;

    tx_dust_policy(uint64_t a_dust_threshold = 0, bool an_add_to_fee = true, cryptonote::account_public_address an_addr_for_dust = cryptonote::account_public_address())
      : dust_threshold(a_dust_threshold)
      , add_to_fee(an_add_to_fee)
      , addr_for_dust(an_addr_for_dust)
    {
    }
  };

  class wallet2
  {
  public:

    struct multisig_info
    {
      struct LR
      {
        rct::key m_L;
        rct::key m_R;

        BEGIN_SERIALIZE_OBJECT()
          FIELD(m_L)
          FIELD(m_R)
        END_SERIALIZE()
      };

      crypto::public_key m_signer;
      std::vector<LR> m_LR;
      std::vector<crypto::key_image> m_partial_key_images; // one per key the participant has

      BEGIN_SERIALIZE_OBJECT()
        FIELD(m_signer)
        FIELD(m_LR)
        FIELD(m_partial_key_images)
      END_SERIALIZE()
    };

    struct tx_scan_info_t
    {
      cryptonote::keypair in_ephemeral;
      crypto::key_image ki;
      rct::key mask;
      uint64_t amount;
      uint64_t money_transfered;
      bool error;
      boost::optional<cryptonote::subaddress_receive_info> received;

      tx_scan_info_t(): money_transfered(0), error(true) {}
    };

    struct transfer_details
    {
      uint64_t m_block_height;
      cryptonote::transaction_prefix m_tx;
      crypto::hash m_txid;
      size_t m_internal_output_index;
      uint64_t m_global_output_index;
      bool m_spent;
      uint64_t m_spent_height;
      crypto::key_image m_key_image; //TODO: key_image stored twice :(
      rct::key m_mask;
      uint64_t m_amount;
      bool m_rct;
      bool m_key_image_known;
      size_t m_pk_index;
      cryptonote::subaddress_index m_subaddr_index;
      bool m_key_image_partial;
      std::vector<rct::key> m_multisig_k;
      std::vector<multisig_info> m_multisig_info; // one per other participant

      bool is_rct() const { return m_rct; }
      uint64_t amount() const { return m_amount; }
      const crypto::public_key &get_public_key() const { return boost::get<const cryptonote::txout_to_key>(m_tx.vout[m_internal_output_index].target).key; }

      BEGIN_SERIALIZE_OBJECT()
        FIELD(m_block_height)
        FIELD(m_tx)
        FIELD(m_txid)
        FIELD(m_internal_output_index)
        FIELD(m_global_output_index)
        FIELD(m_spent)
        FIELD(m_spent_height)
        FIELD(m_key_image)
        FIELD(m_mask)
        FIELD(m_amount)
        FIELD(m_rct)
        FIELD(m_key_image_known)
        FIELD(m_pk_index)
        FIELD(m_subaddr_index)
        FIELD(m_key_image_partial)
        FIELD(m_multisig_k)
        FIELD(m_multisig_info)
      END_SERIALIZE()
    };

    struct payment_details
    {
      crypto::hash m_tx_hash;
      uint64_t m_amount;
	  uint64_t m_fee;
	  uint64_t m_block_height;
      uint64_t m_unlock_time;
      uint64_t m_timestamp;
      cryptonote::subaddress_index m_subaddr_index;
    };

	struct reserve_proof_entry
    {
      crypto::hash txid;
      uint64_t index_in_tx;
      crypto::public_key shared_secret;
      crypto::key_image key_image;
      crypto::signature shared_secret_sig;
      crypto::signature key_image_sig;
    };
	  
	  
	struct address_tx : payment_details
    {
      bool m_coinbase;
      bool m_mempool;
      bool m_incoming;
    };

    struct pool_payment_details
    {
      payment_details m_pd;
      bool m_double_spend_seen;
    };

    struct unconfirmed_transfer_details
    {
      cryptonote::transaction_prefix m_tx;
      uint64_t m_amount_in;
      uint64_t m_amount_out;
      uint64_t m_change;
      time_t m_sent_time;
      std::vector<cryptonote::tx_destination_entry> m_dests;
      crypto::hash m_payment_id;
      enum { pending, pending_not_in_pool, failed } m_state;
      uint64_t m_timestamp;
      uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
    };

    struct confirmed_transfer_details
    {
      uint64_t m_amount_in;
      uint64_t m_amount_out;
      uint64_t m_change;
      uint64_t m_block_height;
      std::vector<cryptonote::tx_destination_entry> m_dests;
      crypto::hash m_payment_id;
      uint64_t m_timestamp;
      uint64_t m_unlock_time;
      uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer

      confirmed_transfer_details(): m_amount_in(0), m_amount_out(0), m_change((uint64_t)-1), m_block_height(0), m_payment_id(crypto::null_hash), m_timestamp(0), m_unlock_time(0), m_subaddr_account((uint32_t)-1) {}
      confirmed_transfer_details(const unconfirmed_transfer_details &utd, uint64_t height):
        m_amount_in(utd.m_amount_in), m_amount_out(utd.m_amount_out), m_change(utd.m_change), m_block_height(height), m_dests(utd.m_dests), m_payment_id(utd.m_payment_id), m_timestamp(utd.m_timestamp), m_unlock_time(utd.m_tx.unlock_time), m_subaddr_account(utd.m_subaddr_account), m_subaddr_indices(utd.m_subaddr_indices) {}
    };

    struct tx_construction_data
    {
      std::vector<cryptonote::tx_source_entry> sources;
      cryptonote::tx_destination_entry change_dts;
      std::vector<cryptonote::tx_destination_entry> splitted_dsts; // split, includes change
      std::vector<size_t> selected_transfers;
      std::vector<uint8_t> extra;
      uint64_t unlock_time;
      bool use_rct;
      std::vector<cryptonote::tx_destination_entry> dests; // original setup, does not include change
      uint32_t subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> subaddr_indices;  // set of address indices used as inputs in this transfer

      BEGIN_SERIALIZE_OBJECT()
        FIELD(sources)
        FIELD(change_dts)
        FIELD(splitted_dsts)
        FIELD(selected_transfers)
        FIELD(extra)
        FIELD(unlock_time)
        FIELD(use_rct)
        FIELD(dests)
        FIELD(subaddr_account)
        FIELD(subaddr_indices)
      END_SERIALIZE()
    };

    typedef std::vector<transfer_details> transfer_container;
    typedef std::unordered_multimap<crypto::hash, payment_details> payment_container;

    struct multisig_sig
    {
      rct::rctSig sigs;
      crypto::public_key ignore;
      std::unordered_set<rct::key> used_L;
      std::unordered_set<crypto::public_key> signing_keys;
      rct::multisig_out msout;
    };

    // The convention for destinations is:
    // dests does not include change
    // splitted_dsts (in construction_data) does
    struct pending_tx
    {
      cryptonote::transaction tx;
      uint64_t dust, fee;
      bool dust_added_to_fee;
      cryptonote::tx_destination_entry change_dts;
      std::vector<size_t> selected_transfers;
      std::string key_images;
      crypto::secret_key tx_key;
      std::vector<crypto::secret_key> additional_tx_keys;
      std::vector<cryptonote::tx_destination_entry> dests;
      std::vector<multisig_sig> multisig_sigs;

      tx_construction_data construction_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(tx)
        FIELD(dust)
        FIELD(fee)
        FIELD(dust_added_to_fee)
        FIELD(change_dts)
        FIELD(selected_transfers)
        FIELD(key_images)
        FIELD(tx_key)
        FIELD(additional_tx_keys)
        FIELD(dests)
        FIELD(construction_data)
        FIELD(multisig_sigs)
      END_SERIALIZE()
    };

    // The term "Unsigned tx" is not really a tx since it's not signed yet.
    // It doesnt have tx hash, key and the integrated address is not separated into addr + payment id.
    struct unsigned_tx_set
    {
      std::vector<tx_construction_data> txes;
      wallet2::transfer_container transfers;
    };

    struct signed_tx_set
    {
      std::vector<pending_tx> ptx;
      std::vector<crypto::key_image> key_images;
    };

    struct multisig_tx_set
    {
      std::vector<pending_tx> m_ptx;
      std::unordered_set<crypto::public_key> m_signers;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(m_ptx)
        FIELD(m_signers)
      END_SERIALIZE()
    };

	  
    typedef std::tuple<uint64_t, crypto::public_key, rct::key> get_outs_entry;

  };
}
BOOST_CLASS_VERSION(tools::wallet2, 22)
BOOST_CLASS_VERSION(tools::wallet2::transfer_details, 9)
BOOST_CLASS_VERSION(tools::wallet2::multisig_info, 1)
BOOST_CLASS_VERSION(tools::wallet2::multisig_info::LR, 0)
BOOST_CLASS_VERSION(tools::wallet2::multisig_tx_set, 1)
BOOST_CLASS_VERSION(tools::wallet2::payment_details, 2)
BOOST_CLASS_VERSION(tools::wallet2::pool_payment_details, 1)
BOOST_CLASS_VERSION(tools::wallet2::unconfirmed_transfer_details, 7)
BOOST_CLASS_VERSION(tools::wallet2::confirmed_transfer_details, 5)
//BOOST_CLASS_VERSION(tools::wallet2::address_book_row, 17)
BOOST_CLASS_VERSION(tools::wallet2::unsigned_tx_set, 0)
BOOST_CLASS_VERSION(tools::wallet2::signed_tx_set, 0)
BOOST_CLASS_VERSION(tools::wallet2::tx_construction_data, 2)
BOOST_CLASS_VERSION(tools::wallet2::pending_tx, 3)
BOOST_CLASS_VERSION(tools::wallet2::multisig_sig, 0)

//namespace boost
//{
//  namespace serialization
//  {
//    template <class Archive>
//    inline typename std::enable_if<!Archive::is_loading::value, void>::type initialize_transfer_details(Archive &a, tools::wallet2::transfer_details &x, const boost::serialization::version_type ver)
//    {
//    }
//    template <class Archive>
//    inline typename std::enable_if<Archive::is_loading::value, void>::type initialize_transfer_details(Archive &a, tools::wallet2::transfer_details &x, const boost::serialization::version_type ver)
//    {
//        if (ver < 1)
//        {
//          x.m_mask = rct::identity();
//          x.m_amount = x.m_tx.vout[x.m_internal_output_index].amount;
//        }
//        if (ver < 2)
//        {
//          x.m_spent_height = 0;
//        }
//        if (ver < 4)
//        {
//          x.m_rct = x.m_tx.vout[x.m_internal_output_index].amount == 0;
//        }
//        if (ver < 6)
//        {
//          x.m_key_image_known = true;
//        }
//        if (ver < 7)
//        {
//          x.m_pk_index = 0;
//        }
//        if (ver < 8)
//        {
//          x.m_subaddr_index = {};
//        }
//        if (ver < 9)
//        {
//          x.m_key_image_partial = false;
//          x.m_multisig_k.clear();
//          x.m_multisig_info.clear();
//        }
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::transfer_details &x, const boost::serialization::version_type ver)
//    {
//      a & x.m_block_height;
//      a & x.m_global_output_index;
//      a & x.m_internal_output_index;
//      if (ver < 3)
//      {
//        cryptonote::transaction tx;
//        a & tx;
//        x.m_tx = (const cryptonote::transaction_prefix&)tx;
//        x.m_txid = cryptonote::get_transaction_hash(tx);
//      }
//      else
//      {
//        a & x.m_tx;
//      }
//      a & x.m_spent;
//      a & x.m_key_image;
//      if (ver < 1)
//      {
//        // ensure mask and amount are set
//        initialize_transfer_details(a, x, ver);
//        return;
//      }
//      a & x.m_mask;
//      a & x.m_amount;
//      if (ver < 2)
//      {
//        initialize_transfer_details(a, x, ver);
//        return;
//      }
//      a & x.m_spent_height;
//      if (ver < 3)
//      {
//        initialize_transfer_details(a, x, ver);
//        return;
//      }
//      a & x.m_txid;
//      if (ver < 4)
//      {
//        initialize_transfer_details(a, x, ver);
//        return;
//      }
//      a & x.m_rct;
//      if (ver < 5)
//      {
//        initialize_transfer_details(a, x, ver);
//        return;
//      }
//      if (ver < 6)
//      {
//        // v5 did not properly initialize
//        uint8_t u;
//        a & u;
//        x.m_key_image_known = true;
//        return;
//      }
//      a & x.m_key_image_known;
//      if (ver < 7)
//      {
//        initialize_transfer_details(a, x, ver);
//        return;
//      }
//      a & x.m_pk_index;
//      if (ver < 8)
//      {
//        initialize_transfer_details(a, x, ver);
//        return;
//      }
//      a & x.m_subaddr_index;
//      if (ver < 9)
//      {
//        initialize_transfer_details(a, x, ver);
//        return;
//      }
//      a & x.m_multisig_info;
//      a & x.m_multisig_k;
//      a & x.m_key_image_partial;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::multisig_info::LR &x, const boost::serialization::version_type ver)
//    {
//      a & x.m_L;
//      a & x.m_R;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::multisig_info &x, const boost::serialization::version_type ver)
//    {
//      a & x.m_signer;
//      a & x.m_LR;
//      a & x.m_partial_key_images;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::multisig_tx_set &x, const boost::serialization::version_type ver)
//    {
//      a & x.m_ptx;
//      a & x.m_signers;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::unconfirmed_transfer_details &x, const boost::serialization::version_type ver)
//    {
//      a & x.m_change;
//      a & x.m_sent_time;
//      if (ver < 5)
//      {
//        cryptonote::transaction tx;
//        a & tx;
//        x.m_tx = (const cryptonote::transaction_prefix&)tx;
//      }
//      else
//      {
//        a & x.m_tx;
//      }
//      if (ver < 1)
//        return;
//      a & x.m_dests;
//      a & x.m_payment_id;
//      if (ver < 2)
//        return;
//      a & x.m_state;
//      if (ver < 3)
//        return;
//      a & x.m_timestamp;
//      if (ver < 4)
//        return;
//      a & x.m_amount_in;
//      a & x.m_amount_out;
//      if (ver < 6)
//      {
//        // v<6 may not have change accumulated in m_amount_out, which is a pain,
//        // as it's readily understood to be sum of outputs.
//        // We convert it to include change from v6
//        if (!typename Archive::is_saving() && x.m_change != (uint64_t)-1)
//          x.m_amount_out += x.m_change;
//      }
//      if (ver < 7)
//      {
//        x.m_subaddr_account = 0;
//        return;
//      }
//      a & x.m_subaddr_account;
//      a & x.m_subaddr_indices;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::confirmed_transfer_details &x, const boost::serialization::version_type ver)
//    {
//      a & x.m_amount_in;
//      a & x.m_amount_out;
//      a & x.m_change;
//      a & x.m_block_height;
//      if (ver < 1)
//        return;
//      a & x.m_dests;
//      a & x.m_payment_id;
//      if (ver < 2)
//        return;
//      a & x.m_timestamp;
//      if (ver < 3)
//      {
//        // v<3 may not have change accumulated in m_amount_out, which is a pain,
//        // as it's readily understood to be sum of outputs. Whether it got added
//        // or not depends on whether it came from a unconfirmed_transfer_details
//        // (not included) or not (included). We can't reliably tell here, so we
//        // check whether either yields a "negative" fee, or use the other if so.
//        // We convert it to include change from v3
//        if (!typename Archive::is_saving() && x.m_change != (uint64_t)-1)
//        {
//          if (x.m_amount_in > (x.m_amount_out + x.m_change))
//            x.m_amount_out += x.m_change;
//        }
//      }
//      if (ver < 4)
//      {
//        if (!typename Archive::is_saving())
//          x.m_unlock_time = 0;
//        return;
//      }
//      a & x.m_unlock_time;
//      if (ver < 5)
//      {
//        x.m_subaddr_account = 0;
//        return;
//      }
//      a & x.m_subaddr_account;
//      a & x.m_subaddr_indices;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive& a, tools::wallet2::payment_details& x, const boost::serialization::version_type ver)
//    {
//      a & x.m_tx_hash;
//      a & x.m_amount;
//      a & x.m_block_height;
//      a & x.m_unlock_time;
//      if (ver < 1)
//        return;
//      a & x.m_timestamp;
//      if (ver < 2)
//      {
//        x.m_subaddr_index = {};
//        return;
//      }
//      a & x.m_subaddr_index;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive& a, tools::wallet2::pool_payment_details& x, const boost::serialization::version_type ver)
//    {
//      a & x.m_pd;
//      a & x.m_double_spend_seen;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive& a, tools::wallet2::address_book_row& x, const boost::serialization::version_type ver)
//    {
//      a & x.m_address;
//      a & x.m_payment_id;
//      a & x.m_description;
//      if (ver < 17)
//      {
//        x.m_is_subaddress = false;
//        return;
//      }
//      a & x.m_is_subaddress;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::unsigned_tx_set &x, const boost::serialization::version_type ver)
//    {
//      a & x.txes;
//      a & x.transfers;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::signed_tx_set &x, const boost::serialization::version_type ver)
//    {
//      a & x.ptx;
//      a & x.key_images;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::tx_construction_data &x, const boost::serialization::version_type ver)
//    {
//      a & x.sources;
//      a & x.change_dts;
//      a & x.splitted_dsts;
//      if (ver < 2)
//      {
//        // load list to vector
//        std::list<size_t> selected_transfers;
//        a & selected_transfers;
//        x.selected_transfers.clear();
//        x.selected_transfers.reserve(selected_transfers.size());
//        for (size_t t: selected_transfers)
//          x.selected_transfers.push_back(t);
//      }
//      a & x.extra;
//      a & x.unlock_time;
//      a & x.use_rct;
//      a & x.dests;
//      if (ver < 1)
//      {
//        x.subaddr_account = 0;
//        return;
//      }
//      a & x.subaddr_account;
//      a & x.subaddr_indices;
//      if (ver < 2)
//        return;
//      a & x.selected_transfers;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::multisig_sig &x, const boost::serialization::version_type ver)
//    {
//      a & x.sigs;
//      a & x.ignore;
//      a & x.used_L;
//      a & x.signing_keys;
//      a & x.msout;
//    }
//
//    template <class Archive>
//    inline void serialize(Archive &a, tools::wallet2::pending_tx &x, const boost::serialization::version_type ver)
//    {
//      a & x.tx;
//      a & x.dust;
//      a & x.fee;
//      a & x.dust_added_to_fee;
//      a & x.change_dts;
//      if (ver < 2)
//      {
//        // load list to vector
//        std::list<size_t> selected_transfers;
//        a & selected_transfers;
//        x.selected_transfers.clear();
//        x.selected_transfers.reserve(selected_transfers.size());
//        for (size_t t: selected_transfers)
//          x.selected_transfers.push_back(t);
//      }
//      a & x.key_images;
//      a & x.tx_key;
//      a & x.dests;
//      a & x.construction_data;
//      if (ver < 1)
//        return;
//      a & x.additional_tx_keys;
//      if (ver < 2)
//        return;
//      a & x.selected_transfers;
//      if (ver < 3)
//        return;
//      a & x.multisig_sigs;
//    }
//  }
//}

namespace tools
{

  namespace detail
  {
    //----------------------------------------------------------------------------------------------------
    inline void digit_split_strategy(const std::vector<cryptonote::tx_destination_entry>& dsts,
      const cryptonote::tx_destination_entry& change_dst, uint64_t dust_threshold,
      std::vector<cryptonote::tx_destination_entry>& splitted_dsts, std::vector<cryptonote::tx_destination_entry> &dust_dsts)
    {
      splitted_dsts.clear();
      dust_dsts.clear();

      for(auto& de: dsts)
      {
        cryptonote::decompose_amount_into_digits(de.amount, 0,
          [&](uint64_t chunk) { splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, de.addr, de.is_subaddress)); },
          [&](uint64_t a_dust) { splitted_dsts.push_back(cryptonote::tx_destination_entry(a_dust, de.addr, de.is_subaddress)); } );
      }

      cryptonote::decompose_amount_into_digits(change_dst.amount, 0,
        [&](uint64_t chunk) {
          if (chunk <= dust_threshold)
            dust_dsts.push_back(cryptonote::tx_destination_entry(chunk, change_dst.addr, false));
          else
            splitted_dsts.push_back(cryptonote::tx_destination_entry(chunk, change_dst.addr, false));
        },
        [&](uint64_t a_dust) { dust_dsts.push_back(cryptonote::tx_destination_entry(a_dust, change_dst.addr, false)); } );
    }
    //----------------------------------------------------------------------------------------------------
    inline void null_split_strategy(const std::vector<cryptonote::tx_destination_entry>& dsts,
      const cryptonote::tx_destination_entry& change_dst, uint64_t dust_threshold,
      std::vector<cryptonote::tx_destination_entry>& splitted_dsts, std::vector<cryptonote::tx_destination_entry> &dust_dsts)
    {
      splitted_dsts = dsts;

      dust_dsts.clear();
      uint64_t change = change_dst.amount;

      if (0 != change)
      {
        splitted_dsts.push_back(cryptonote::tx_destination_entry(change, change_dst.addr, false));
      }
    }
    //----------------------------------------------------------------------------------------------------
    inline void print_source_entry(const cryptonote::tx_source_entry& src)
    {
      std::string indexes;
      std::for_each(src.outputs.begin(), src.outputs.end(), [&](const cryptonote::tx_source_entry::output_entry& s_e) { indexes += boost::to_string(s_e.first) + " "; });
      LOG_PRINT_L0("amount=" << cryptonote::print_money(src.amount) << ", real_output=" <<src.real_output << ", real_output_in_tx_index=" << src.real_output_in_tx_index << ", indexes: " << indexes);
    }
    //----------------------------------------------------------------------------------------------------
  }

}
