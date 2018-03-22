// Copyright (c) 2014-2018, The Monero Project
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

#include <numeric>
#include <random>
#include <tuple>
#include <boost/format.hpp>
#include <boost/optional/optional.hpp>
#include <boost/utility/value_init.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/split.hpp>
#include "include_base_utils.h"
using namespace epee;

#include "cryptonote_config.h"
#include "wallet2-BORROWED.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "misc_language.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "multisig/multisig.h"
#include "common/boost_serialization_helper.h"
#include "common/command_line.h"
#include "common/threadpool.h"
#include "profile_tools.h"
#include "crypto/crypto.h"
#include "serialization/binary_utils.h"
#include "serialization/string.h"
#include "cryptonote_basic/blobdatatype.h"
#include "mnemonics/electrum-words.h"
#include "common/i18n.h"
#include "common/util.h"
#include "common/apply_permutation.h"
//#include "rapidjson/document.h"
//#include "rapidjson/writer.h"
//#include "rapidjson/stringbuffer.h"
#include "common/json_util.h"
#include "memwipe.h"
#include "common/base58.h"
#include "common/dns_utils.h"
#include "ringct/rctSigs.h"

extern "C"
{
#include "crypto/keccak.h"
#include "crypto/crypto-ops.h"
}
using namespace std;
using namespace crypto;
using namespace cryptonote;

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "wallet.wallet2"

// used to choose when to stop adding outputs to a tx
#define APPROXIMATE_INPUT_BYTES 80

// used to target a given block size (additional outputs may be added on top to build fee)
#define TX_SIZE_TARGET(bytes) (bytes*2/3)

// arbitrary, used to generate different hashes from the same input
#define CHACHA8_KEY_TAIL 0x8c

#define UNSIGNED_TX_PREFIX "Monero unsigned tx set\004"
#define SIGNED_TX_PREFIX "Monero signed tx set\004"
#define MULTISIG_UNSIGNED_TX_PREFIX "Monero multisig unsigned tx set\001"

#define RECENT_OUTPUT_RATIO (0.5) // 50% of outputs are from the recent zone
#define RECENT_OUTPUT_DAYS (1.8) // last 1.8 day makes up the recent zone (taken from monerolink.pdf, Miller et al)
#define RECENT_OUTPUT_ZONE ((time_t)(RECENT_OUTPUT_DAYS * 86400))
#define RECENT_OUTPUT_BLOCKS (RECENT_OUTPUT_DAYS * 720)

#define FEE_ESTIMATE_GRACE_BLOCKS 10 // estimate fee valid for that many blocks

#define SECOND_OUTPUT_RELATEDNESS_THRESHOLD 0.0f

#define SUBADDRESS_LOOKAHEAD_MAJOR 50
#define SUBADDRESS_LOOKAHEAD_MINOR 200

#define KEY_IMAGE_EXPORT_FILE_MAGIC "Monero key image export\002"

#define MULTISIG_EXPORT_FILE_MAGIC "Monero multisig export\001"

#define SEGREGATION_FORK_HEIGHT 1564965
#define TESTNET_SEGREGATION_FORK_HEIGHT 1000000
#define STAGENET_SEGREGATION_FORK_HEIGHT 1000000
#define SEGREGATION_FORK_VICINITY 1500 /* blocks */



namespace
{
// Create on-demand to prevent static initialization order fiasco issues.
struct options {
  const command_line::arg_descriptor<std::string> daemon_address = {"daemon-address", tools::wallet2::tr("Use daemon instance at <host>:<port>"), ""};
  const command_line::arg_descriptor<std::string> daemon_host = {"daemon-host", tools::wallet2::tr("Use daemon instance at host <arg> instead of localhost"), ""};
  const command_line::arg_descriptor<std::string> password = {"password", tools::wallet2::tr("Wallet password (escape/quote as needed)"), "", true};
  const command_line::arg_descriptor<std::string> password_file = {"password-file", tools::wallet2::tr("Wallet password file"), "", true};
  const command_line::arg_descriptor<int> daemon_port = {"daemon-port", tools::wallet2::tr("Use daemon instance at port <arg> instead of 18081"), 0};
  const command_line::arg_descriptor<std::string> daemon_login = {"daemon-login", tools::wallet2::tr("Specify username[:password] for daemon RPC client"), "", true};
  const command_line::arg_descriptor<bool> testnet = {"testnet", tools::wallet2::tr("For testnet. Daemon must also be launched with --testnet flag"), false};
  const command_line::arg_descriptor<bool> stagenet = {"stagenet", tools::wallet2::tr("For stagenet. Daemon must also be launched with --stagenet flag"), false};
  const command_line::arg_descriptor<bool> restricted = {"restricted-rpc", tools::wallet2::tr("Restricts to view-only commands"), false};
};

void do_prepare_file_names(const std::string& file_path, std::string& keys_file, std::string& wallet_file)
{
  keys_file = file_path;
  wallet_file = file_path;
  boost::system::error_code e;
  if(string_tools::get_extension(keys_file) == "keys")
  {//provided keys file name
    wallet_file = string_tools::cut_off_extension(wallet_file);
  }else
  {//provided wallet file name
    keys_file += ".keys";
  }
}

uint64_t calculate_fee(uint64_t fee_per_kb, size_t bytes, uint64_t fee_multiplier)
{
  uint64_t kB = (bytes + 1023) / 1024;
  return kB * fee_per_kb * fee_multiplier;
}

uint64_t calculate_fee(uint64_t fee_per_kb, const cryptonote::blobdata &blob, uint64_t fee_multiplier)
{
  return calculate_fee(fee_per_kb, blob.size(), fee_multiplier);
}

std::string get_size_string(size_t sz)
{
  return std::to_string(sz) + " bytes (" + std::to_string((sz + 1023) / 1024) + " kB)";
}

std::string get_size_string(const cryptonote::blobdata &tx)
{
  return get_size_string(tx.size());
}

static void throw_on_rpc_response_error(const boost::optional<std::string> &status, const char *method)
{
  // no error
  if (!status)
    return;

  // empty string -> not connection
  THROW_WALLET_EXCEPTION_IF(status->empty(), tools::error::no_connection_to_daemon, method);

  THROW_WALLET_EXCEPTION_IF(*status == CORE_RPC_STATUS_BUSY, tools::error::daemon_busy, method);
  THROW_WALLET_EXCEPTION_IF(*status != CORE_RPC_STATUS_OK, tools::error::wallet_generic_rpc_error, method, *status);
}

std::string strjoin(const std::vector<size_t> &V, const char *sep)
{
  std::stringstream ss;
  bool first = true;
  for (const auto &v: V)
  {
    if (!first)
      ss << sep;
    ss << std::to_string(v);
    first = false;
  }
  return ss.str();
}

static void emplace_or_replace(std::unordered_multimap<crypto::hash, tools::wallet2::pool_payment_details> &container,
  const crypto::hash &key, const tools::wallet2::pool_payment_details &pd)
{
  auto range = container.equal_range(key);
  for (auto i = range.first; i != range.second; ++i)
  {
    if (i->second.m_pd.m_tx_hash == pd.m_pd.m_tx_hash && i->second.m_pd.m_subaddr_index == pd.m_pd.m_subaddr_index)
    {
      i->second = pd;
      return;
    }
  }
  container.emplace(key, pd);
}

void drop_from_short_history(std::list<crypto::hash> &short_chain_history, size_t N)
{
  std::list<crypto::hash>::iterator right;
  // drop early N off, skipping the genesis block
  if (short_chain_history.size() > N) {
    right = short_chain_history.end();
    std::advance(right,-1);
    std::list<crypto::hash>::iterator left = right;
    std::advance(left, -N);
    short_chain_history.erase(left, right);
  }
}

size_t estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof)
{
  size_t size = 0;

  // tx prefix

  // first few bytes
  size += 1 + 6;

  // vin
  size += n_inputs * (1+6+(mixin+1)*2+32);

  // vout
  size += n_outputs * (6+32);

  // extra
  size += extra_size;

  // rct signatures

  // type
  size += 1;

  // rangeSigs
  if (bulletproof)
    size += ((2*6 + 4 + 5)*32 + 3) * n_outputs;
  else
    size += (2*64*32+32+64*32) * n_outputs;

  // MGs
  size += n_inputs * (64 * (mixin+1) + 32);

  // mixRing - not serialized, can be reconstructed
  /* size += 2 * 32 * (mixin+1) * n_inputs; */

  // pseudoOuts
  size += 32 * n_inputs;
  // ecdhInfo
  size += 2 * 32 * n_outputs;
  // outPk - only commitment is saved
  size += 32 * n_outputs;
  // txnFee
  size += 4;

  LOG_PRINT_L2("estimated rct tx size for " << n_inputs << " with ring size " << (mixin+1) << " and " << n_outputs << ": " << size << " (" << ((32 * n_inputs/*+1*/) + 2 * 32 * (mixin+1) * n_inputs + 32 * n_outputs) << " saved)");
  return size;
}

size_t estimate_tx_size(bool use_rct, int n_inputs, int mixin, int n_outputs, size_t extra_size, bool bulletproof)
{
  if (use_rct)
    return estimate_rct_tx_size(n_inputs, mixin, n_outputs + 1, extra_size, bulletproof);
  else
    return n_inputs * (mixin+1) * APPROXIMATE_INPUT_BYTES + extra_size;
}

uint8_t get_bulletproof_fork()
{
  return 8;
}

crypto::hash8 get_short_payment_id(const tools::wallet2::pending_tx &ptx, hw::device &hwdev)
{
  crypto::hash8 payment_id8 = null_hash8;
  std::vector<tx_extra_field> tx_extra_fields;
  parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
  cryptonote::tx_extra_nonce extra_nonce;
  if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
  {
    if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
    {
      if (ptx.dests.empty())
      {
        MWARNING("Encrypted payment id found, but no destinations public key, cannot decrypt");
        return crypto::null_hash8;
      }
      hwdev.decrypt_payment_id(payment_id8, ptx.dests[0].addr.m_view_public_key, ptx.tx_key);
    }
  }
  return payment_id8;
}

tools::wallet2::tx_construction_data get_construction_data_with_decrypted_short_payment_id(const tools::wallet2::pending_tx &ptx, hw::device &hwdev)
{
  tools::wallet2::tx_construction_data construction_data = ptx.construction_data;
  crypto::hash8 payment_id = get_short_payment_id(ptx,hwdev);
  if (payment_id != null_hash8)
  {
    // Remove encrypted
    remove_field_from_tx_extra(construction_data.extra, typeid(cryptonote::tx_extra_nonce));
    // Add decrypted
    std::string extra_nonce;
    set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, payment_id);
    THROW_WALLET_EXCEPTION_IF(!add_extra_nonce_to_tx_extra(construction_data.extra, extra_nonce),
        tools::error::wallet_internal_error, "Failed to add decrypted payment id to tx extra");
    LOG_PRINT_L1("Decrypted payment ID: " << payment_id);
  }
  return construction_data;
}

uint32_t get_subaddress_clamped_sum(uint32_t idx, uint32_t extra)
{
  static constexpr uint32_t uint32_max = std::numeric_limits<uint32_t>::max();
  if (idx > uint32_max - extra)
    return uint32_max;
  return idx + extra;
}

  //-----------------------------------------------------------------
} //namespace

namespace tools
{
// for now, limit to 30 attempts.  TODO: discuss a good number to limit to.
const size_t MAX_SPLIT_ATTEMPTS = 30;

constexpr const std::chrono::seconds wallet2::rpc_timeout;
const char* wallet2::tr(const char* str) { return i18n_translate(str, "tools::wallet2"); }

wallet2::wallet2(network_type nettype, bool restricted):
  m_multisig_rescan_info(NULL),
  m_multisig_rescan_k(NULL),
  m_run(true),
  m_callback(0),
  m_nettype(nettype),
  m_always_confirm_transfers(true),
  m_print_ring_members(false),
  m_store_tx_info(true),
  m_default_mixin(0),
  m_default_priority(0),
  m_auto_refresh(true),
  m_refresh_from_block_height(0),
  m_explicit_refresh_from_block_height(true),
  m_confirm_missing_payment_id(true),
  m_ask_password(true),
  m_min_output_count(0),
  m_min_output_value(0),
  m_merge_destinations(false),
  m_confirm_backlog(true),
  m_confirm_backlog_threshold(0),
  m_confirm_export_overwrite(true),
  m_auto_low_priority(true),
  m_segregate_pre_fork_outputs(true),
  m_key_reuse_mitigation2(true),
  m_segregation_height(0),
  m_is_initialized(false),
  m_restricted(restricted),
  is_old_file_format(false),
//  m_node_rpc_proxy(m_http_client, m_daemon_rpc_mutex),
  m_subaddress_lookahead_major(SUBADDRESS_LOOKAHEAD_MAJOR),
  m_subaddress_lookahead_minor(SUBADDRESS_LOOKAHEAD_MINOR),
  m_light_wallet(false),
  m_light_wallet_scanned_block_height(0),
  m_light_wallet_blockchain_height(0),
  m_light_wallet_connected(false),
  m_light_wallet_balance(0),
  m_light_wallet_unlocked_balance(0),
  m_key_on_device(false),
  m_ring_history_saved(false)
{
}

wallet2::~wallet2()
{
}

bool wallet2::has_testnet_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().testnet);
}

bool wallet2::has_stagenet_option(const boost::program_options::variables_map& vm)
{
  return command_line::get_arg(vm, options().stagenet);
}

//----------------------------------------------------------------------------------------------------
bool wallet2::is_deterministic() const
{
  crypto::secret_key second;
  keccak((uint8_t *)&get_account().get_keys().m_spend_secret_key, sizeof(crypto::secret_key), (uint8_t *)&second, sizeof(crypto::secret_key));
  sc_reduce32((uint8_t *)&second);
  bool keys_deterministic = memcmp(second.data,get_account().get_keys().m_view_secret_key.data, sizeof(crypto::secret_key)) == 0;
  return keys_deterministic;
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Gets the seed language
 */
const std::string &wallet2::get_seed_language() const
{
  return seed_language;
}
/*!
 * \brief Sets the seed language
 * \param language  Seed language to set to
 */
void wallet2::set_seed_language(const std::string &language)
{
  seed_language = language;
}
//----------------------------------------------------------------------------------------------------
cryptonote::account_public_address wallet2::get_subaddress(const cryptonote::subaddress_index& index) const
{
  hw::device &hwdev = m_account.get_device();
  return hwdev.get_subaddress(m_account.get_keys(), index);
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const
{
  hw::device &hwdev = m_account.get_device();
  return hwdev.get_subaddress_spend_public_key(m_account.get_keys(), index);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_subaddress_as_str(const cryptonote::subaddress_index& index) const
{
  cryptonote::account_public_address address = get_subaddress(index);
  return cryptonote::get_account_address_as_str(m_nettype, !index.is_zero(), address);
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_integrated_address_as_str(const crypto::hash8& payment_id) const
{
  return cryptonote::get_account_integrated_address_as_str(m_nettype, get_address(), payment_id);
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_subaddress_account(const std::string& label)
{
  uint32_t index_major = (uint32_t)get_num_subaddress_accounts();
  expand_subaddresses({index_major, 0});
  m_subaddress_labels[index_major][0] = label;
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_subaddress(uint32_t index_major, const std::string& label)
{
  THROW_WALLET_EXCEPTION_IF(index_major >= m_subaddress_labels.size(), error::account_index_outofbound);
  uint32_t index_minor = (uint32_t)get_num_subaddresses(index_major);
  expand_subaddresses({index_major, index_minor});
  m_subaddress_labels[index_major][index_minor] = label;
}
//----------------------------------------------------------------------------------------------------
void wallet2::expand_subaddresses(const cryptonote::subaddress_index& index)
{
  hw::device &hwdev = m_account.get_device();
  if (m_subaddress_labels.size() <= index.major)
  {
    // add new accounts
    cryptonote::subaddress_index index2;
    const uint32_t major_end = get_subaddress_clamped_sum(index.major, m_subaddress_lookahead_major);
    for (index2.major = m_subaddress_labels.size(); index2.major < major_end; ++index2.major)
    {
      const uint32_t end = get_subaddress_clamped_sum((index2.major == index.major ? index.minor : 0), m_subaddress_lookahead_minor);
      const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(m_account.get_keys(), index2.major, 0, end);
      for (index2.minor = 0; index2.minor < end; ++index2.minor)
      {
         const crypto::public_key &D = pkeys[index2.minor];
         m_subaddresses[D] = index2;
      }
    }
    m_subaddress_labels.resize(index.major + 1, {"Untitled account"});
    m_subaddress_labels[index.major].resize(index.minor + 1);
  }
  else if (m_subaddress_labels[index.major].size() <= index.minor)
  {
    // add new subaddresses
    const uint32_t end = get_subaddress_clamped_sum(index.minor, m_subaddress_lookahead_minor);
    const uint32_t begin = m_subaddress_labels[index.major].size();
    cryptonote::subaddress_index index2 = {index.major, begin};
    const std::vector<crypto::public_key> pkeys = hwdev.get_subaddress_spend_public_keys(m_account.get_keys(), index2.major, index2.minor, end);
    for (; index2.minor < end; ++index2.minor)
    {
       const crypto::public_key &D = pkeys[index2.minor - begin];
       m_subaddresses[D] = index2;
    }
    m_subaddress_labels[index.major].resize(index.minor + 1);
  }
}
//----------------------------------------------------------------------------------------------------
std::string wallet2::get_subaddress_label(const cryptonote::subaddress_index& index) const
{
  if (index.major >= m_subaddress_labels.size() || index.minor >= m_subaddress_labels[index.major].size())
  {
    MERROR("Subaddress label doesn't exist");
    return "";
  }
  return m_subaddress_labels[index.major][index.minor];
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_subaddress_label(const cryptonote::subaddress_index& index, const std::string &label)
{
  THROW_WALLET_EXCEPTION_IF(index.major >= m_subaddress_labels.size(), error::account_index_outofbound);
  THROW_WALLET_EXCEPTION_IF(index.minor >= m_subaddress_labels[index.major].size(), error::address_index_outofbound);
  m_subaddress_labels[index.major][index.minor] = label;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_subaddress_lookahead(size_t major, size_t minor)
{
  THROW_WALLET_EXCEPTION_IF(major > 0xffffffff, error::wallet_internal_error, "Subaddress major lookahead is too large");
  THROW_WALLET_EXCEPTION_IF(minor > 0xffffffff, error::wallet_internal_error, "Subaddress minor lookahead is too large");
  m_subaddress_lookahead_major = major;
  m_subaddress_lookahead_minor = minor;
}
//----------------------------------------------------------------------------------------------------
/*!
 * \brief Tells if the wallet file is deprecated.
 */
bool wallet2::is_deprecated() const
{
  return is_old_file_format;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_spent(size_t idx, uint64_t height)
{
  transfer_details &td = m_transfers[idx];
  LOG_PRINT_L2("Setting SPENT at " << height << ": ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = true;
  td.m_spent_height = height;
}
//----------------------------------------------------------------------------------------------------
void wallet2::set_unspent(size_t idx)
{
  transfer_details &td = m_transfers[idx];
  LOG_PRINT_L2("Setting UNSPENT: ki " << td.m_key_image << ", amount " << print_money(td.m_amount));
  td.m_spent = false;
  td.m_spent_height = 0;
}
//----------------------------------------------------------------------------------------------------
void wallet2::check_acc_out_precomp(const tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, tx_scan_info_t &tx_scan_info) const
{
  if (o.target.type() !=  typeid(txout_to_key))
  {
     tx_scan_info.error = true;
     LOG_ERROR("wrong type id in transaction out");
     return;
  }
  tx_scan_info.received = is_out_to_acc_precomp(m_subaddresses, boost::get<txout_to_key>(o.target).key, derivation, additional_derivations, i, m_account.get_device());
  if(tx_scan_info.received)
  {
    tx_scan_info.money_transfered = o.amount; // may be 0 for ringct outputs
  }
  else
  {
    tx_scan_info.money_transfered = 0;
  }
  tx_scan_info.error = false;
}
//----------------------------------------------------------------------------------------------------
static uint64_t decodeRct(const rct::rctSig & rv, const crypto::key_derivation &derivation, unsigned int i, rct::key & mask, hw::device &hwdev)
{
  crypto::secret_key scalar1;
  hwdev.derivation_to_scalar(derivation, i, scalar1);
  try
  {
    switch (rv.type)
    {
    case rct::RCTTypeSimple:
    case rct::RCTTypeSimpleBulletproof:
      return rct::decodeRctSimple(rv, rct::sk2rct(scalar1), i, mask, hwdev);
    case rct::RCTTypeFull:
    case rct::RCTTypeFullBulletproof:
      return rct::decodeRct(rv, rct::sk2rct(scalar1), i, mask, hwdev);
    default:
      LOG_ERROR("Unsupported rct type: " << rv.type);
      return 0;
    }
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Failed to decode input " << i);
    return 0;
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::scan_output(const cryptonote::transaction &tx, const crypto::public_key &tx_pub_key, size_t i, tx_scan_info_t &tx_scan_info, int &num_vouts_received, std::unordered_map<cryptonote::subaddress_index, uint64_t> &tx_money_got_in_outs, std::vector<size_t> &outs) const
{
  THROW_WALLET_EXCEPTION_IF(i >= tx.vout.size(), error::wallet_internal_error, "Invalid vout index");
  if (m_multisig)
  {
    tx_scan_info.in_ephemeral.pub = boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key;
    tx_scan_info.in_ephemeral.sec = crypto::null_skey;
    tx_scan_info.ki = rct::rct2ki(rct::zero());
  }
  else
  {
    bool r = cryptonote::generate_key_image_helper_precomp(m_account.get_keys(), boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key, tx_scan_info.received->derivation, i, tx_scan_info.received->index, tx_scan_info.in_ephemeral, tx_scan_info.ki, m_account.get_device());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
    THROW_WALLET_EXCEPTION_IF(tx_scan_info.in_ephemeral.pub != boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key,
        error::wallet_internal_error, "key_image generated ephemeral public key not matched with output_key");
  }

  outs.push_back(i);
  if (tx_scan_info.money_transfered == 0)
  {
    tx_scan_info.money_transfered = tools::decodeRct(tx.rct_signatures, tx_scan_info.received->derivation, i, tx_scan_info.mask, m_account.get_device());
  }
  tx_money_got_in_outs[tx_scan_info.received->index] += tx_scan_info.money_transfered;
  tx_scan_info.amount = tx_scan_info.money_transfered;
  ++num_vouts_received;
}

//----------------------------------------------------------------------------------------------------
void wallet2::process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height)
{
  if (m_unconfirmed_txs.empty())
    return;

  auto unconf_it = m_unconfirmed_txs.find(txid);
  if(unconf_it != m_unconfirmed_txs.end()) {
    if (store_tx_info()) {
      try {
        m_confirmed_txs.insert(std::make_pair(txid, confirmed_transfer_details(unconf_it->second, height)));
      }
      catch (...) {
        // can fail if the tx has unexpected input types
        LOG_PRINT_L0("Failed to add outgoing transaction to confirmed transaction map");
      }
    }
    m_unconfirmed_txs.erase(unconf_it);
  }
}
void wallet2::remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes)
{
	// remove pool txes to us that aren't in the pool anymore
	std::unordered_multimap<crypto::hash, wallet2::pool_payment_details>::iterator uit = m_unconfirmed_payments.begin();
	while (uit != m_unconfirmed_payments.end())
	{
		const crypto::hash &txid = uit->second.m_pd.m_tx_hash;
		bool found = false;
		for (const auto &it2: tx_hashes)
		{
			if (it2 == txid)
			{
				found = true;
				break;
			}
		}
		auto pit = uit++;
		if (!found)
		{
			MDEBUG("Removing " << txid << " from unconfirmed payments, not found in pool");
			m_unconfirmed_payments.erase(pit);
			if (0 != m_callback)
				m_callback->on_pool_tx_removed(txid);
		}
	}
}
	
	
	
	
	
	
	
//----------------------------------------------------------------------------------------------------
bool wallet2::deinit()
{
  m_is_initialized=false;
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::clear()
{
  m_blockchain.clear();
  m_transfers.clear();
  m_key_images.clear();
  m_pub_keys.clear();
  m_unconfirmed_txs.clear();
  m_payments.clear();
  m_tx_keys.clear();
  m_additional_tx_keys.clear();
  m_confirmed_txs.clear();
  m_unconfirmed_payments.clear();
  m_scanned_pool_txs[0].clear();
  m_scanned_pool_txs[1].clear();
  m_address_book.clear();
  m_local_bc_height = 1;
  m_subaddresses.clear();
  m_subaddress_labels.clear();
  return true;
}


//----------------------------------------------------------------------------------------------------
bool wallet2::parse_long_payment_id(const std::string& payment_id_str, crypto::hash& payment_id)
{
  cryptonote::blobdata payment_id_data;
  if(!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data))
    return false;

  if(sizeof(crypto::hash) != payment_id_data.size())
    return false;

  payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_data.data());
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_short_payment_id(const std::string& payment_id_str, crypto::hash8& payment_id)
{
  cryptonote::blobdata payment_id_data;
  if(!epee::string_tools::parse_hexstr_to_binbuff(payment_id_str, payment_id_data))
    return false;

  if(sizeof(crypto::hash8) != payment_id_data.size())
    return false;

  payment_id = *reinterpret_cast<const crypto::hash8*>(payment_id_data.data());
  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_payment_id(const std::string& payment_id_str, crypto::hash& payment_id)
{
  if (parse_long_payment_id(payment_id_str, payment_id))
    return true;
  crypto::hash8 payment_id8;
  if (parse_short_payment_id(payment_id_str, payment_id8))
  {
    memcpy(payment_id.data, payment_id8.data, 8);
    memset(payment_id.data + 8, 0, 24);
    return true;
  }
  return false;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const
{
  hw::device &hwdev =  m_account.get_device();
  return hwdev.generate_chacha_key(m_account.get_keys(), key);
}
void wallet2::check_genesis(const crypto::hash& genesis_hash) const {
  std::string what("Genesis block mismatch. You probably use wallet without testnet (or stagenet) flag with blockchain from test (or stage) network or vice versa");

  THROW_WALLET_EXCEPTION_IF(genesis_hash != m_blockchain.genesis(), error::wallet_internal_error, what);
}
//----------------------------------------------------------------------------------------------------
std::map<uint32_t, uint64_t> wallet2::balance_per_subaddress(uint32_t index_major) const
{
  std::map<uint32_t, uint64_t> amount_per_subaddr;
  for (const auto& td: m_transfers)
  {
    if (td.m_subaddr_index.major == index_major && !td.m_spent)
    {
      auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[td.m_subaddr_index.minor] = td.amount();
      else
        found->second += td.amount();
    }
  }
  for (const auto& utx: m_unconfirmed_txs)
  {
    if (utx.second.m_subaddr_account == index_major && utx.second.m_state != wallet2::unconfirmed_transfer_details::failed)
    {
      // all changes go to 0-th subaddress (in the current subaddress account)
      auto found = amount_per_subaddr.find(0);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[0] = utx.second.m_change;
      else
        found->second += utx.second.m_change;
    }
  }
  return amount_per_subaddr;
}
//----------------------------------------------------------------------------------------------------
std::map<uint32_t, uint64_t> wallet2::unlocked_balance_per_subaddress(uint32_t index_major) const
{
  std::map<uint32_t, uint64_t> amount_per_subaddr;
  for(const transfer_details& td: m_transfers)
  {
    if(td.m_subaddr_index.major == index_major && !td.m_spent && is_transfer_unlocked(td))
    {
      auto found = amount_per_subaddr.find(td.m_subaddr_index.minor);
      if (found == amount_per_subaddr.end())
        amount_per_subaddr[td.m_subaddr_index.minor] = td.amount();
      else
        found->second += td.amount();
    }
  }
  return amount_per_subaddr;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::balance_all() const
{
  uint64_t r = 0;
  for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
    r += balance(index_major);
  return r;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::unlocked_balance_all() const
{
  uint64_t r = 0;
  for (uint32_t index_major = 0; index_major < get_num_subaddress_accounts(); ++index_major)
    r += unlocked_balance(index_major);
  return r;
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_transfers(wallet2::transfer_container& incoming_transfers) const
{
  incoming_transfers = m_transfers;
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments(const crypto::hash& payment_id, std::list<wallet2::payment_details>& payments, uint64_t min_height, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  auto range = m_payments.equal_range(payment_id);
  std::for_each(range.first, range.second, [&payments, &min_height, &subaddr_account, &subaddr_indices](const payment_container::value_type& x) {
    if (min_height < x.second.m_block_height &&
      (!subaddr_account || *subaddr_account == x.second.m_subaddr_index.major) &&
      (subaddr_indices.empty() || subaddr_indices.count(x.second.m_subaddr_index.minor) == 1))
    {
      payments.push_back(x.second);
    }
  });
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments(std::list<std::pair<crypto::hash,wallet2::payment_details>>& payments, uint64_t min_height, uint64_t max_height, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  auto range = std::make_pair(m_payments.begin(), m_payments.end());
  std::for_each(range.first, range.second, [&payments, &min_height, &max_height, &subaddr_account, &subaddr_indices](const payment_container::value_type& x) {
    if (min_height < x.second.m_block_height && max_height >= x.second.m_block_height &&
      (!subaddr_account || *subaddr_account == x.second.m_subaddr_index.major) &&
      (subaddr_indices.empty() || subaddr_indices.count(x.second.m_subaddr_index.minor) == 1))
    {
      payments.push_back(x);
    }
  });
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_payments_out(std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>>& confirmed_payments,
    uint64_t min_height, uint64_t max_height, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_confirmed_txs.begin(); i != m_confirmed_txs.end(); ++i) {
    if (i->second.m_block_height <= min_height || i->second.m_block_height > max_height)
      continue;
    if (subaddr_account && *subaddr_account != i->second.m_subaddr_account)
      continue;
    if (!subaddr_indices.empty() && std::count_if(i->second.m_subaddr_indices.begin(), i->second.m_subaddr_indices.end(), [&subaddr_indices](uint32_t index) { return subaddr_indices.count(index) == 1; }) == 0)
      continue;
    confirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet2::unconfirmed_transfer_details>>& unconfirmed_payments, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_unconfirmed_txs.begin(); i != m_unconfirmed_txs.end(); ++i) {
    if (subaddr_account && *subaddr_account != i->second.m_subaddr_account)
      continue;
    if (!subaddr_indices.empty() && std::count_if(i->second.m_subaddr_indices.begin(), i->second.m_subaddr_indices.end(), [&subaddr_indices](uint32_t index) { return subaddr_indices.count(index) == 1; }) == 0)
      continue;
    unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
void wallet2::get_unconfirmed_payments(std::list<std::pair<crypto::hash,wallet2::pool_payment_details>>& unconfirmed_payments, const boost::optional<uint32_t>& subaddr_account, const std::set<uint32_t>& subaddr_indices) const
{
  for (auto i = m_unconfirmed_payments.begin(); i != m_unconfirmed_payments.end(); ++i) {
    if ((!subaddr_account || *subaddr_account == i->second.m_pd.m_subaddr_index.major) &&
      (subaddr_indices.empty() || subaddr_indices.count(i->second.m_pd.m_subaddr_index.minor) == 1))
    unconfirmed_payments.push_back(*i);
  }
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_transfer_unlocked(const transfer_details& td) const
{
  return is_transfer_unlocked(td.m_tx.unlock_time, td.m_block_height);
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_transfer_unlocked(uint64_t unlock_time, uint64_t block_height) const
{
  if(!is_tx_spendtime_unlocked(unlock_time, block_height))
    return false;

  if(block_height + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE > m_local_bc_height)
    return false;

  return true;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::is_tx_spendtime_unlocked(uint64_t unlock_time, uint64_t block_height) const
{
  if(unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
  {
    //interpret as block index
    if(m_local_bc_height-1 + CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS >= unlock_time)
      return true;
    else
      return false;
  }else
  {
    //interpret as time
    uint64_t current_time = static_cast<uint64_t>(time(NULL));
    // XXX: this needs to be fast, so we'd need to get the starting heights
    // from the daemon to be correct once voting kicks in
    uint64_t v2height = m_nettype == TESTNET ? 624634 : m_nettype == STAGENET ? (uint64_t)-1/*TODO*/ : 1009827;
    uint64_t leeway = block_height < v2height ? CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V1 : CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2;
    if(current_time + leeway >= unlock_time)
      return true;
    else
      return false;
  }
  return false;
}
//----------------------------------------------------------------------------------------------------
namespace
{
  template<typename T>
  T pop_index(std::vector<T>& vec, size_t idx)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");
    CHECK_AND_ASSERT_MES(idx < vec.size(), T(), "idx out of bounds");

    T res = vec[idx];
    if (idx + 1 != vec.size())
    {
      vec[idx] = vec.back();
    }
    vec.resize(vec.size() - 1);

    return res;
  }

  template<typename T>
  T pop_random_value(std::vector<T>& vec)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    size_t idx = crypto::rand<size_t>() % vec.size();
    return pop_index (vec, idx);
  }

  template<typename T>
  T pop_back(std::vector<T>& vec)
  {
    CHECK_AND_ASSERT_MES(!vec.empty(), T(), "Vector must be non-empty");

    T res = vec.back();
    vec.pop_back();
    return res;
  }

  template<typename T>
  void pop_if_present(std::vector<T>& vec, T e)
  {
    for (size_t i = 0; i < vec.size(); ++i)
    {
      if (e == vec[i])
      {
        pop_index (vec, i);
        return;
      }
    }
  }
}
//----------------------------------------------------------------------------------------------------
// This returns a handwavy estimation of how much two outputs are related
// If they're from the same tx, then they're fully related. From close block
// heights, they're kinda related. The actual values don't matter, just
// their ordering, but it could become more murky if we add scores later.
float wallet2::get_output_relatedness(const transfer_details &td0, const transfer_details &td1) const
{
  int dh;

  // expensive test, and same tx will fall onto the same block height below
  if (td0.m_txid == td1.m_txid)
    return 1.0f;

  // same block height -> possibly tx burst, or same tx (since above is disabled)
  dh = td0.m_block_height > td1.m_block_height ? td0.m_block_height - td1.m_block_height : td1.m_block_height - td0.m_block_height;
  if (dh == 0)
    return 0.9f;

  // adjacent blocks -> possibly tx burst
  if (dh == 1)
    return 0.8f;

  // could extract the payment id, and compare them, but this is a bit expensive too

  // similar block heights
  if (dh < 10)
    return 0.2f;

  // don't think these are particularly related
  return 0.0f;
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::pop_best_value_from(const transfer_container &transfers, std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, bool smallest) const
{
  std::vector<size_t> candidates;
  float best_relatedness = 1.0f;
  for (size_t n = 0; n < unused_indices.size(); ++n)
  {
    const transfer_details &candidate = transfers[unused_indices[n]];
    float relatedness = 0.0f;
    for (std::vector<size_t>::const_iterator i = selected_transfers.begin(); i != selected_transfers.end(); ++i)
    {
      float r = get_output_relatedness(candidate, transfers[*i]);
      if (r > relatedness)
      {
        relatedness = r;
        if (relatedness == 1.0f)
          break;
      }
    }

    if (relatedness < best_relatedness)
    {
      best_relatedness = relatedness;
      candidates.clear();
    }

    if (relatedness == best_relatedness)
      candidates.push_back(n);
  }

  // we have all the least related outputs in candidates, so we can pick either
  // the smallest, or a random one, depending on request
  size_t idx;
  if (smallest)
  {
    idx = 0;
    for (size_t n = 0; n < candidates.size(); ++n)
    {
      const transfer_details &td = transfers[unused_indices[candidates[n]]];
      if (td.amount() < transfers[unused_indices[candidates[idx]]].amount())
        idx = n;
    }
  }
  else
  {
    idx = crypto::rand<size_t>() % candidates.size();
  }
  return pop_index (unused_indices, candidates[idx]);
}
//----------------------------------------------------------------------------------------------------
size_t wallet2::pop_best_value(std::vector<size_t> &unused_indices, const std::vector<size_t>& selected_transfers, bool smallest) const
{
  return pop_best_value_from(m_transfers, unused_indices, selected_transfers, smallest);
}
//----------------------------------------------------------------------------------------------------
// Select random input sources for transaction.
// returns:
//    direct return: amount of money found
//    modified reference: selected_transfers, a list of iterators/indices of input sources
uint64_t wallet2::select_transfers(uint64_t needed_money, std::vector<size_t> unused_transfers_indices, std::vector<size_t>& selected_transfers, bool trusted_daemon) const
{
  uint64_t found_money = 0;
  selected_transfers.reserve(unused_transfers_indices.size());
  while (found_money < needed_money && !unused_transfers_indices.empty())
  {
    size_t idx = pop_best_value(unused_transfers_indices, selected_transfers);

    const transfer_container::const_iterator it = m_transfers.begin() + idx;
    selected_transfers.push_back(idx);
    found_money += it->amount();
  }

  return found_money;
}
//----------------------------------------------------------------------------------------------------
void wallet2::add_unconfirmed_tx(const cryptonote::transaction& tx, uint64_t amount_in, const std::vector<cryptonote::tx_destination_entry> &dests, const crypto::hash &payment_id, uint64_t change_amount, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices)
{
  unconfirmed_transfer_details& utd = m_unconfirmed_txs[cryptonote::get_transaction_hash(tx)];
  utd.m_amount_in = amount_in;
  utd.m_amount_out = 0;
  for (const auto &d: dests)
    utd.m_amount_out += d.amount;
  utd.m_amount_out += change_amount; // dests does not contain change
  utd.m_change = change_amount;
  utd.m_sent_time = time(NULL);
  utd.m_tx = (const cryptonote::transaction_prefix&)tx;
  utd.m_dests = dests;
  utd.m_payment_id = payment_id;
  utd.m_state = wallet2::unconfirmed_transfer_details::pending;
  utd.m_timestamp = time(NULL);
  utd.m_subaddr_account = subaddr_account;
  utd.m_subaddr_indices = subaddr_indices;
  for (const auto &in: tx.vin)
  {
    if (in.type() != typeid(cryptonote::txin_to_key))
      continue;
    const auto &txin = boost::get<cryptonote::txin_to_key>(in);
    utd.m_rings.push_back(std::make_pair(txin.k_image, txin.key_offsets));
  }
}

//----------------------------------------------------------------------------------------------------
void wallet2::transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, const size_t fake_outs_count, const std::vector<size_t> &unused_transfers_indices,
                       uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx& ptx, bool trusted_daemon)
{
  transfer(dsts, fake_outs_count, unused_transfers_indices, unlock_time, fee, extra, detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), tx, ptx, trusted_daemon);
}
//----------------------------------------------------------------------------------------------------
void wallet2::transfer(const std::vector<cryptonote::tx_destination_entry>& dsts, const size_t fake_outs_count, const std::vector<size_t> &unused_transfers_indices,
                       uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, bool trusted_daemon)
{
  cryptonote::transaction tx;
  pending_tx ptx;
  transfer(dsts, fake_outs_count, unused_transfers_indices, unlock_time, fee, extra, tx, ptx, trusted_daemon);
}

namespace {
// split_amounts(vector<cryptonote::tx_destination_entry> dsts, size_t num_splits)
//
// split amount for each dst in dsts into num_splits parts
// and make num_splits new vector<crypt...> instances to hold these new amounts
std::vector<std::vector<cryptonote::tx_destination_entry>> split_amounts(
    std::vector<cryptonote::tx_destination_entry> dsts, size_t num_splits)
{
  std::vector<std::vector<cryptonote::tx_destination_entry>> retVal;

  if (num_splits <= 1)
  {
    retVal.push_back(dsts);
    return retVal;
  }

  // for each split required
  for (size_t i=0; i < num_splits; i++)
  {
    std::vector<cryptonote::tx_destination_entry> new_dsts;

    // for each destination
    for (size_t j=0; j < dsts.size(); j++)
    {
      cryptonote::tx_destination_entry de;
      uint64_t amount;

      amount = dsts[j].amount;
      amount = amount / num_splits;

      // if last split, add remainder
      if (i + 1 == num_splits)
      {
        amount += dsts[j].amount % num_splits;
      }
      
      de.addr = dsts[j].addr;
      de.amount = amount;

      new_dsts.push_back(de);
    }

    retVal.push_back(new_dsts);
  }

  return retVal;
}
} // anonymous namespace
//----------------------------------------------------------------------------------------------------
crypto::hash wallet2::get_payment_id(const pending_tx &ptx) const
{
  std::vector<tx_extra_field> tx_extra_fields;
  parse_tx_extra(ptx.tx.extra, tx_extra_fields); // ok if partially parsed
  tx_extra_nonce extra_nonce;
  crypto::hash payment_id = null_hash;
  if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
  {
    crypto::hash8 payment_id8 = null_hash8;
    if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
    {
      if (ptx.dests.empty())
      {
        MWARNING("Encrypted payment id found, but no destinations public key, cannot decrypt");
        return crypto::null_hash;
      }
      if (m_account.get_device().decrypt_payment_id(payment_id8, ptx.dests[0].addr.m_view_public_key, ptx.tx_key))
      {
        memcpy(payment_id.data, payment_id8.data, 8);
      }
    }
    else if (!get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
    {
      payment_id = crypto::null_hash;
    }
  }
  return payment_id;
}

//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_fee_multiplier(uint32_t priority, int fee_algorithm) const
{
  static const uint64_t old_multipliers[3] = {1, 2, 3};
  static const uint64_t new_multipliers[3] = {1, 20, 166};
  static const uint64_t newer_multipliers[4] = {1, 4, 20, 166};

  if (fee_algorithm == -1)
    fee_algorithm = get_fee_algorithm();

  // 0 -> default (here, x1 till fee algorithm 2, x4 from it)
  if (priority == 0)
    priority = m_default_priority;
  if (priority == 0)
  {
    if (fee_algorithm >= 2)
      priority = 2;
    else
      priority = 1;
  }

  // 1 to 3/4 are allowed as priorities
  uint32_t max_priority = (fee_algorithm >= 2) ? 4 : 3;
  if (priority >= 1 && priority <= max_priority)
  {
    switch (fee_algorithm)
    {
      case 0: return old_multipliers[priority-1];
      case 1: return new_multipliers[priority-1];
      case 2: return newer_multipliers[priority-1];
      default: THROW_WALLET_EXCEPTION_IF (true, error::invalid_priority);
    }
  }

  THROW_WALLET_EXCEPTION_IF (false, error::invalid_priority);
  return 1;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_dynamic_per_kb_fee_estimate() const
{
	
	
	//  uint64_t fee;
//  boost::optional<std::string> result = m_node_rpc_proxy.get_dynamic_per_kb_fee_estimate(FEE_ESTIMATE_GRACE_BLOCKS, fee);
//  if (!result)
//    return fee;
//  LOG_PRINT_L1("Failed to query per kB fee, using " << print_money(FEE_PER_KB));
  return FEE_PER_KB;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_per_kb_fee() const
{
  if(m_light_wallet)
    return m_light_wallet_per_kb_fee;
  bool use_dyn_fee = use_fork_rules(HF_VERSION_DYNAMIC_FEE, -720 * 1);
  if (!use_dyn_fee)
    return FEE_PER_KB;

  return get_dynamic_per_kb_fee_estimate();
}
//----------------------------------------------------------------------------------------------------
int wallet2::get_fee_algorithm() const
{
  // changes at v3 and v5
  if (use_fork_rules(5, 0))
    return 2;
  if (use_fork_rules(3, -720 * 14))
   return 1;
  return 0;
}
//------------------------------------------------------------------------------------------------------------------------------
uint64_t wallet2::adjust_mixin(uint64_t mixin) const
{
  if (mixin < 6 && use_fork_rules(7, 10)) {
    MWARNING("Requested ring size " << (mixin + 1) << " too low for hard fork 7, using 7");
    mixin = 6;
  }
  else if (mixin < 4 && use_fork_rules(6, 10)) {
    MWARNING("Requested ring size " << (mixin + 1) << " too low for hard fork 6, using 5");
    mixin = 4;
  }
  else if (mixin < 2 && use_fork_rules(2, 10)) {
    MWARNING("Requested ring size " << (mixin + 1) << " too low for hard fork 2, using 3");
    mixin = 2;
  }
  return mixin;
}
////----------------------------------------------------------------------------------------------------
//uint32_t wallet2::adjust_priority(uint32_t priority)
//{
//  if (priority == 0 && m_default_priority == 0 && auto_low_priority())
//  {
//    try
//    {
//      // check if there's a backlog in the tx pool
//      const double fee_level = get_fee_multiplier(1) * get_per_kb_fee() * (12/(double)13) / (double)1024;
//      const std::vector<std::pair<uint64_t, uint64_t>> blocks = estimate_backlog({std::make_pair(fee_level, fee_level)});
//      if (blocks.size() != 1)
//      {
//        MERROR("Bad estimated backlog array size");
//        return priority;
//      }
//      else if (blocks[0].first > 0)
//      {
//        MINFO("We don't use the low priority because there's a backlog in the tx pool.");
//        return priority;
//      }
//
//      // get the current full reward zone
//      cryptonote::COMMAND_RPC_GET_INFO::request getinfo_req = AUTO_VAL_INIT(getinfo_req);
//      cryptonote::COMMAND_RPC_GET_INFO::response getinfo_res = AUTO_VAL_INIT(getinfo_res);
//      m_daemon_rpc_mutex.lock();
//      bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_info", getinfo_req, getinfo_res, m_http_client);
//      m_daemon_rpc_mutex.unlock();
//      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_info");
//      THROW_WALLET_EXCEPTION_IF(getinfo_res.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "get_info");
//      THROW_WALLET_EXCEPTION_IF(getinfo_res.status != CORE_RPC_STATUS_OK, error::get_tx_pool_error);
//      const uint64_t full_reward_zone = getinfo_res.block_size_limit / 2;
//
//      // get the last N block headers and sum the block sizes
//      const size_t N = 10;
//      if (m_blockchain.size() < N)
//      {
//        MERROR("The blockchain is too short");
//        return priority;
//      }
//      cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::request getbh_req = AUTO_VAL_INIT(getbh_req);
//      cryptonote::COMMAND_RPC_GET_BLOCK_HEADERS_RANGE::response getbh_res = AUTO_VAL_INIT(getbh_res);
//      m_daemon_rpc_mutex.lock();
//      getbh_req.start_height = m_blockchain.size() - N;
//      getbh_req.end_height = m_blockchain.size() - 1;
//      r = net_utils::invoke_http_json_rpc("/json_rpc", "getblockheadersrange", getbh_req, getbh_res, m_http_client, rpc_timeout);
//      m_daemon_rpc_mutex.unlock();
//      THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "getblockheadersrange");
//      THROW_WALLET_EXCEPTION_IF(getbh_res.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "getblockheadersrange");
//      THROW_WALLET_EXCEPTION_IF(getbh_res.status != CORE_RPC_STATUS_OK, error::get_blocks_error, getbh_res.status);
//      if (getbh_res.headers.size() != N)
//      {
//        MERROR("Bad blockheaders size");
//        return priority;
//      }
//      size_t block_size_sum = 0;
//      for (const cryptonote::block_header_response &i : getbh_res.headers)
//      {
//        block_size_sum += i.block_size;
//      }
//
//      // estimate how 'full' the last N blocks are
//      const size_t P = 100 * block_size_sum / (N * full_reward_zone);
//      MINFO((boost::format("The last %d blocks fill roughly %d%% of the full reward zone.") % N % P).str());
//      if (P > 80)
//      {
//        MINFO("We don't use the low priority because recent blocks are quite full.");
//        return priority;
//      }
//      MINFO("We'll use the low priority because probably it's safe to do so.");
//      return 1;
//    }
//    catch (const std::exception &e)
//    {
//      MERROR(e.what());
//    }
//  }
//  return priority;
//}
//----------------------------------------------------------------------------------------------------
// separated the call(s) to wallet2::transfer into their own function
//
// this function will make multiple calls to wallet2::transfer if multiple
// transactions will be required
std::vector<wallet2::pending_tx> wallet2::create_transactions(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, bool trusted_daemon)
{
  const std::vector<size_t> unused_transfers_indices = select_available_outputs_from_histogram(fake_outs_count + 1, true, true, true, trusted_daemon);

  const uint64_t fee_per_kb  = get_per_kb_fee();
  const uint64_t fee_multiplier = get_fee_multiplier(priority, get_fee_algorithm());

  // failsafe split attempt counter
  size_t attempt_count = 0;

  for(attempt_count = 1; ;attempt_count++)
  {
    size_t num_tx = 0.5 + pow(1.7,attempt_count-1);

    auto split_values = split_amounts(dsts, num_tx);

    // Throw if split_amounts comes back with a vector of size different than it should
    if (split_values.size() != num_tx)
    {
      throw std::runtime_error("Splitting transactions returned a number of potential tx not equal to what was requested");
    }

    std::vector<pending_tx> ptx_vector;
    try
    {
      // for each new destination vector (i.e. for each new tx)
      for (auto & dst_vector : split_values)
      {
        cryptonote::transaction tx;
        pending_tx ptx;

	// loop until fee is met without increasing tx size to next KB boundary.
	const size_t estimated_tx_size = estimate_tx_size(false, unused_transfers_indices.size(), fake_outs_count, dst_vector.size(), extra.size(), false);
	uint64_t needed_fee = calculate_fee(fee_per_kb, estimated_tx_size, fee_multiplier);
	do
	{
	  transfer(dst_vector, fake_outs_count, unused_transfers_indices, unlock_time, needed_fee, extra, tx, ptx, trusted_daemon);
	  auto txBlob = t_serializable_object_to_blob(ptx.tx);
          needed_fee = calculate_fee(fee_per_kb, txBlob, fee_multiplier);
	} while (ptx.fee < needed_fee);

        ptx_vector.push_back(ptx);

        // mark transfers to be used as "spent"
        for(size_t idx: ptx.selected_transfers)
        {
          set_spent(idx, 0);
        }
      }

      // if we made it this far, we've selected our transactions.  committing them will mark them spent,
      // so this is a failsafe in case they don't go through
      // unmark pending tx transfers as spent
      for (auto & ptx : ptx_vector)
      {
        // mark transfers to be used as not spent
        for(size_t idx2: ptx.selected_transfers)
        {
          set_unspent(idx2);
        }

      }

      // if we made it this far, we're OK to actually send the transactions
      return ptx_vector;

    }
    // only catch this here, other exceptions need to pass through to the calling function
    catch (const tools::error::tx_too_big& e)
    {

      // unmark pending tx transfers as spent
      for (auto & ptx : ptx_vector)
      {
        // mark transfers to be used as not spent
        for(size_t idx2: ptx.selected_transfers)
        {
          set_unspent(idx2);
        }
      }

      if (attempt_count >= MAX_SPLIT_ATTEMPTS)
      {
        throw;
      }
    }
    catch (...)
    {
      // in case of some other exception, make sure any tx in queue are marked unspent again

      // unmark pending tx transfers as spent
      for (auto & ptx : ptx_vector)
      {
        // mark transfers to be used as not spent
        for(size_t idx2: ptx.selected_transfers)
        {
          set_unspent(idx2);
        }
      }

      throw;
    }
  }
}

bool wallet2::is_output_blackballed(const crypto::public_key &output) const
{
	// NOTE: modified
	return false;
}


bool wallet2::tx_add_fake_output(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& output_public_key, const rct::key& mask, uint64_t real_index, bool unlocked) const
{
  if (!unlocked) // don't add locked outs
    return false;
  if (global_index == real_index) // don't re-add real one
    return false;
  auto item = std::make_tuple(global_index, output_public_key, mask);
  CHECK_AND_ASSERT_MES(!outs.empty(), false, "internal error: outs is empty");
  if (std::find(outs.back().begin(), outs.back().end(), item) != outs.back().end()) // don't add duplicates
    return false;
  if (is_output_blackballed(output_public_key)) // don't add blackballed outputs
    return false;
  outs.back().push_back(item);
  return true;
}

void wallet2::light_wallet_get_outs(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count) {
  
  MDEBUG("LIGHTWALLET - Getting random outs");
	

	// TODO: make overridable or remove
	
	
	
}

void wallet2::get_outs(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count)
{
  LOG_PRINT_L2("fake_outputs_count: " << fake_outputs_count);
	
//	LOG_PRINT_L2("fake_outputs_count: " << fake_outputs_count);
//	outs.clear();
//
//	if(m_light_wallet && fake_outputs_count > 0) {
//		light_wallet_get_outs(outs, selected_transfers, fake_outputs_count);
//		return;
//	}

	// TODO: overridable

	
}

template<typename T>
void wallet2::transfer_selected(const std::vector<cryptonote::tx_destination_entry>& dsts, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,
  std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs,
  uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, T destination_split_strategy, const tx_dust_policy& dust_policy, cryptonote::transaction& tx, pending_tx &ptx)
{
  using namespace cryptonote;
  // throw if attempting a transaction with no destinations
  THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);

  THROW_WALLET_EXCEPTION_IF(m_multisig, error::wallet_internal_error, "Multisig wallets cannot spend non rct outputs");

  uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit();
  uint64_t needed_money = fee;
  LOG_PRINT_L2("transfer: starting with fee " << print_money (needed_money));

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  for(auto& dt: dsts)
  {
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_destination);
    needed_money += dt.amount;
    LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
    THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, fee, m_nettype);
  }

  uint64_t found_money = 0;
  for(size_t idx: selected_transfers)
  {
    found_money += m_transfers[idx].amount();
  }

  LOG_PRINT_L2("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
  THROW_WALLET_EXCEPTION_IF(found_money < needed_money, error::not_enough_unlocked_money, found_money, needed_money - fee, fee);

  uint32_t subaddr_account = m_transfers[*selected_transfers.begin()].m_subaddr_index.major;
  for (auto i = ++selected_transfers.begin(); i != selected_transfers.end(); ++i)
    THROW_WALLET_EXCEPTION_IF(subaddr_account != m_transfers[*i].m_subaddr_index.major, error::wallet_internal_error, "the tx uses funds from multiple accounts");

  if (outs.empty())
    get_outs(outs, selected_transfers, fake_outputs_count); // may throw

  //prepare inputs
  LOG_PRINT_L2("preparing outputs");
  typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
  size_t i = 0, out_index = 0;
  std::vector<cryptonote::tx_source_entry> sources;
  for(size_t idx: selected_transfers)
  {
    sources.resize(sources.size()+1);
    cryptonote::tx_source_entry& src = sources.back();
    const transfer_details& td = m_transfers[idx];
    src.amount = td.amount();
    src.rct = td.is_rct();
    //paste keys (fake and real)

    for (size_t n = 0; n < fake_outputs_count + 1; ++n)
    {
      tx_output_entry oe;
      oe.first = std::get<0>(outs[out_index][n]);
      oe.second.dest = rct::pk2rct(std::get<1>(outs[out_index][n]));
      oe.second.mask = std::get<2>(outs[out_index][n]);

      src.outputs.push_back(oe);
      ++i;
    }

    //paste real transaction to the random index
    auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
    {
      return a.first == td.m_global_output_index;
    });
    THROW_WALLET_EXCEPTION_IF(it_to_replace == src.outputs.end(), error::wallet_internal_error,
        "real output not found");

    tx_output_entry real_oe;
    real_oe.first = td.m_global_output_index;
    real_oe.second.dest = rct::pk2rct(boost::get<txout_to_key>(td.m_tx.vout[td.m_internal_output_index].target).key);
    real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
    *it_to_replace = real_oe;
    src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
    src.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);
    src.real_output = it_to_replace - src.outputs.begin();
    src.real_output_in_tx_index = td.m_internal_output_index;
    src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
    detail::print_source_entry(src);
    ++out_index;
  }
  LOG_PRINT_L2("outputs prepared");

  cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
  if (needed_money < found_money)
  {
    change_dts.addr = get_subaddress({subaddr_account, 0});
    change_dts.amount = found_money - needed_money;
  }

  std::vector<cryptonote::tx_destination_entry> splitted_dsts, dust_dsts;
  uint64_t dust = 0;
  destination_split_strategy(dsts, change_dts, dust_policy.dust_threshold, splitted_dsts, dust_dsts);
  for(auto& d: dust_dsts) {
    THROW_WALLET_EXCEPTION_IF(dust_policy.dust_threshold < d.amount, error::wallet_internal_error, "invalid dust value: dust = " +
      std::to_string(d.amount) + ", dust_threshold = " + std::to_string(dust_policy.dust_threshold));
  }
  for(auto& d: dust_dsts) {
    if (!dust_policy.add_to_fee)
      splitted_dsts.push_back(cryptonote::tx_destination_entry(d.amount, dust_policy.addr_for_dust, d.is_subaddress));
    dust += d.amount;
  }

  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  rct::multisig_out msout;
  LOG_PRINT_L2("constructing tx");
  bool r = cryptonote::construct_tx_and_get_tx_key(m_account.get_keys(), m_subaddresses, sources, splitted_dsts, change_dts.addr, extra, tx, unlock_time, tx_key, additional_tx_keys, false, false, m_multisig ? &msout : NULL);
  LOG_PRINT_L2("constructed tx, r="<<r);
  THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, splitted_dsts, unlock_time, m_nettype);
  THROW_WALLET_EXCEPTION_IF(upper_transaction_size_limit <= get_object_blobsize(tx), error::tx_too_big, tx, upper_transaction_size_limit);

  std::string key_images;
  bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
  {
    CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
    key_images += boost::to_string(in.k_image) + " ";
    return true;
  });
  THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, tx);
  
  
  bool dust_sent_elsewhere = (dust_policy.addr_for_dust.m_view_public_key != change_dts.addr.m_view_public_key
                                || dust_policy.addr_for_dust.m_spend_public_key != change_dts.addr.m_spend_public_key);
  
  if (dust_policy.add_to_fee || dust_sent_elsewhere) change_dts.amount -= dust;

  ptx.key_images = key_images;
  ptx.fee = (dust_policy.add_to_fee ? fee+dust : fee);
  ptx.dust = ((dust_policy.add_to_fee || dust_sent_elsewhere) ? dust : 0);
  ptx.dust_added_to_fee = dust_policy.add_to_fee;
  ptx.tx = tx;
  ptx.change_dts = change_dts;
  ptx.selected_transfers = selected_transfers;
  ptx.tx_key = tx_key;
  ptx.additional_tx_keys = additional_tx_keys;
  ptx.dests = dsts;
  ptx.construction_data.sources = sources;
  ptx.construction_data.change_dts = change_dts;
  ptx.construction_data.splitted_dsts = splitted_dsts;
  ptx.construction_data.selected_transfers = selected_transfers;
  ptx.construction_data.extra = tx.extra;
  ptx.construction_data.unlock_time = unlock_time;
  ptx.construction_data.use_rct = false;
  ptx.construction_data.dests = dsts;
  // record which subaddress indices are being used as inputs
  ptx.construction_data.subaddr_account = subaddr_account;
  ptx.construction_data.subaddr_indices.clear();
  for (size_t idx: selected_transfers)
    ptx.construction_data.subaddr_indices.insert(m_transfers[idx].m_subaddr_index.minor);
  LOG_PRINT_L2("transfer_selected done");
}

void wallet2::transfer_selected_rct(std::vector<cryptonote::tx_destination_entry> dsts, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,
  std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs,
  uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx &ptx, bool bulletproof)
{
  using namespace cryptonote;
  // throw if attempting a transaction with no destinations
  THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);

  uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit();
  uint64_t needed_money = fee;
  LOG_PRINT_L2("transfer_selected_rct: starting with fee " << print_money (needed_money));
  LOG_PRINT_L2("selected transfers: " << strjoin(selected_transfers, " "));

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  for(auto& dt: dsts)
  {
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_destination);
    needed_money += dt.amount;
    LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
    THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, fee, m_nettype);
  }

  // if this is a multisig wallet, create a list of multisig signers we can use
  std::deque<crypto::public_key> multisig_signers;
  size_t n_multisig_txes = 0;
  if (m_multisig && !m_transfers.empty())
  {
    const crypto::public_key local_signer = get_multisig_signer_public_key();
    size_t n_available_signers = 1;
    for (const crypto::public_key &signer: m_multisig_signers)
    {
      if (signer == local_signer)
        continue;
      multisig_signers.push_front(signer);
      for (const auto &i: m_transfers[0].m_multisig_info)
      {
        if (i.m_signer == signer)
        {
          multisig_signers.pop_front();
          multisig_signers.push_back(signer);
          ++n_available_signers;
          break;
        }
      }
    }
    multisig_signers.push_back(local_signer);
    MDEBUG("We can use " << n_available_signers << "/" << m_multisig_signers.size() <<  " other signers");
    THROW_WALLET_EXCEPTION_IF(n_available_signers+1 < m_multisig_threshold, error::multisig_import_needed);
    n_multisig_txes = n_available_signers == m_multisig_signers.size() ? m_multisig_threshold : 1;
    MDEBUG("We will create " << n_multisig_txes << " txes");
  }

  uint64_t found_money = 0;
  for(size_t idx: selected_transfers)
  {
    found_money += m_transfers[idx].amount();
  }

  LOG_PRINT_L2("wanted " << print_money(needed_money) << ", found " << print_money(found_money) << ", fee " << print_money(fee));
  THROW_WALLET_EXCEPTION_IF(found_money < needed_money, error::not_enough_unlocked_money, found_money, needed_money - fee, fee);

  uint32_t subaddr_account = m_transfers[*selected_transfers.begin()].m_subaddr_index.major;
  for (auto i = ++selected_transfers.begin(); i != selected_transfers.end(); ++i)
    THROW_WALLET_EXCEPTION_IF(subaddr_account != m_transfers[*i].m_subaddr_index.major, error::wallet_internal_error, "the tx uses funds from multiple accounts");

  if (outs.empty())
    get_outs(outs, selected_transfers, fake_outputs_count); // may throw

  //prepare inputs
  LOG_PRINT_L2("preparing outputs");
  size_t i = 0, out_index = 0;
  std::vector<cryptonote::tx_source_entry> sources;
  std::unordered_set<rct::key> used_L;
  for(size_t idx: selected_transfers)
  {
    sources.resize(sources.size()+1);
    cryptonote::tx_source_entry& src = sources.back();
    const transfer_details& td = m_transfers[idx];
    src.amount = td.amount();
    src.rct = td.is_rct();
    //paste mixin transaction

    THROW_WALLET_EXCEPTION_IF(outs.size() < out_index + 1 ,  error::wallet_internal_error, "outs.size() < out_index + 1"); 
    THROW_WALLET_EXCEPTION_IF(outs[out_index].size() < fake_outputs_count ,  error::wallet_internal_error, "fake_outputs_count > random outputs found");
      
    typedef cryptonote::tx_source_entry::output_entry tx_output_entry;
    for (size_t n = 0; n < fake_outputs_count + 1; ++n)
    {
      tx_output_entry oe;
      oe.first = std::get<0>(outs[out_index][n]);
      oe.second.dest = rct::pk2rct(std::get<1>(outs[out_index][n]));
      oe.second.mask = std::get<2>(outs[out_index][n]);
      src.outputs.push_back(oe);
    }
    ++i;

    //paste real transaction to the random index
    auto it_to_replace = std::find_if(src.outputs.begin(), src.outputs.end(), [&](const tx_output_entry& a)
    {
      return a.first == td.m_global_output_index;
    });
    THROW_WALLET_EXCEPTION_IF(it_to_replace == src.outputs.end(), error::wallet_internal_error,
        "real output not found");

    tx_output_entry real_oe;
    real_oe.first = td.m_global_output_index;
    real_oe.second.dest = rct::pk2rct(td.get_public_key());
    real_oe.second.mask = rct::commit(td.amount(), td.m_mask);
    *it_to_replace = real_oe;
    src.real_out_tx_key = get_tx_pub_key_from_extra(td.m_tx, td.m_pk_index);
    src.real_out_additional_tx_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);
    src.real_output = it_to_replace - src.outputs.begin();
    src.real_output_in_tx_index = td.m_internal_output_index;
    src.mask = td.m_mask;
    if (m_multisig)
    {
      crypto::public_key ignore = m_multisig_threshold == m_multisig_signers.size() ? crypto::null_pkey : multisig_signers.front();
      src.multisig_kLRki = get_multisig_composite_kLRki(idx, ignore, used_L, used_L);
    }
    else
      src.multisig_kLRki = rct::multisig_kLRki({rct::zero(), rct::zero(), rct::zero(), rct::zero()});
    detail::print_source_entry(src);
    ++out_index;
  }
  LOG_PRINT_L2("outputs prepared");

  // we still keep a copy, since we want to keep dsts free of change for user feedback purposes
  std::vector<cryptonote::tx_destination_entry> splitted_dsts = dsts;
  cryptonote::tx_destination_entry change_dts = AUTO_VAL_INIT(change_dts);
  change_dts.amount = found_money - needed_money;
  if (change_dts.amount == 0)
  {
    if (splitted_dsts.size() == 1)
    {
      // If the change is 0, send it to a random address, to avoid confusing
      // the sender with a 0 amount output. We send a 0 amount in order to avoid
      // letting the destination be able to work out which of the inputs is the
      // real one in our rings
      LOG_PRINT_L2("generating dummy address for 0 change");
      cryptonote::account_base dummy;
      dummy.generate();
      change_dts.addr = dummy.get_keys().m_account_address;
      LOG_PRINT_L2("generated dummy address for 0 change");
      splitted_dsts.push_back(change_dts);
    }
  }
  else
  {
    change_dts.addr = get_subaddress({subaddr_account, 0});
    splitted_dsts.push_back(change_dts);
  }

  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  rct::multisig_out msout;
  LOG_PRINT_L2("constructing tx");
  auto sources_copy = sources;
  bool r = cryptonote::construct_tx_and_get_tx_key(m_account.get_keys(), m_subaddresses, sources, splitted_dsts, change_dts.addr, extra, tx, unlock_time, tx_key, additional_tx_keys, true, bulletproof, m_multisig ? &msout : NULL);
  LOG_PRINT_L2("constructed tx, r="<<r);
  THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, dsts, unlock_time, m_nettype);
  THROW_WALLET_EXCEPTION_IF(upper_transaction_size_limit <= get_object_blobsize(tx), error::tx_too_big, tx, upper_transaction_size_limit);

  // work out the permutation done on sources
  std::vector<size_t> ins_order;
  for (size_t n = 0; n < sources.size(); ++n)
  {
    for (size_t idx = 0; idx < sources_copy.size(); ++idx)
    {
      THROW_WALLET_EXCEPTION_IF((size_t)sources_copy[idx].real_output >= sources_copy[idx].outputs.size(),
          error::wallet_internal_error, "Invalid real_output");
      if (sources_copy[idx].outputs[sources_copy[idx].real_output].second.dest == sources[n].outputs[sources[n].real_output].second.dest)
        ins_order.push_back(idx);
    }
  }
  THROW_WALLET_EXCEPTION_IF(ins_order.size() != sources.size(), error::wallet_internal_error, "Failed to work out sources permutation");

  std::vector<tools::wallet2::multisig_sig> multisig_sigs;
  if (m_multisig)
  {
    crypto::public_key ignore = m_multisig_threshold == m_multisig_signers.size() ? crypto::null_pkey : multisig_signers.front();
    multisig_sigs.push_back({tx.rct_signatures, ignore, used_L, std::unordered_set<crypto::public_key>(), msout});

    if (m_multisig_threshold < m_multisig_signers.size())
    {
      const crypto::hash prefix_hash = cryptonote::get_transaction_prefix_hash(tx);

      // create the other versions, one for every other participant (the first one's already done above)
      for (size_t signer_index = 1; signer_index < n_multisig_txes; ++signer_index)
      {
        std::unordered_set<rct::key> new_used_L;
        size_t src_idx = 0;
        THROW_WALLET_EXCEPTION_IF(selected_transfers.size() != sources.size(), error::wallet_internal_error, "mismatched selected_transfers and sources sixes");
        for(size_t idx: selected_transfers)
        {
          cryptonote::tx_source_entry& src = sources[src_idx];
          src.multisig_kLRki = get_multisig_composite_kLRki(idx, multisig_signers[signer_index], used_L, new_used_L);
          ++src_idx;
        }

        LOG_PRINT_L2("Creating supplementary multisig transaction");
        cryptonote::transaction ms_tx;
        auto sources_copy_copy = sources_copy;
        bool r = cryptonote::construct_tx_with_tx_key(m_account.get_keys(), m_subaddresses, sources_copy_copy, splitted_dsts, change_dts.addr, extra, ms_tx, unlock_time,tx_key, additional_tx_keys, true, bulletproof, &msout);
        LOG_PRINT_L2("constructed tx, r="<<r);
        THROW_WALLET_EXCEPTION_IF(!r, error::tx_not_constructed, sources, splitted_dsts, unlock_time, m_nettype);
        THROW_WALLET_EXCEPTION_IF(upper_transaction_size_limit <= get_object_blobsize(tx), error::tx_too_big, tx, upper_transaction_size_limit);
        THROW_WALLET_EXCEPTION_IF(cryptonote::get_transaction_prefix_hash(ms_tx) != prefix_hash, error::wallet_internal_error, "Multisig txes do not share prefix");
        multisig_sigs.push_back({ms_tx.rct_signatures, multisig_signers[signer_index], new_used_L, std::unordered_set<crypto::public_key>(), msout});

        ms_tx.rct_signatures = tx.rct_signatures;
        THROW_WALLET_EXCEPTION_IF(cryptonote::get_transaction_hash(ms_tx) != cryptonote::get_transaction_hash(tx), error::wallet_internal_error, "Multisig txes differ by more than the signatures");
      }
    }
  }

  LOG_PRINT_L2("gathering key images");
  std::string key_images;
  bool all_are_txin_to_key = std::all_of(tx.vin.begin(), tx.vin.end(), [&](const txin_v& s_e) -> bool
  {
    CHECKED_GET_SPECIFIC_VARIANT(s_e, const txin_to_key, in, false);
    key_images += boost::to_string(in.k_image) + " ";
    return true;
  });
  THROW_WALLET_EXCEPTION_IF(!all_are_txin_to_key, error::unexpected_txin_type, tx);
  LOG_PRINT_L2("gathered key images");

  ptx.key_images = key_images;
  ptx.fee = fee;
  ptx.dust = 0;
  ptx.dust_added_to_fee = false;
  ptx.tx = tx;
  ptx.change_dts = change_dts;
  ptx.selected_transfers = selected_transfers;
  tools::apply_permutation(ins_order, ptx.selected_transfers);
  ptx.tx_key = tx_key;
  ptx.additional_tx_keys = additional_tx_keys;
  ptx.dests = dsts;
  ptx.multisig_sigs = multisig_sigs;
  ptx.construction_data.sources = sources_copy;
  ptx.construction_data.change_dts = change_dts;
  ptx.construction_data.splitted_dsts = splitted_dsts;
  ptx.construction_data.selected_transfers = ptx.selected_transfers;
  ptx.construction_data.extra = tx.extra;
  ptx.construction_data.unlock_time = unlock_time;
  ptx.construction_data.use_rct = true;
  ptx.construction_data.dests = dsts;
  // record which subaddress indices are being used as inputs
  ptx.construction_data.subaddr_account = subaddr_account;
  ptx.construction_data.subaddr_indices.clear();
  for (size_t idx: selected_transfers)
    ptx.construction_data.subaddr_indices.insert(m_transfers[idx].m_subaddr_index.minor);
  LOG_PRINT_L2("transfer_selected_rct done");
}

std::vector<size_t> wallet2::pick_preferred_rct_inputs(uint64_t needed_money, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices) const
{
  std::vector<size_t> picks;
  float current_output_relatdness = 1.0f;

  LOG_PRINT_L2("pick_preferred_rct_inputs: needed_money " << print_money(needed_money));

  // try to find a rct input of enough size
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!td.m_spent && td.is_rct() && td.amount() >= needed_money && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
    {
      LOG_PRINT_L2("We can use " << i << " alone: " << print_money(td.amount()));
      picks.push_back(i);
      return picks;
    }
  }

  // then try to find two outputs
  // this could be made better by picking one of the outputs to be a small one, since those
  // are less useful since often below the needed money, so if one can be used in a pair,
  // it gets rid of it for the future
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!td.m_spent && !td.m_key_image_partial && td.is_rct() && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
    {
      LOG_PRINT_L2("Considering input " << i << ", " << print_money(td.amount()));
      for (size_t j = i + 1; j < m_transfers.size(); ++j)
      {
        const transfer_details& td2 = m_transfers[j];
        if (!td2.m_spent && !td.m_key_image_partial && td2.is_rct() && td.amount() + td2.amount() >= needed_money && is_transfer_unlocked(td2) && td2.m_subaddr_index == td.m_subaddr_index)
        {
          // update our picks if those outputs are less related than any we
          // already found. If the same, don't update, and oldest suitable outputs
          // will be used in preference.
          float relatedness = get_output_relatedness(td, td2);
          LOG_PRINT_L2("  with input " << j << ", " << print_money(td2.amount()) << ", relatedness " << relatedness);
          if (relatedness < current_output_relatdness)
          {
            // reset the current picks with those, and return them directly
            // if they're unrelated. If they are related, we'll end up returning
            // them if we find nothing better
            picks.clear();
            picks.push_back(i);
            picks.push_back(j);
            LOG_PRINT_L0("we could use " << i << " and " << j);
            if (relatedness == 0.0f)
              return picks;
            current_output_relatdness = relatedness;
          }
        }
      }
    }
  }

  return picks;
}

bool wallet2::should_pick_a_second_output(bool use_rct, size_t n_transfers, const std::vector<size_t> &unused_transfers_indices, const std::vector<size_t> &unused_dust_indices) const
{
  if (!use_rct)
    return false;
  if (n_transfers > 1)
    return false;
  if (unused_dust_indices.empty() && unused_transfers_indices.empty())
    return false;
  // we want at least one free rct output to avoid a corner case where
  // we'd choose a non rct output which doesn't have enough "siblings"
  // value-wise on the chain, and thus can't be mixed
  bool found = false;
  for (auto i: unused_dust_indices)
  {
    if (m_transfers[i].is_rct())
    {
      found = true;
      break;
    }
  }
  if (!found) for (auto i: unused_transfers_indices)
  {
    if (m_transfers[i].is_rct())
    {
      found = true;
      break;
    }
  }
  if (!found)
    return false;
  return true;
}


//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_multisig_signer_public_key(const crypto::secret_key &spend_skey) const
{
	crypto::public_key pkey;
	crypto::secret_key_to_public_key(get_multisig_blinded_secret_key(spend_skey), pkey);
	return pkey;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_multisig_signer_public_key() const
{
	CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
	crypto::public_key signer;
	CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(get_account().get_keys().m_spend_secret_key, signer), "Failed to generate signer public key");
	return signer;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_multisig_signing_public_key(const crypto::secret_key &msk) const
{
	CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
	crypto::public_key pkey;
	CHECK_AND_ASSERT_THROW_MES(crypto::secret_key_to_public_key(msk, pkey), "Failed to derive public key");
	return pkey;
}
//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_multisig_signing_public_key(size_t idx) const
{
	CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
	CHECK_AND_ASSERT_THROW_MES(idx < get_account().get_multisig_keys().size(), "Multisig signing key index out of range");
	return get_multisig_signing_public_key(get_account().get_multisig_keys()[idx]);
}
//----------------------------------------------------------------------------------------------------
rct::key wallet2::get_multisig_k(size_t idx, const std::unordered_set<rct::key> &used_L) const
{
	CHECK_AND_ASSERT_THROW_MES(m_multisig, "Wallet is not multisig");
	CHECK_AND_ASSERT_THROW_MES(idx < m_transfers.size(), "idx out of range");
	for (const auto &k: m_transfers[idx].m_multisig_k)
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
rct::multisig_kLRki wallet2::get_multisig_kLRki(size_t n, const rct::key &k) const
{
	CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad m_transfers index");
	rct::multisig_kLRki kLRki;
	kLRki.k = k;
	cryptonote::generate_multisig_LR(m_transfers[n].get_public_key(), rct::rct2sk(kLRki.k), (crypto::public_key&)kLRki.L, (crypto::public_key&)kLRki.R);
	kLRki.ki = rct::ki2rct(m_transfers[n].m_key_image);
	return kLRki;
}
//----------------------------------------------------------------------------------------------------
rct::multisig_kLRki wallet2::get_multisig_composite_kLRki(size_t n, const crypto::public_key &ignore, std::unordered_set<rct::key> &used_L, std::unordered_set<rct::key> &new_used_L) const
{
	CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad transfer index");
	
	const transfer_details &td = m_transfers[n];
	rct::multisig_kLRki kLRki = get_multisig_kLRki(n, rct::skGen());
	
	// pick a L/R pair from every other participant but one
	size_t n_signers_used = 1;
	for (const auto &p: m_transfers[n].m_multisig_info)
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
	CHECK_AND_ASSERT_THROW_MES(n_signers_used >= m_multisig_threshold, "LR not found for enough participants");
	
	return kLRki;
}
//----------------------------------------------------------------------------------------------------
crypto::key_image wallet2::get_multisig_composite_key_image(size_t n) const
{
	CHECK_AND_ASSERT_THROW_MES(n < m_transfers.size(), "Bad output index");
	
	const transfer_details &td = m_transfers[n];
	const crypto::public_key tx_key = get_tx_pub_key_from_received_outs(td);
	const std::vector<crypto::public_key> additional_tx_keys = cryptonote::get_additional_tx_pub_keys_from_extra(td.m_tx);
	crypto::key_image ki;
	std::vector<crypto::key_image> pkis;
	for (const auto &info: td.m_multisig_info)
		for (const auto &pki: info.m_partial_key_images)
			pkis.push_back(pki);
	bool r = cryptonote::generate_multisig_composite_key_image(get_account().get_keys(), m_subaddresses, td.get_public_key(), tx_key, additional_tx_keys, td.m_internal_output_index, pkis, ki);
	THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key image");
	return ki;
}

std::vector<size_t> wallet2::get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const
{
  std::vector<size_t> indices;
  for (size_t n: unused_dust_indices)
    if (m_transfers[n].is_rct())
      indices.push_back(n);
  for (size_t n: unused_transfers_indices)
    if (m_transfers[n].is_rct())
      indices.push_back(n);
  return indices;
}

static uint32_t get_count_above(const std::vector<wallet2::transfer_details> &transfers, const std::vector<size_t> &indices, uint64_t threshold)
{
  uint32_t count = 0;
  for (size_t idx: indices)
    if (transfers[idx].amount() >= threshold)
      ++count;
  return count;
}

	
bool wallet2::light_wallet_key_image_is_ours(const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index)
{
  // Lookup key image from cache
  std::map<uint64_t, crypto::key_image> index_keyimage_map;
  std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> >::const_iterator found_pub_key = m_key_image_cache.find(tx_public_key);
  if(found_pub_key != m_key_image_cache.end()) {
    // pub key found. key image for index cached?
    index_keyimage_map = found_pub_key->second;
    std::map<uint64_t,crypto::key_image>::const_iterator index_found = index_keyimage_map.find(out_index);
    if(index_found != index_keyimage_map.end())
      return key_image == index_found->second;
  }

  // Not in cache - calculate key image
  crypto::key_image calculated_key_image;
  cryptonote::keypair in_ephemeral;
  
  // Subaddresses aren't supported in mymonero/openmonero yet. Roll out the original scheme:
  //   compute D = a*R
  //   compute P = Hs(D || i)*G + B
  //   compute x = Hs(D || i) + b      (and check if P==x*G)
  //   compute I = x*Hp(P)
  const account_keys& ack = get_account().get_keys();
  crypto::key_derivation derivation;
  bool r = crypto::generate_key_derivation(tx_public_key, ack.m_view_secret_key, derivation);
  CHECK_AND_ASSERT_MES(r, false, "failed to generate_key_derivation(" << tx_public_key << ", " << ack.m_view_secret_key << ")");

  r = crypto::derive_public_key(derivation, out_index, ack.m_account_address.m_spend_public_key, in_ephemeral.pub);
  CHECK_AND_ASSERT_MES(r, false, "failed to derive_public_key (" << derivation << ", " << out_index << ", " << ack.m_account_address.m_spend_public_key << ")");

  crypto::derive_secret_key(derivation, out_index, ack.m_spend_secret_key, in_ephemeral.sec);
  crypto::public_key out_pkey_test;
  r = crypto::secret_key_to_public_key(in_ephemeral.sec, out_pkey_test);
  CHECK_AND_ASSERT_MES(r, false, "failed to secret_key_to_public_key(" << in_ephemeral.sec << ")");
  CHECK_AND_ASSERT_MES(in_ephemeral.pub == out_pkey_test, false, "derived secret key doesn't match derived public key");

  crypto::generate_key_image(in_ephemeral.pub, in_ephemeral.sec, calculated_key_image);

  index_keyimage_map.emplace(out_index, calculated_key_image);
  m_key_image_cache.emplace(tx_public_key, index_keyimage_map);
  return key_image == calculated_key_image;
}

// Another implementation of transaction creation that is hopefully better
// While there is anything left to pay, it goes through random outputs and tries
// to fill the next destination/amount. If it fully fills it, it will use the
// remainder to try to fill the next one as well.
// The tx size if roughly estimated as a linear function of only inputs, and a
// new tx will be created when that size goes above a given fraction of the
// max tx size. At that point, more outputs may be added if the fee cannot be
// satisfied.
// If the next output in the next tx would go to the same destination (ie, we
// cut off at a tx boundary in the middle of paying a given destination), the
// fee will be carved out of the current input if possible, to avoid having to
// add another output just for the fee and getting change.
// This system allows for sending (almost) the entire balance, since it does
// not generate spurious change in all txes, thus decreasing the instantaneous
// usable balance.
std::vector<wallet2::pending_tx> wallet2::create_transactions_2(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, bool trusted_daemon)
{
	// NOTE: manually redacted
//  if(m_light_wallet) {
//    // Populate m_transfers
//    light_wallet_get_unspent_outs();
//  }
  std::vector<std::pair<uint32_t, std::vector<size_t>>> unused_transfers_indices_per_subaddr;
  std::vector<std::pair<uint32_t, std::vector<size_t>>> unused_dust_indices_per_subaddr;
  uint64_t needed_money;
  uint64_t accumulated_fee, accumulated_outputs, accumulated_change;
  struct TX {
    std::vector<size_t> selected_transfers;
    std::vector<cryptonote::tx_destination_entry> dsts;
    cryptonote::transaction tx;
    pending_tx ptx;
    size_t bytes;
    std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;

    void add(const account_public_address &addr, bool is_subaddress, uint64_t amount, unsigned int original_output_index, bool merge_destinations) {
      if (merge_destinations)
      {
        std::vector<cryptonote::tx_destination_entry>::iterator i;
        i = std::find_if(dsts.begin(), dsts.end(), [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &addr, sizeof(addr)); });
        if (i == dsts.end())
        {
          dsts.push_back(tx_destination_entry(0,addr,is_subaddress));
          i = dsts.end() - 1;
        }
        i->amount += amount;
      }
      else
      {
        THROW_WALLET_EXCEPTION_IF(original_output_index > dsts.size(), error::wallet_internal_error,
            std::string("original_output_index too large: ") + std::to_string(original_output_index) + " > " + std::to_string(dsts.size()));
        if (original_output_index == dsts.size())
          dsts.push_back(tx_destination_entry(0,addr,is_subaddress));
        THROW_WALLET_EXCEPTION_IF(memcmp(&dsts[original_output_index].addr, &addr, sizeof(addr)), error::wallet_internal_error, "Mismatched destination address");
        dsts[original_output_index].amount += amount;
      }
    }
  };
  std::vector<TX> txes;
  bool adding_fee; // true if new outputs go towards fee, rather than destinations
  uint64_t needed_fee, available_for_fee = 0;
  uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit();
  const bool use_rct = use_fork_rules(4, 0);
  const bool bulletproof = use_fork_rules(get_bulletproof_fork(), 0);

  const uint64_t fee_per_kb  = get_per_kb_fee();
  const uint64_t fee_multiplier = get_fee_multiplier(priority, get_fee_algorithm());

  // throw if attempting a transaction with no destinations
  THROW_WALLET_EXCEPTION_IF(dsts.empty(), error::zero_destination);

  // calculate total amount being sent to all destinations
  // throw if total amount overflows uint64_t
  needed_money = 0;
  for(auto& dt: dsts)
  {
    THROW_WALLET_EXCEPTION_IF(0 == dt.amount, error::zero_destination);
    needed_money += dt.amount;
    LOG_PRINT_L2("transfer: adding " << print_money(dt.amount) << ", for a total of " << print_money (needed_money));
    THROW_WALLET_EXCEPTION_IF(needed_money < dt.amount, error::tx_sum_overflow, dsts, 0, m_nettype);
  }

  // throw if attempting a transaction with no money
  THROW_WALLET_EXCEPTION_IF(needed_money == 0, error::zero_destination);

  std::map<uint32_t, uint64_t> unlocked_balance_per_subaddr = unlocked_balance_per_subaddress(subaddr_account);
  std::map<uint32_t, uint64_t> balance_per_subaddr = balance_per_subaddress(subaddr_account);

  if (subaddr_indices.empty()) // "index=<N1>[,<N2>,...]" wasn't specified -> use all the indices with non-zero unlocked balance
  {
    for (const auto& i : balance_per_subaddr)
      subaddr_indices.insert(i.first);
  }

  // early out if we know we can't make it anyway
  // we could also check for being within FEE_PER_KB, but if the fee calculation
  // ever changes, this might be missed, so let this go through
  uint64_t balance_subtotal = 0;
  uint64_t unlocked_balance_subtotal = 0;
  for (uint32_t index_minor : subaddr_indices)
  {
    balance_subtotal += balance_per_subaddr[index_minor];
    unlocked_balance_subtotal += unlocked_balance_per_subaddr[index_minor];
  }
  THROW_WALLET_EXCEPTION_IF(needed_money > balance_subtotal, error::not_enough_money,
    balance_subtotal, needed_money, 0);
  // first check overall balance is enough, then unlocked one, so we throw distinct exceptions
  THROW_WALLET_EXCEPTION_IF(needed_money > unlocked_balance_subtotal, error::not_enough_unlocked_money,
      unlocked_balance_subtotal, needed_money, 0);

  for (uint32_t i : subaddr_indices)
    LOG_PRINT_L2("Candidate subaddress index for spending: " << i);

  // gather all dust and non-dust outputs belonging to specified subaddresses
  size_t num_nondust_outputs = 0;
  size_t num_dust_outputs = 0;
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!td.m_spent && !td.m_key_image_partial && (use_rct ? true : !td.is_rct()) && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && subaddr_indices.count(td.m_subaddr_index.minor) == 1)
    {
      const uint32_t index_minor = td.m_subaddr_index.minor;
      auto find_predicate = [&index_minor](const std::pair<uint32_t, std::vector<size_t>>& x) { return x.first == index_minor; };
      if ((td.is_rct()) || is_valid_decomposed_amount(td.amount()))
      {
        auto found = std::find_if(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), find_predicate);
        if (found == unused_transfers_indices_per_subaddr.end())
        {
          unused_transfers_indices_per_subaddr.push_back({index_minor, {i}});
        }
        else
        {
          found->second.push_back(i);
        }
        ++num_nondust_outputs;
      }
      else
      {
        auto found = std::find_if(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), find_predicate);
        if (found == unused_dust_indices_per_subaddr.end())
        {
          unused_dust_indices_per_subaddr.push_back({index_minor, {i}});
        }
        else
        {
          found->second.push_back(i);
        }
        ++num_dust_outputs;
      }
    }
  }

  // shuffle & sort output indices
  {
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), g);
    std::shuffle(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), g);
    auto sort_predicate = [&unlocked_balance_per_subaddr] (const std::pair<uint32_t, std::vector<size_t>>& x, const std::pair<uint32_t, std::vector<size_t>>& y)
    {
      return unlocked_balance_per_subaddr[x.first] > unlocked_balance_per_subaddr[y.first];
    };
    std::sort(unused_transfers_indices_per_subaddr.begin(), unused_transfers_indices_per_subaddr.end(), sort_predicate);
    std::sort(unused_dust_indices_per_subaddr.begin(), unused_dust_indices_per_subaddr.end(), sort_predicate);
  }

  LOG_PRINT_L2("Starting with " << num_nondust_outputs << " non-dust outputs and " << num_dust_outputs << " dust outputs");

  if (unused_dust_indices_per_subaddr.empty() && unused_transfers_indices_per_subaddr.empty())
    return std::vector<wallet2::pending_tx>();

  // if empty, put dummy entry so that the front can be referenced later in the loop
  if (unused_dust_indices_per_subaddr.empty())
    unused_dust_indices_per_subaddr.push_back({});
  if (unused_transfers_indices_per_subaddr.empty())
    unused_transfers_indices_per_subaddr.push_back({});

  // start with an empty tx
  txes.push_back(TX());
  accumulated_fee = 0;
  accumulated_outputs = 0;
  accumulated_change = 0;
  adding_fee = false;
  needed_fee = 0;
  std::vector<std::vector<tools::wallet2::get_outs_entry>> outs;

  // for rct, since we don't see the amounts, we will try to make all transactions
  // look the same, with 1 or 2 inputs, and 2 outputs. One input is preferable, as
  // this prevents linking to another by provenance analysis, but two is ok if we
  // try to pick outputs not from the same block. We will get two outputs, one for
  // the destination, and one for change.
  LOG_PRINT_L2("checking preferred");
  std::vector<size_t> preferred_inputs;
  uint64_t rct_outs_needed = 2 * (fake_outs_count + 1);
  rct_outs_needed += 100; // some fudge factor since we don't know how many are locked
  if (use_rct)
  {
    // this is used to build a tx that's 1 or 2 inputs, and 2 outputs, which
    // will get us a known fee.
    uint64_t estimated_fee = calculate_fee(fee_per_kb, estimate_rct_tx_size(2, fake_outs_count, 2, extra.size(), bulletproof), fee_multiplier);
    preferred_inputs = pick_preferred_rct_inputs(needed_money + estimated_fee, subaddr_account, subaddr_indices);
    if (!preferred_inputs.empty())
    {
      string s;
      for (auto i: preferred_inputs) s += boost::lexical_cast<std::string>(i) + " (" + print_money(m_transfers[i].amount()) + ") ";
      LOG_PRINT_L1("Found preferred rct inputs for rct tx: " << s);

      // bring the list of available outputs stored by the same subaddress index to the front of the list
      uint32_t index_minor = m_transfers[preferred_inputs[0]].m_subaddr_index.minor;
      for (size_t i = 1; i < unused_transfers_indices_per_subaddr.size(); ++i)
      {
        if (unused_transfers_indices_per_subaddr[i].first == index_minor)
        {
          std::swap(unused_transfers_indices_per_subaddr[0], unused_transfers_indices_per_subaddr[i]);
          break;
        }
      }
      for (size_t i = 1; i < unused_dust_indices_per_subaddr.size(); ++i)
      {
        if (unused_dust_indices_per_subaddr[i].first == index_minor)
        {
          std::swap(unused_dust_indices_per_subaddr[0], unused_dust_indices_per_subaddr[i]);
          break;
        }
      }
    }
  }
  LOG_PRINT_L2("done checking preferred");

  // while:
  // - we have something to send
  // - or we need to gather more fee
  // - or we have just one input in that tx, which is rct (to try and make all/most rct txes 2/2)
  unsigned int original_output_index = 0;
  std::vector<size_t>* unused_transfers_indices = &unused_transfers_indices_per_subaddr[0].second;
  std::vector<size_t>* unused_dust_indices      = &unused_dust_indices_per_subaddr[0].second;
  hw::device &hwdev = m_account.get_device();
  hwdev.set_signature_mode(hw::device::SIGNATURE_FAKE);
  while ((!dsts.empty() && dsts[0].amount > 0) || adding_fee || !preferred_inputs.empty() || should_pick_a_second_output(use_rct, txes.back().selected_transfers.size(), *unused_transfers_indices, *unused_dust_indices)) {
    TX &tx = txes.back();

    LOG_PRINT_L2("Start of loop with " << unused_transfers_indices->size() << " " << unused_dust_indices->size());
    LOG_PRINT_L2("unused_transfers_indices: " << strjoin(*unused_transfers_indices, " "));
    LOG_PRINT_L2("unused_dust_indices: " << strjoin(*unused_dust_indices, " "));
    LOG_PRINT_L2("dsts size " << dsts.size() << ", first " << (dsts.empty() ? "-" : cryptonote::print_money(dsts[0].amount)));
    LOG_PRINT_L2("adding_fee " << adding_fee << ", use_rct " << use_rct);

    // if we need to spend money and don't have any left, we fail
    if (unused_dust_indices->empty() && unused_transfers_indices->empty()) {
      LOG_PRINT_L2("No more outputs to choose from");
      THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance(subaddr_account), needed_money, accumulated_fee + needed_fee);
    }

    // get a random unspent output and use it to pay part (or all) of the current destination (and maybe next one, etc)
    // This could be more clever, but maybe at the cost of making probabilistic inferences easier
    size_t idx;
    if (!preferred_inputs.empty()) {
      idx = pop_back(preferred_inputs);
      pop_if_present(*unused_transfers_indices, idx);
      pop_if_present(*unused_dust_indices, idx);
    } else if ((dsts.empty() || dsts[0].amount == 0) && !adding_fee) {
      // the "make rct txes 2/2" case - we pick a small value output to "clean up" the wallet too
      std::vector<size_t> indices = get_only_rct(*unused_dust_indices, *unused_transfers_indices);
      idx = pop_best_value(indices, tx.selected_transfers, true);

      // we might not want to add it if it's a large output and we don't have many left
      if (m_transfers[idx].amount() >= m_min_output_value) {
        if (get_count_above(m_transfers, *unused_transfers_indices, m_min_output_value) < m_min_output_count) {
          LOG_PRINT_L2("Second output was not strictly needed, and we're running out of outputs above " << print_money(m_min_output_value) << ", not adding");
          break;
        }
      }

      // since we're trying to add a second output which is not strictly needed,
      // we only add it if it's unrelated enough to the first one
      float relatedness = get_output_relatedness(m_transfers[idx], m_transfers[tx.selected_transfers.front()]);
      if (relatedness > SECOND_OUTPUT_RELATEDNESS_THRESHOLD)
      {
        LOG_PRINT_L2("Second output was not strictly needed, and relatedness " << relatedness << ", not adding");
        break;
      }
      pop_if_present(*unused_transfers_indices, idx);
      pop_if_present(*unused_dust_indices, idx);
    } else
      idx = pop_best_value(unused_transfers_indices->empty() ? *unused_dust_indices : *unused_transfers_indices, tx.selected_transfers);

    const transfer_details &td = m_transfers[idx];
    LOG_PRINT_L2("Picking output " << idx << ", amount " << print_money(td.amount()) << ", ki " << td.m_key_image);

    // add this output to the list to spend
    tx.selected_transfers.push_back(idx);
    uint64_t available_amount = td.amount();
    accumulated_outputs += available_amount;

    // clear any fake outs we'd already gathered, since we'll need a new set
    outs.clear();

    if (adding_fee)
    {
      LOG_PRINT_L2("We need more fee, adding it to fee");
      available_for_fee += available_amount;
    }
    else
    {
      while (!dsts.empty() && dsts[0].amount <= available_amount && estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof) < TX_SIZE_TARGET(upper_transaction_size_limit))
      {
        // we can fully pay that destination
        LOG_PRINT_L2("We can fully pay " << get_account_address_as_str(m_nettype, dsts[0].is_subaddress, dsts[0].addr) <<
          " for " << print_money(dsts[0].amount));
        tx.add(dsts[0].addr, dsts[0].is_subaddress, dsts[0].amount, original_output_index, m_merge_destinations);
        available_amount -= dsts[0].amount;
        dsts[0].amount = 0;
        pop_index(dsts, 0);
        ++original_output_index;
      }

      if (available_amount > 0 && !dsts.empty() && estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof) < TX_SIZE_TARGET(upper_transaction_size_limit)) {
        // we can partially fill that destination
        LOG_PRINT_L2("We can partially pay " << get_account_address_as_str(m_nettype, dsts[0].is_subaddress, dsts[0].addr) <<
          " for " << print_money(available_amount) << "/" << print_money(dsts[0].amount));
        tx.add(dsts[0].addr, dsts[0].is_subaddress, available_amount, original_output_index, m_merge_destinations);
        dsts[0].amount -= available_amount;
        available_amount = 0;
      }
    }

    // here, check if we need to sent tx and start a new one
    LOG_PRINT_L2("Considering whether to create a tx now, " << tx.selected_transfers.size() << " inputs, tx limit "
      << upper_transaction_size_limit);
    bool try_tx = false;
    // if we have preferred picks, but haven't yet used all of them, continue
    if (preferred_inputs.empty())
    {
      if (adding_fee)
      {
        /* might not actually be enough if adding this output bumps size to next kB, but we need to try */
        try_tx = available_for_fee >= needed_fee;
      }
      else
      {
        const size_t estimated_rct_tx_size = estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof);
        try_tx = dsts.empty() || (estimated_rct_tx_size >= TX_SIZE_TARGET(upper_transaction_size_limit));
      }
    }

    if (try_tx) {
      cryptonote::transaction test_tx;
      pending_tx test_ptx;

      const size_t estimated_tx_size = estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof);
      needed_fee = calculate_fee(fee_per_kb, estimated_tx_size, fee_multiplier);

      uint64_t inputs = 0, outputs = needed_fee;
      for (size_t idx: tx.selected_transfers) inputs += m_transfers[idx].amount();
      for (const auto &o: tx.dsts) outputs += o.amount;

      if (inputs < outputs)
      {
        LOG_PRINT_L2("We don't have enough for the basic fee, switching to adding_fee");
        adding_fee = true;
        goto skip_tx;
      }

      LOG_PRINT_L2("Trying to create a tx now, with " << tx.dsts.size() << " outputs and " <<
        tx.selected_transfers.size() << " inputs");
      if (use_rct)
        transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
          test_tx, test_ptx, bulletproof);
      else
        transfer_selected(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
          detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx);
      auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
      needed_fee = calculate_fee(fee_per_kb, txBlob, fee_multiplier);
      available_for_fee = test_ptx.fee + test_ptx.change_dts.amount + (!test_ptx.dust_added_to_fee ? test_ptx.dust : 0);
      LOG_PRINT_L2("Made a " << get_size_string(txBlob) << " tx, with " << print_money(available_for_fee) << " available for fee (" <<
        print_money(needed_fee) << " needed)");

      if (needed_fee > available_for_fee && !dsts.empty() && dsts[0].amount > 0)
      {
        // we don't have enough for the fee, but we've only partially paid the current address,
        // so we can take the fee from the paid amount, since we'll have to make another tx anyway
        std::vector<cryptonote::tx_destination_entry>::iterator i;
        i = std::find_if(tx.dsts.begin(), tx.dsts.end(),
          [&](const cryptonote::tx_destination_entry &d) { return !memcmp (&d.addr, &dsts[0].addr, sizeof(dsts[0].addr)); });
        THROW_WALLET_EXCEPTION_IF(i == tx.dsts.end(), error::wallet_internal_error, "paid address not found in outputs");
        if (i->amount > needed_fee)
        {
          uint64_t new_paid_amount = i->amount /*+ test_ptx.fee*/ - needed_fee;
          LOG_PRINT_L2("Adjusting amount paid to " << get_account_address_as_str(m_nettype, i->is_subaddress, i->addr) << " from " <<
            print_money(i->amount) << " to " << print_money(new_paid_amount) << " to accommodate " <<
            print_money(needed_fee) << " fee");
          dsts[0].amount += i->amount - new_paid_amount;
          i->amount = new_paid_amount;
          test_ptx.fee = needed_fee;
          available_for_fee = needed_fee;
        }
      }

      if (needed_fee > available_for_fee)
      {
        LOG_PRINT_L2("We could not make a tx, switching to fee accumulation");

        adding_fee = true;
      }
      else
      {
        LOG_PRINT_L2("We made a tx, adjusting fee and saving it, we need " << print_money(needed_fee) << " and we have " << print_money(test_ptx.fee));
        while (needed_fee > test_ptx.fee) {
          if (use_rct)
            transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
              test_tx, test_ptx, bulletproof);
          else
            transfer_selected(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
              detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx);
          txBlob = t_serializable_object_to_blob(test_ptx.tx);
          needed_fee = calculate_fee(fee_per_kb, txBlob, fee_multiplier);
          LOG_PRINT_L2("Made an attempt at a  final " << get_size_string(txBlob) << " tx, with " << print_money(test_ptx.fee) <<
            " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
        }

        LOG_PRINT_L2("Made a final " << get_size_string(txBlob) << " tx, with " << print_money(test_ptx.fee) <<
          " fee  and " << print_money(test_ptx.change_dts.amount) << " change");

        tx.tx = test_tx;
        tx.ptx = test_ptx;
        tx.bytes = txBlob.size();
        tx.outs = outs;
        accumulated_fee += test_ptx.fee;
        accumulated_change += test_ptx.change_dts.amount;
        adding_fee = false;
        if (!dsts.empty())
        {
          LOG_PRINT_L2("We have more to pay, starting another tx");
          txes.push_back(TX());
          original_output_index = 0;
        }
      }
    }

skip_tx:
    // if unused_*_indices is empty while unused_*_indices_per_subaddr has multiple elements, and if we still have something to pay, 
    // pop front of unused_*_indices_per_subaddr and have unused_*_indices point to the front of unused_*_indices_per_subaddr
    if ((!dsts.empty() && dsts[0].amount > 0) || adding_fee)
    {
      if (unused_transfers_indices->empty() && unused_transfers_indices_per_subaddr.size() > 1)
      {
        unused_transfers_indices_per_subaddr.erase(unused_transfers_indices_per_subaddr.begin());
        unused_transfers_indices = &unused_transfers_indices_per_subaddr[0].second;
      }
      if (unused_dust_indices->empty() && unused_dust_indices_per_subaddr.size() > 1)
      {
        unused_dust_indices_per_subaddr.erase(unused_dust_indices_per_subaddr.begin());
        unused_dust_indices = &unused_dust_indices_per_subaddr[0].second;
      }
    }
  }

  if (adding_fee)
  {
    LOG_PRINT_L1("We ran out of outputs while trying to gather final fee");
    THROW_WALLET_EXCEPTION_IF(1, error::tx_not_possible, unlocked_balance(subaddr_account), needed_money, accumulated_fee + needed_fee);
  }

  LOG_PRINT_L1("Done creating " << txes.size() << " transactions, " << print_money(accumulated_fee) <<
    " total fee, " << print_money(accumulated_change) << " total change");

  hwdev.set_signature_mode(hw::device::SIGNATURE_REAL);
  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    cryptonote::transaction test_tx;
    pending_tx test_ptx;
    if (use_rct) {
      transfer_selected_rct(tx.dsts,                    /* NOMOD std::vector<cryptonote::tx_destination_entry> dsts,*/
                            tx.selected_transfers,      /* const std::list<size_t> selected_transfers */
                            fake_outs_count,            /* CONST size_t fake_outputs_count, */
                            tx.outs,                    /* MOD   std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, */
                            unlock_time,                /* CONST uint64_t unlock_time,  */
                            needed_fee,                 /* CONST uint64_t fee, */
                            extra,                      /* const std::vector<uint8_t>& extra, */
                            test_tx,                    /* OUT   cryptonote::transaction& tx, */
                            test_ptx,                   /* OUT   cryptonote::transaction& tx, */
                            bulletproof);
    } else {
      transfer_selected(tx.dsts,
                        tx.selected_transfers,
                        fake_outs_count,
                        tx.outs,
                        unlock_time,
                        needed_fee,
                        extra,
                        detail::digit_split_strategy,
                        tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD),
                        test_tx,
                        test_ptx);
    }
    auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
    tx.tx = test_tx;
    tx.ptx = test_ptx;
    tx.bytes = txBlob.size();
  }

  std::vector<wallet2::pending_tx> ptx_vector;
  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    uint64_t tx_money = 0;
    for (size_t idx: tx.selected_transfers)
      tx_money += m_transfers[idx].amount();
    LOG_PRINT_L1("  Transaction " << (1+std::distance(txes.begin(), i)) << "/" << txes.size() <<
      ": " << get_size_string(tx.bytes) << ", sending " << print_money(tx_money) << " in " << tx.selected_transfers.size() <<
      " outputs to " << tx.dsts.size() << " destination(s), including " <<
      print_money(tx.ptx.fee) << " fee, " << print_money(tx.ptx.change_dts.amount) << " change");
    ptx_vector.push_back(tx.ptx);
  }

  // if we made it this far, we're OK to actually send the transactions
  return ptx_vector;
}

std::vector<wallet2::pending_tx> wallet2::create_transactions_all(uint64_t below, const cryptonote::account_public_address &address, bool is_subaddress, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, bool trusted_daemon)
{
  std::vector<size_t> unused_transfers_indices;
  std::vector<size_t> unused_dust_indices;
  const bool use_rct = use_fork_rules(4, 0);

  THROW_WALLET_EXCEPTION_IF(unlocked_balance(subaddr_account) == 0, error::wallet_internal_error, "No unlocked balance in the entire wallet");

  std::map<uint32_t, std::pair<std::vector<size_t>, std::vector<size_t>>> unused_transfer_dust_indices_per_subaddr;

  // gather all dust and non-dust outputs of specified subaddress (if any) and below specified threshold (if any)
  bool fund_found = false;
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (!td.m_spent && !td.m_key_image_partial && (use_rct ? true : !td.is_rct()) && is_transfer_unlocked(td) && td.m_subaddr_index.major == subaddr_account && (subaddr_indices.empty() || subaddr_indices.count(td.m_subaddr_index.minor) == 1))
    {
      fund_found = true;
      if (below == 0 || td.amount() < below)
      {
        if ((td.is_rct()) || is_valid_decomposed_amount(td.amount()))
          unused_transfer_dust_indices_per_subaddr[td.m_subaddr_index.minor].first.push_back(i);
        else
          unused_transfer_dust_indices_per_subaddr[td.m_subaddr_index.minor].second.push_back(i);
      }
    }
  }
  THROW_WALLET_EXCEPTION_IF(!fund_found, error::wallet_internal_error, "No unlocked balance in the specified subaddress(es)");
  THROW_WALLET_EXCEPTION_IF(unused_transfer_dust_indices_per_subaddr.empty(), error::wallet_internal_error, "The smallest amount found is not below the specified threshold");

  if (subaddr_indices.empty())
  {
    // in case subaddress index wasn't specified, choose non-empty subaddress randomly (with index=0 being chosen last)
    if (unused_transfer_dust_indices_per_subaddr.count(0) == 1 && unused_transfer_dust_indices_per_subaddr.size() > 1)
      unused_transfer_dust_indices_per_subaddr.erase(0);
    auto i = unused_transfer_dust_indices_per_subaddr.begin();
    std::advance(i, crypto::rand<size_t>() % unused_transfer_dust_indices_per_subaddr.size());
    unused_transfers_indices = i->second.first;
    unused_dust_indices = i->second.second;
    LOG_PRINT_L2("Spending from subaddress index " << i->first);
  }
  else
  {
    for (const auto& p : unused_transfer_dust_indices_per_subaddr)
    {
      unused_transfers_indices.insert(unused_transfers_indices.end(), p.second.first.begin(), p.second.first.end());
      unused_dust_indices.insert(unused_dust_indices.end(), p.second.second.begin(), p.second.second.end());
      LOG_PRINT_L2("Spending from subaddress index " << p.first);
    }
  }

  return create_transactions_from(address, is_subaddress, unused_transfers_indices, unused_dust_indices, fake_outs_count, unlock_time, priority, extra, trusted_daemon);
}

std::vector<wallet2::pending_tx> wallet2::create_transactions_single(const crypto::key_image &ki, const cryptonote::account_public_address &address, bool is_subaddress, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, bool trusted_daemon)
{
  std::vector<size_t> unused_transfers_indices;
  std::vector<size_t> unused_dust_indices;
  const bool use_rct = use_fork_rules(4, 0);
  // find output with the given key image
  for (size_t i = 0; i < m_transfers.size(); ++i)
  {
    const transfer_details& td = m_transfers[i];
    if (td.m_key_image_known && td.m_key_image == ki && !td.m_spent && (use_rct ? true : !td.is_rct()) && is_transfer_unlocked(td))
    {
      if (td.is_rct() || is_valid_decomposed_amount(td.amount()))
        unused_transfers_indices.push_back(i);
      else
        unused_dust_indices.push_back(i);
      break;
    }
  }
  return create_transactions_from(address, is_subaddress, unused_transfers_indices, unused_dust_indices, fake_outs_count, unlock_time, priority, extra, trusted_daemon);
}

std::vector<wallet2::pending_tx> wallet2::create_transactions_from(const cryptonote::account_public_address &address, bool is_subaddress, std::vector<size_t> unused_transfers_indices, std::vector<size_t> unused_dust_indices, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, bool trusted_daemon)
{
  uint64_t accumulated_fee, accumulated_outputs, accumulated_change;
  struct TX {
    std::vector<size_t> selected_transfers;
    std::vector<cryptonote::tx_destination_entry> dsts;
    cryptonote::transaction tx;
    pending_tx ptx;
    size_t bytes;
    std::vector<std::vector<get_outs_entry>> outs;
  };
  std::vector<TX> txes;
  uint64_t needed_fee, available_for_fee = 0;
  uint64_t upper_transaction_size_limit = get_upper_transaction_size_limit();
  std::vector<std::vector<get_outs_entry>> outs;

  const bool use_rct = fake_outs_count > 0 && use_fork_rules(4, 0);
  const bool bulletproof = use_fork_rules(get_bulletproof_fork(), 0);
  const uint64_t fee_per_kb  = get_per_kb_fee();
  const uint64_t fee_multiplier = get_fee_multiplier(priority, get_fee_algorithm());

  LOG_PRINT_L2("Starting with " << unused_transfers_indices.size() << " non-dust outputs and " << unused_dust_indices.size() << " dust outputs");

  if (unused_dust_indices.empty() && unused_transfers_indices.empty())
    return std::vector<wallet2::pending_tx>();

  // start with an empty tx
  txes.push_back(TX());
  accumulated_fee = 0;
  accumulated_outputs = 0;
  accumulated_change = 0;
  needed_fee = 0;

  // while we have something to send
  hw::device &hwdev = m_account.get_device();
  hwdev.set_signature_mode(hw::device::SIGNATURE_FAKE);
  while (!unused_dust_indices.empty() || !unused_transfers_indices.empty()) {
    TX &tx = txes.back();

    // get a random unspent output and use it to pay next chunk. We try to alternate
    // dust and non dust to ensure we never get with only dust, from which we might
    // get a tx that can't pay for itself
    size_t idx = unused_transfers_indices.empty() ? pop_best_value(unused_dust_indices, tx.selected_transfers) : unused_dust_indices.empty() ? pop_best_value(unused_transfers_indices, tx.selected_transfers) : ((tx.selected_transfers.size() & 1) || accumulated_outputs > fee_per_kb * fee_multiplier * (upper_transaction_size_limit + 1023) / 1024) ? pop_best_value(unused_dust_indices, tx.selected_transfers) : pop_best_value(unused_transfers_indices, tx.selected_transfers);

    const transfer_details &td = m_transfers[idx];
    LOG_PRINT_L2("Picking output " << idx << ", amount " << print_money(td.amount()));

    // add this output to the list to spend
    tx.selected_transfers.push_back(idx);
    uint64_t available_amount = td.amount();
    accumulated_outputs += available_amount;

    // clear any fake outs we'd already gathered, since we'll need a new set
    outs.clear();

    // here, check if we need to sent tx and start a new one
    LOG_PRINT_L2("Considering whether to create a tx now, " << tx.selected_transfers.size() << " inputs, tx limit "
      << upper_transaction_size_limit);
    const size_t estimated_rct_tx_size = estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size() + 1, extra.size(), bulletproof);
    bool try_tx = (unused_dust_indices.empty() && unused_transfers_indices.empty()) || ( estimated_rct_tx_size >= TX_SIZE_TARGET(upper_transaction_size_limit));

    if (try_tx) {
      cryptonote::transaction test_tx;
      pending_tx test_ptx;

      const size_t estimated_tx_size = estimate_tx_size(use_rct, tx.selected_transfers.size(), fake_outs_count, tx.dsts.size(), extra.size(), bulletproof);
      needed_fee = calculate_fee(fee_per_kb, estimated_tx_size, fee_multiplier);

      tx.dsts.push_back(tx_destination_entry(1, address, is_subaddress));

      LOG_PRINT_L2("Trying to create a tx now, with " << tx.dsts.size() << " destinations and " <<
        tx.selected_transfers.size() << " outputs");
      if (use_rct)
        transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
          test_tx, test_ptx, bulletproof);
      else
        transfer_selected(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
          detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx);
      auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
      needed_fee = calculate_fee(fee_per_kb, txBlob, fee_multiplier);
      available_for_fee = test_ptx.fee + test_ptx.dests[0].amount + test_ptx.change_dts.amount;
      LOG_PRINT_L2("Made a " << get_size_string(txBlob) << " tx, with " << print_money(available_for_fee) << " available for fee (" <<
        print_money(needed_fee) << " needed)");

      THROW_WALLET_EXCEPTION_IF(needed_fee > available_for_fee, error::wallet_internal_error, "Transaction cannot pay for itself");

      do {
        LOG_PRINT_L2("We made a tx, adjusting fee and saving it");
        tx.dsts[0].amount = available_for_fee - needed_fee;
        if (use_rct)
          transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra, 
            test_tx, test_ptx, bulletproof);
        else
          transfer_selected(tx.dsts, tx.selected_transfers, fake_outs_count, outs, unlock_time, needed_fee, extra,
            detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx);
        txBlob = t_serializable_object_to_blob(test_ptx.tx);
        needed_fee = calculate_fee(fee_per_kb, txBlob, fee_multiplier);
        LOG_PRINT_L2("Made an attempt at a final " << get_size_string(txBlob) << " tx, with " << print_money(test_ptx.fee) <<
          " fee  and " << print_money(test_ptx.change_dts.amount) << " change");
      } while (needed_fee > test_ptx.fee);

      LOG_PRINT_L2("Made a final " << get_size_string(txBlob) << " tx, with " << print_money(test_ptx.fee) <<
        " fee  and " << print_money(test_ptx.change_dts.amount) << " change");

      tx.tx = test_tx;
      tx.ptx = test_ptx;
      tx.bytes = txBlob.size();
      tx.outs = outs;
      accumulated_fee += test_ptx.fee;
      accumulated_change += test_ptx.change_dts.amount;
      if (!unused_transfers_indices.empty() || !unused_dust_indices.empty())
      {
        LOG_PRINT_L2("We have more to pay, starting another tx");
        txes.push_back(TX());
      }
    }
  }

  LOG_PRINT_L1("Done creating " << txes.size() << " transactions, " << print_money(accumulated_fee) <<
    " total fee, " << print_money(accumulated_change) << " total change");
 
  hwdev.set_signature_mode(hw::device::SIGNATURE_REAL);
  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    cryptonote::transaction test_tx;
    pending_tx test_ptx;
    if (use_rct) {
      transfer_selected_rct(tx.dsts, tx.selected_transfers, fake_outs_count, tx.outs, unlock_time, needed_fee, extra, 
        test_tx, test_ptx, bulletproof);
    } else {
      transfer_selected(tx.dsts, tx.selected_transfers, fake_outs_count, tx.outs, unlock_time, needed_fee, extra,
        detail::digit_split_strategy, tx_dust_policy(::config::DEFAULT_DUST_THRESHOLD), test_tx, test_ptx);
    }
    auto txBlob = t_serializable_object_to_blob(test_ptx.tx);
    tx.tx = test_tx;
    tx.ptx = test_ptx;
    tx.bytes = txBlob.size();
  }

  std::vector<wallet2::pending_tx> ptx_vector;
  for (std::vector<TX>::iterator i = txes.begin(); i != txes.end(); ++i)
  {
    TX &tx = *i;
    uint64_t tx_money = 0;
    for (size_t idx: tx.selected_transfers)
      tx_money += m_transfers[idx].amount();
    LOG_PRINT_L1("  Transaction " << (1+std::distance(txes.begin(), i)) << "/" << txes.size() <<
      ": " << get_size_string(tx.bytes) << ", sending " << print_money(tx_money) << " in " << tx.selected_transfers.size() <<
      " outputs to " << tx.dsts.size() << " destination(s), including " <<
      print_money(tx.ptx.fee) << " fee, " << print_money(tx.ptx.change_dts.amount) << " change");
    ptx_vector.push_back(tx.ptx);
  }

  // if we made it this far, we're OK to actually send the transactions
  return ptx_vector;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::use_fork_rules(uint8_t version, int64_t early_blocks) const
{
  // TODO: How to get fork rule info from light wallet node?
	if(m_light_wallet) {
		// TODO: implement.. need to have the latest lightwallet blockchain height and look up earliest_height for the version requested.. then call monero_fork_rules function
		//
		// This is all temporary:
		if (version >= get_bulletproof_fork()) {
			return false;
		}
		return true;
	}
    
//  uint64_t height, earliest_height;
//  boost::optional<std::string> result = m_node_rpc_proxy.get_height(height);
//  throw_on_rpc_response_error(result, "get_info");
//  result = m_node_rpc_proxy.get_earliest_height(version, earliest_height);
//  throw_on_rpc_response_error(result, "get_hard_fork_info");
//
//  bool close_enough = height >=  earliest_height - early_blocks && earliest_height != std::numeric_limits<uint64_t>::max(); // start using the rules that many blocks beforehand
//  if (close_enough)
//    LOG_PRINT_L2("Using v" << (unsigned)version << " rules");
//  else
//    LOG_PRINT_L2("Not using v" << (unsigned)version << " rules");
//  return close_enough;

	return false;
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_upper_transaction_size_limit() const
{
  if (m_upper_transaction_size_limit > 0)
    return m_upper_transaction_size_limit;
  uint64_t full_reward_zone = use_fork_rules(5, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 : use_fork_rules(2, 10) ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
  return full_reward_zone - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_outputs(const std::function<bool(const transfer_details &td)> &f) const
{
  std::vector<size_t> outputs;
  size_t n = 0;
  for (transfer_container::const_iterator i = m_transfers.begin(); i != m_transfers.end(); ++i, ++n)
  {
    if (i->m_spent)
      continue;
    if (i->m_key_image_partial)
      continue;
    if (!is_transfer_unlocked(*i))
      continue;
    if (f(*i))
      outputs.push_back(n);
  }
  return outputs;
}
//----------------------------------------------------------------------------------------------------
std::vector<uint64_t> wallet2::get_unspent_amounts_vector() const
{
  std::set<uint64_t> set;
  for (const auto &td: m_transfers)
  {
    if (!td.m_spent)
      set.insert(td.is_rct() ? 0 : td.amount());
  }
  std::vector<uint64_t> vector;
  vector.reserve(set.size());
  for (const auto &i: set)
  {
    vector.push_back(i);
  }
  return vector;
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_outputs_from_histogram(uint64_t count, bool atleast, bool unlocked, bool allow_rct, bool trusted_daemon)
{
  cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request req_t = AUTO_VAL_INIT(req_t);
  cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response resp_t = AUTO_VAL_INIT(resp_t);
  m_daemon_rpc_mutex.lock();
  if (trusted_daemon)
    req_t.amounts = get_unspent_amounts_vector();
  req_t.min_count = count;
  req_t.max_count = 0;
  req_t.unlocked = unlocked;
  bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_output_histogram", req_t, resp_t, m_http_client, rpc_timeout);
  m_daemon_rpc_mutex.unlock();
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "select_available_outputs_from_histogram");
  THROW_WALLET_EXCEPTION_IF(resp_t.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "get_output_histogram");
  THROW_WALLET_EXCEPTION_IF(resp_t.status != CORE_RPC_STATUS_OK, error::get_histogram_error, resp_t.status);

  std::set<uint64_t> mixable;
  for (const auto &i: resp_t.histogram)
  {
    mixable.insert(i.amount);
  }

  return select_available_outputs([mixable, atleast, allow_rct](const transfer_details &td) {
    if (!allow_rct && td.is_rct())
      return false;
    const uint64_t amount = td.is_rct() ? 0 : td.amount();
    if (atleast) {
      if (mixable.find(amount) != mixable.end())
        return true;
    }
    else {
      if (mixable.find(amount) == mixable.end())
        return true;
    }
    return false;
  });
}
//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_num_rct_outputs()
{
  cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::request req_t = AUTO_VAL_INIT(req_t);
  cryptonote::COMMAND_RPC_GET_OUTPUT_HISTOGRAM::response resp_t = AUTO_VAL_INIT(resp_t);
  m_daemon_rpc_mutex.lock();
  req_t.amounts.push_back(0);
  req_t.min_count = 0;
  req_t.max_count = 0;
  bool r = net_utils::invoke_http_json_rpc("/json_rpc", "get_output_histogram", req_t, resp_t, m_http_client, rpc_timeout);
  m_daemon_rpc_mutex.unlock();
  THROW_WALLET_EXCEPTION_IF(!r, error::no_connection_to_daemon, "get_num_rct_outputs");
  THROW_WALLET_EXCEPTION_IF(resp_t.status == CORE_RPC_STATUS_BUSY, error::daemon_busy, "get_output_histogram");
  THROW_WALLET_EXCEPTION_IF(resp_t.status != CORE_RPC_STATUS_OK, error::get_histogram_error, resp_t.status);
  THROW_WALLET_EXCEPTION_IF(resp_t.histogram.size() != 1, error::get_histogram_error, "Expected exactly one response");
  THROW_WALLET_EXCEPTION_IF(resp_t.histogram[0].amount != 0, error::get_histogram_error, "Expected 0 amount");

  return resp_t.histogram[0].total_instances;
}
//----------------------------------------------------------------------------------------------------
const wallet2::transfer_details &wallet2::get_transfer_details(size_t idx) const
{
  THROW_WALLET_EXCEPTION_IF(idx >= m_transfers.size(), error::wallet_internal_error, "Bad transfer index");
  return m_transfers[idx];
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_unmixable_outputs(bool trusted_daemon)
{
  // request all outputs with less than 3 instances
  const size_t min_mixin = use_fork_rules(6, 10) ? 4 : 2; // v6 increases min mixin from 2 to 4
  return select_available_outputs_from_histogram(min_mixin + 1, false, true, false, trusted_daemon);
}
//----------------------------------------------------------------------------------------------------
std::vector<size_t> wallet2::select_available_mixable_outputs(bool trusted_daemon)
{
  // request all outputs with at least 3 instances, so we can use mixin 2 with
  const size_t min_mixin = use_fork_rules(6, 10) ? 4 : 2; // v6 increases min mixin from 2 to 4
  return select_available_outputs_from_histogram(min_mixin + 1, true, true, true, trusted_daemon);
}
//----------------------------------------------------------------------------------------------------
std::vector<wallet2::pending_tx> wallet2::create_unmixable_sweep_transactions(bool trusted_daemon)
{
  // From hard fork 1, we don't consider small amounts to be dust anymore
  const bool hf1_rules = use_fork_rules(2, 10); // first hard fork has version 2
  tx_dust_policy dust_policy(hf1_rules ? 0 : ::config::DEFAULT_DUST_THRESHOLD);

  const uint64_t fee_per_kb  = get_per_kb_fee();

  // may throw
  std::vector<size_t> unmixable_outputs = select_available_unmixable_outputs(trusted_daemon);
  size_t num_dust_outputs = unmixable_outputs.size();

  if (num_dust_outputs == 0)
  {
    return std::vector<wallet2::pending_tx>();
  }

  // split in "dust" and "non dust" to make it easier to select outputs
  std::vector<size_t> unmixable_transfer_outputs, unmixable_dust_outputs;
  for (auto n: unmixable_outputs)
  {
    if (m_transfers[n].amount() < fee_per_kb)
      unmixable_dust_outputs.push_back(n);
    else
      unmixable_transfer_outputs.push_back(n);
  }

  return create_transactions_from(m_account_public_address, false, unmixable_transfer_outputs, unmixable_dust_outputs, 0 /*fake_outs_count */, 0 /* unlock_time */, 1 /*priority */, std::vector<uint8_t>(), trusted_daemon);
}

const std::pair<std::map<std::string, std::string>, std::vector<std::string>>& wallet2::get_account_tags()
{
  // ensure consistency
  if (m_account_tags.second.size() != get_num_subaddress_accounts())
    m_account_tags.second.resize(get_num_subaddress_accounts(), "");
  for (const std::string& tag : m_account_tags.second)
  {
    if (!tag.empty() && m_account_tags.first.count(tag) == 0)
      m_account_tags.first.insert({tag, ""});
  }
  for (auto i = m_account_tags.first.begin(); i != m_account_tags.first.end(); )
  {
    if (std::find(m_account_tags.second.begin(), m_account_tags.second.end(), i->first) == m_account_tags.second.end())
      i = m_account_tags.first.erase(i);
    else
      ++i;
  }
  return m_account_tags;
}

void wallet2::set_account_tag(const std::set<uint32_t> account_indices, const std::string& tag)
{
  for (uint32_t account_index : account_indices)
  {
    THROW_WALLET_EXCEPTION_IF(account_index >= get_num_subaddress_accounts(), error::wallet_internal_error, "Account index out of bound");
    if (m_account_tags.second[account_index] == tag)
      MDEBUG("This tag is already assigned to this account");
    else
      m_account_tags.second[account_index] = tag;
  }
  get_account_tags();
}

void wallet2::set_account_tag_description(const std::string& tag, const std::string& description)
{
  THROW_WALLET_EXCEPTION_IF(tag.empty(), error::wallet_internal_error, "Tag must not be empty");
  THROW_WALLET_EXCEPTION_IF(m_account_tags.first.count(tag) == 0, error::wallet_internal_error, "Tag is unregistered");
  m_account_tags.first[tag] = description;
}

std::string wallet2::sign(const std::string &data) const
{
  crypto::hash hash;
  crypto::cn_fast_hash(data.data(), data.size(), hash);
  const cryptonote::account_keys &keys = m_account.get_keys();
  crypto::signature signature;
  crypto::generate_signature(hash, keys.m_account_address.m_spend_public_key, keys.m_spend_secret_key, signature);
  return std::string("SigV1") + tools::base58::encode(std::string((const char *)&signature, sizeof(signature)));
}

//----------------------------------------------------------------------------------------------------
crypto::public_key wallet2::get_tx_pub_key_from_received_outs(const tools::wallet2::transfer_details &td) const
{
  std::vector<tx_extra_field> tx_extra_fields;
  if(!parse_tx_extra(td.m_tx.extra, tx_extra_fields))
  {
    // Extra may only be partially parsed, it's OK if tx_extra_fields contains public key
  }

  // Due to a previous bug, there might be more than one tx pubkey in extra, one being
  // the result of a previously discarded signature.
  // For speed, since scanning for outputs is a slow process, we check whether extra
  // contains more than one pubkey. If not, the first one is returned. If yes, they're
  // checked for whether they yield at least one output
  tx_extra_pub_key pub_key_field;
  THROW_WALLET_EXCEPTION_IF(!find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, 0), error::wallet_internal_error,
      "Public key wasn't found in the transaction extra");
  const crypto::public_key tx_pub_key = pub_key_field.pub_key;
  bool two_found = find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, 1);
  if (!two_found) {
    // easy case, just one found
    return tx_pub_key;
  }

  // more than one, loop and search
  const cryptonote::account_keys& keys = m_account.get_keys();
  size_t pk_index = 0;
  hw::device &hwdev = m_account.get_device();

  const std::vector<crypto::public_key> additional_tx_pub_keys = get_additional_tx_pub_keys_from_extra(td.m_tx);
  std::vector<crypto::key_derivation> additional_derivations;
  for (size_t i = 0; i < additional_tx_pub_keys.size(); ++i)
  {
    additional_derivations.push_back({});
    bool r = hwdev.generate_key_derivation(additional_tx_pub_keys[i], keys.m_view_secret_key, additional_derivations.back());
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");
  }

  while (find_tx_extra_field_by_type(tx_extra_fields, pub_key_field, pk_index++)) {
    const crypto::public_key tx_pub_key = pub_key_field.pub_key;
    crypto::key_derivation derivation;
    bool r = hwdev.generate_key_derivation(tx_pub_key, keys.m_view_secret_key, derivation);
    THROW_WALLET_EXCEPTION_IF(!r, error::wallet_internal_error, "Failed to generate key derivation");

    for (size_t i = 0; i < td.m_tx.vout.size(); ++i)
    {
      tx_scan_info_t tx_scan_info;
      check_acc_out_precomp(td.m_tx.vout[i], derivation, additional_derivations, i, tx_scan_info);
      if (!tx_scan_info.error && tx_scan_info.received)
        return tx_pub_key;
    }
  }

  // we found no key yielding an output
  THROW_WALLET_EXCEPTION_IF(true, error::wallet_internal_error,
      "Public key yielding at least one output wasn't found in the transaction extra");
  return crypto::null_pkey;
}

	
	
//----------------------------------------------------------------------------------------------------
std::string wallet2::make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const
{
  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype(), address))
  {
    error = std::string("wrong address: ") + address;
    return std::string();
  }

  // we want only one payment id
  if (info.has_payment_id && !payment_id.empty())
  {
    error = "A single payment id is allowed";
    return std::string();
  }

  if (!payment_id.empty())
  {
    crypto::hash pid32;
    crypto::hash8 pid8;
    if (!wallet2::parse_long_payment_id(payment_id, pid32) && !wallet2::parse_short_payment_id(payment_id, pid8))
    {
      error = "Invalid payment id";
      return std::string();
    }
  }

  std::string uri = "monero:" + address;
  unsigned int n_fields = 0;

  if (!payment_id.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("tx_payment_id=") + payment_id;
  }

  if (amount > 0)
  {
    // URI encoded amount is in decimal units, not atomic units
    uri += (n_fields++ ? "&" : "?") + std::string("tx_amount=") + cryptonote::print_money(amount);
  }

  if (!recipient_name.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("recipient_name=") + epee::net_utils::conver_to_url_format(recipient_name);
  }

  if (!tx_description.empty())
  {
    uri += (n_fields++ ? "&" : "?") + std::string("tx_description=") + epee::net_utils::conver_to_url_format(tx_description);
  }

  return uri;
}
//----------------------------------------------------------------------------------------------------
bool wallet2::parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error)
{
  if (uri.substr(0, 7) != "monero:")
  {
    error = std::string("URI has wrong scheme (expected \"monero:\"): ") + uri;
    return false;
  }

  std::string remainder = uri.substr(7);
  const char *ptr = strchr(remainder.c_str(), '?');
  address = ptr ? remainder.substr(0, ptr-remainder.c_str()) : remainder;

  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, nettype(), address))
  {
    error = std::string("URI has wrong address: ") + address;
    return false;
  }
  if (!strchr(remainder.c_str(), '?'))
    return true;

  std::vector<std::string> arguments;
  std::string body = remainder.substr(address.size() + 1);
  if (body.empty())
    return true;
  boost::split(arguments, body, boost::is_any_of("&"));
  std::set<std::string> have_arg;
  for (const auto &arg: arguments)
  {
    std::vector<std::string> kv;
    boost::split(kv, arg, boost::is_any_of("="));
    if (kv.size() != 2)
    {
      error = std::string("URI has wrong parameter: ") + arg;
      return false;
    }
    if (have_arg.find(kv[0]) != have_arg.end())
    {
      error = std::string("URI has more than one instance of " + kv[0]);
      return false;
    }
    have_arg.insert(kv[0]);

    if (kv[0] == "tx_amount")
    {
      amount = 0;
      if (!cryptonote::parse_amount(amount, kv[1]))
      {
        error = std::string("URI has invalid amount: ") + kv[1];
        return false;
      }
    }
    else if (kv[0] == "tx_payment_id")
    {
      if (info.has_payment_id)
      {
        error = "Separate payment id given with an integrated address";
        return false;
      }
      crypto::hash hash;
      crypto::hash8 hash8;
      if (!wallet2::parse_long_payment_id(kv[1], hash) && !wallet2::parse_short_payment_id(kv[1], hash8))
      {
        error = "Invalid payment id: " + kv[1];
        return false;
      }
      payment_id = kv[1];
    }
    else if (kv[0] == "recipient_name")
    {
      recipient_name = epee::net_utils::convert_from_url_format(kv[1]);
    }
    else if (kv[0] == "tx_description")
    {
      tx_description = epee::net_utils::convert_from_url_format(kv[1]);
    }
    else
    {
      unknown_parameters.push_back(arg);
    }
  }
  return true;
}

//----------------------------------------------------------------------------------------------------
uint64_t wallet2::get_segregation_fork_height() const
{
  if (m_nettype == TESTNET)
    return TESTNET_SEGREGATION_FORK_HEIGHT;
  if (m_nettype == STAGENET)
    return STAGENET_SEGREGATION_FORK_HEIGHT;
  THROW_WALLET_EXCEPTION_IF(m_nettype != MAINNET, tools::error::wallet_internal_error, "Invalid network type");

  if (m_segregation_height > 0)
    return m_segregation_height;

  static const bool use_dns = true;
  if (use_dns)
  {
    // All four MoneroPulse domains have DNSSEC on and valid
    static const std::vector<std::string> dns_urls = {
        "segheights.moneropulse.org",
        "segheights.moneropulse.net",
        "segheights.moneropulse.co",
        "segheights.moneropulse.se"
    };

    const uint64_t current_height = get_blockchain_current_height();
    uint64_t best_diff = std::numeric_limits<uint64_t>::max(), best_height = 0;
    std::vector<std::string> records;
    if (tools::dns_utils::load_txt_records_from_dns(records, dns_urls))
    {
      for (const auto& record : records)
      {
        std::vector<std::string> fields;
        boost::split(fields, record, boost::is_any_of(":"));
        if (fields.size() != 2)
          continue;
        uint64_t height;
        if (!string_tools::get_xtype_from_string(height, fields[1]))
          continue;

        MINFO("Found segregation height via DNS: " << fields[0] << " fork height at " << height);
        uint64_t diff = height > current_height ? height - current_height : current_height - height;
        if (diff < best_diff)
        {
          best_diff = diff;
          best_height = height;
        }
      }
      if (best_height)
        return best_height;
    }
  }
  return SEGREGATION_FORK_HEIGHT;
}
//----------------------------------------------------------------------------------------------------
void wallet2::generate_genesis(cryptonote::block& b) const {
  if (m_nettype == TESTNET)
  {
    cryptonote::generate_genesis_block(b, config::testnet::GENESIS_TX, config::testnet::GENESIS_NONCE);
  }
  else if (m_nettype == STAGENET)
  {
    cryptonote::generate_genesis_block(b, config::stagenet::GENESIS_TX, config::stagenet::GENESIS_NONCE);
  }
  else
  {
    cryptonote::generate_genesis_block(b, config::GENESIS_TX, config::GENESIS_NONCE);
  }
}
}
