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

#include <sstream>
#include <numeric>
#include <boost/utility/value_init.hpp>
#include <boost/interprocess/detail/atomic.hpp>
#include <boost/limits.hpp>
#include "misc_language.h"
#include "include_base_utils.h"
#include "cryptonote_basic_impl.h"
#include "cryptonote_format_utils.h"
#include "file_io_utils.h"
#include "common/command_line.h"
#include "string_coding.h"
#include "storages/portable_storage_template_helper.h"
#include "boost/logic/tribool.hpp"

//#ifdef __APPLE__
//  #include <sys/times.h>
//  #include <IOKit/IOKitLib.h>
//  #include <IOKit/ps/IOPSKeys.h>
//  #include <IOKit/ps/IOPowerSources.h>
//  #include <mach/mach_host.h>
//  #include <AvailabilityMacros.h>
//  #include <TargetConditionals.h>
//#endif

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "miner"

using namespace epee;

#include "miner.h"


extern "C" void slow_hash_allocate_state();
extern "C" void slow_hash_free_state();
namespace cryptonote
{

  namespace
  {
    const command_line::arg_descriptor<std::string> arg_extra_messages =  {"extra-messages-file", "Specify file for extra messages to include into coinbase transactions", "", true};
    const command_line::arg_descriptor<std::string> arg_start_mining =    {"start-mining", "Specify wallet address to mining for", "", true};
    const command_line::arg_descriptor<uint32_t>      arg_mining_threads =  {"mining-threads", "Specify mining threads count", 0, true};
    const command_line::arg_descriptor<bool>        arg_bg_mining_enable =  {"bg-mining-enable", "enable/disable background mining", true, true};
    const command_line::arg_descriptor<bool>        arg_bg_mining_ignore_battery =  {"bg-mining-ignore-battery", "if true, assumes plugged in when unable to query system power status", false, true};    
    const command_line::arg_descriptor<uint64_t>    arg_bg_mining_min_idle_interval_seconds =  {"bg-mining-min-idle-interval", "Specify min lookback interval in seconds for determining idle state", miner::BACKGROUND_MINING_DEFAULT_MIN_IDLE_INTERVAL_IN_SECONDS, true};
    const command_line::arg_descriptor<uint16_t>     arg_bg_mining_idle_threshold_percentage =  {"bg-mining-idle-threshold", "Specify minimum avg idle percentage over lookback interval", miner::BACKGROUND_MINING_DEFAULT_IDLE_THRESHOLD_PERCENTAGE, true};
    const command_line::arg_descriptor<uint16_t>     arg_bg_mining_miner_target_percentage =  {"bg-mining-miner-target", "Specificy maximum percentage cpu use by miner(s)", miner::BACKGROUND_MINING_DEFAULT_MINING_TARGET_PERCENTAGE, true};
  }

  //-----------------------------------------------------------------------------------------------------
  miner::~miner()
  {
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_block_template(const block& bl, const difficulty_type& di, uint64_t height)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_block_chain_update()
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::request_block_template()
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_idle()
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::do_print_hashrate(bool do_hr)
  {
	  throw;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::merge_hr()
  {
	  throw;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::init_options(boost::program_options::options_description& desc)
  {
	  throw;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::init(const boost::program_options::variables_map& vm, bool testnet)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::is_mining() const
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  const account_public_address& miner::get_mining_address() const
  {
	  return m_mine_address;
  }
  //-----------------------------------------------------------------------------------------------------
  uint32_t miner::get_threads_count() const {
	  throw;
	  return 0;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::start(const account_public_address& adr, size_t threads_count, const boost::thread::attributes& attrs, bool do_background, bool ignore_battery)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  uint64_t miner::get_speed() const
  {
	  throw;
	  return 0;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::send_stop_signal()
  {
	  throw;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::stop()
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::find_nonce_for_given_block(block& bl, const difficulty_type& diffic, uint64_t height)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::on_synchronized()
  {
	  throw;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::pause()
  {
	  throw;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::resume()
  {
	  throw;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::worker_thread()
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::get_is_background_mining_enabled() const
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::get_ignore_battery() const
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  /**
  * This has differing behaviour depending on if mining has been started/etc.
  * Note: add documentation
  */
  bool miner::set_is_background_mining_enabled(bool is_background_mining_enabled)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::set_ignore_battery(bool ignore_battery)
  {
	  throw;
	  return;
  }
  //-----------------------------------------------------------------------------------------------------
  uint64_t miner::get_min_idle_seconds() const
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_min_idle_seconds(uint64_t min_idle_seconds)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  uint8_t miner::get_idle_threshold() const
  {
	  throw;
	  return 0;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_idle_threshold(uint8_t idle_threshold)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  uint8_t miner::get_mining_target() const
  {
	  throw;
	  return 0;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_mining_target(uint8_t mining_target)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::background_worker_thread()
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::get_system_times(uint64_t& total_time, uint64_t& idle_time)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::get_process_time(uint64_t& total_time)
  {
	  throw;
	  return false;
  }
  //-----------------------------------------------------------------------------------------------------  
  uint8_t miner::get_percent_of_total(uint64_t other, uint64_t total)
  {
	  throw;
	  return 0;
  }
  //-----------------------------------------------------------------------------------------------------    
  boost::logic::tribool miner::on_battery_power()
  {
	  throw;
	  return false;
  }
}
