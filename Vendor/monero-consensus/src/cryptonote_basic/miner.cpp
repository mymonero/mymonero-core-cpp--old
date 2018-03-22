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

#include <sstream>
#include <numeric>
#include <boost/utility/value_init.hpp>
#include <boost/interprocess/detail/atomic.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/limits.hpp>
#include "include_base_utils.h"
#include "misc_language.h"
#include "syncobj.h"
#include "cryptonote_basic_impl.h"
#include "cryptonote_format_utils.h"
#include "file_io_utils.h"
#include "common/command_line.h"
#include "string_coding.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h"
#include "boost/logic/tribool.hpp"

#ifdef __FreeBSD__
#include <devstat.h>
#include <errno.h>
#include <fcntl.h>
#include <machine/apm_bios.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/sysctl.h>
#include <sys/times.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "miner"

using namespace epee;

#include "miner.h"


extern "C" void slow_hash_allocate_state();
extern "C" void slow_hash_free_state();
namespace cryptonote
{


  miner::miner(i_miner_handler* phandler):m_stop(1),
    m_template(boost::value_initialized<block>()),
    m_template_no(0),
    m_diffic(0),
    m_thread_index(0),
    m_phandler(phandler),
    m_height(0),
    m_pausers_count(0),
    m_threads_total(0),
    m_starter_nonce(0),
    m_last_hr_merge_time(0),
    m_hashes(0),
    m_do_print_hashrate(false),
    m_do_mining(false),
    m_current_hash_rate(0),
    m_is_background_mining_enabled(false),
    m_min_idle_seconds(BACKGROUND_MINING_DEFAULT_MIN_IDLE_INTERVAL_IN_SECONDS),
    m_idle_threshold(BACKGROUND_MINING_DEFAULT_IDLE_THRESHOLD_PERCENTAGE),
    m_mining_target(BACKGROUND_MINING_DEFAULT_MINING_TARGET_PERCENTAGE),
    m_miner_extra_sleep(BACKGROUND_MINING_DEFAULT_MINER_EXTRA_SLEEP_MILLIS)
  {

  }
  //-----------------------------------------------------------------------------------------------------
  miner::~miner()
  {

  }

  //-----------------------------------------------------------------------------------------------------
  bool miner::find_nonce_for_given_block(block& bl, const difficulty_type& diffic, uint64_t height)
  {
    for(; bl.nonce != std::numeric_limits<uint32_t>::max(); bl.nonce++)
    {
      crypto::hash h;
      get_block_longhash(bl, h, height);

      if(check_hash(h, diffic))
      {
        bl.invalidate_hashes();
        return true;
      }
    }
    bl.invalidate_hashes();
    return false;
  }

}
