//
//  full_wallet3.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 2/21/18.
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

#include "full_wallet3.hpp"
#include "include_base_utils.h"
#include "monero_transfer_utils.hpp"
#include "monero_fork_rules.hpp"
#include <random>

using namespace epee;
using namespace tools;
using namespace crypto;
using namespace cryptonote;


full_wallet3::full_wallet3(bool testnet, bool restricted)
	: wallet3_base::wallet3_base(testnet, restricted)
	// TODO
//	, m_node_rpc_proxy(m_http_client, m_daemon_rpc_mutex)
	// TODO
{
}
//
//
uint64_t full_wallet3::get_dynamic_per_kb_fee_estimate() const
{
// TODO
	return FEE_PER_KB;
}
bool full_wallet3::use_fork_rules(uint8_t version, int64_t early_blocks) const
{
	return monero_fork_rules::use_fork_rules(
		version,
		early_blocks,
		node_rpc_proxy__get_height(),
		node_rpc_proxy__get_earliest_height(version)
	);
}
//
uint64_t full_wallet3::node_rpc_proxy__get_height() const
{
//	uint64_t height;
//	boost::optional<std::string> result = m_node_rpc_proxy.get_height(height);
	// TODO: include
//	throw_on_rpc_response_error(result, "get_info");
	//
	return 0; // TODO height;
}
uint64_t full_wallet3::node_rpc_proxy__get_earliest_height(uint8_t version) const
{
//	uint64_t earliest_height;
//	boost::optional<std::string> result = m_node_rpc_proxy.get_earliest_height(version, earliest_height);
	// TODO: include
//	throw_on_rpc_response_error(result, "get_hard_fork_info");
	//
	return 0; // TODO earliest_height;
}
