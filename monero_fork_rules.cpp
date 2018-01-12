//
//  monero_fork_rules.cpp
//  MyMonero
//
//  Created by Paul Shapiro on 1/9/18.
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
//
#include "monero_fork_rules.hpp"
//
using namespace monero_fork_rules;
//
bool monero_fork_rules::use_fork_rules(uint8_t version, int64_t early_blocks, bool is_light_wallet, uint64_t rpc_proxy_height, uint64_t rpc_proxy_earliest_height)
{
	// TODO: How to get fork rule info from light wallet node?
	if(is_light_wallet)
		return true;
	bool close_enough = rpc_proxy_height >= rpc_proxy_earliest_height - early_blocks; // start using the rules that many blocks beforehand
//	if (close_enough)
//		LOG_PRINT_L2("Using v" << (unsigned)version << " rules");
//	else
//		LOG_PRINT_L2("Not using v" << (unsigned)version << " rules");
	return close_enough;
}

uint8_t monero_fork_rules::get_bulletproof_fork(bool is_testnet)
{
	if (is_testnet)
		return 7;
	else
		return 255; // TODO
}
