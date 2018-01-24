//
//  light_wallet3_server_api.h
//  MyMonero
//
//  Created by Paul Shapiro on 1/24/18.
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


#pragma once

#include <iostream>
#include <boost/date_time.hpp>

namespace light_wallet3_server_api
{
	using namespace boost::posix_time;
	
	const std::locale server_api_timestamp_formats[] =
	{
		std::locale(std::locale::classic(),new time_input_facet("%Y-%m-%dT%H:%M:%S"))
	};
	const size_t server_api_timestamp_formats__n = sizeof(server_api_timestamp_formats)/sizeof(server_api_timestamp_formats[0]);
	
	static inline std::time_t pt_to_time_t(const ptime& pt)
	{
		ptime timet_start(boost::gregorian::date(1970,1,1));
		time_duration diff = pt - timet_start;
		//
		return diff.ticks() / time_duration::rep_type::ticks_per_second;
	}
	static inline time_t epoch_time_by_parsing_date_string(const std::string& s)
	{
		ptime pt;
		for (size_t i = 0; i < server_api_timestamp_formats__n; ++i) {
			std::istringstream is(s);
			is.imbue(server_api_timestamp_formats[i]);
			is >> pt;
			if (pt != ptime()) {
				break;
			}
		}
		return pt_to_time_t(pt);
	}
	//
	//
	//-----------------------------------------------
	struct COMMAND_RPC_GET_ADDRESS_TXS
	{
		struct request
		{
			std::string address;
			std::string view_key;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(address)
			KV_SERIALIZE(view_key)
			END_KV_SERIALIZE_MAP()
		};
		
		struct spent_output {
			uint64_t amount;
			std::string key_image;
			std::string tx_pub_key;
			uint64_t out_index;
			uint32_t mixin;
			
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(amount)
			KV_SERIALIZE(key_image)
			KV_SERIALIZE(tx_pub_key)
			KV_SERIALIZE(out_index)
			KV_SERIALIZE(mixin)
			END_KV_SERIALIZE_MAP()
		};
		
		struct transaction
		{
			uint64_t id;
			std::string hash;
			std::string timestamp;
			uint64_t total_received;
			uint64_t total_sent;
			uint64_t unlock_time;
			uint64_t height;
			std::list<spent_output> spent_outputs;
			std::string payment_id;
			bool coinbase;
			bool mempool;
			uint32_t mixin;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(id)
			KV_SERIALIZE(hash)
			KV_SERIALIZE(timestamp)
			KV_SERIALIZE(total_received)
			KV_SERIALIZE(total_sent)
			KV_SERIALIZE(unlock_time)
			KV_SERIALIZE(height)
			KV_SERIALIZE(spent_outputs)
			KV_SERIALIZE(payment_id)
			KV_SERIALIZE(coinbase)
			KV_SERIALIZE(mempool)
			KV_SERIALIZE(mixin)
			END_KV_SERIALIZE_MAP()
		};
		
		
		struct response
		{
			//std::list<std::string> txs_as_json;
			uint64_t total_received;
			uint64_t total_received_unlocked = 0; // OpenMonero only
			uint64_t scanned_height;
			std::list<transaction> transactions;
			uint64_t blockchain_height;
			uint64_t scanned_block_height;
			std::string status;
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(total_received)
			KV_SERIALIZE(total_received_unlocked)
			KV_SERIALIZE(scanned_height)
			KV_SERIALIZE(transactions)
			KV_SERIALIZE(blockchain_height)
			KV_SERIALIZE(scanned_block_height)
			KV_SERIALIZE(status)
			END_KV_SERIALIZE_MAP()
		};
	};
	
	//-----------------------------------------------
	struct COMMAND_RPC_GET_ADDRESS_INFO
	{
		struct request
		{
			std::string address;
			std::string view_key;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(address)
			KV_SERIALIZE(view_key)
			END_KV_SERIALIZE_MAP()
		};
		
		struct spent_output
		{
			uint64_t amount;
			std::string key_image;
			std::string tx_pub_key;
			uint64_t  out_index;
			uint32_t  mixin;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(amount)
			KV_SERIALIZE(key_image)
			KV_SERIALIZE(tx_pub_key)
			KV_SERIALIZE(out_index)
			KV_SERIALIZE(mixin)
			END_KV_SERIALIZE_MAP()
		};
		
		
		
		struct response
		{
			uint64_t locked_funds;
			uint64_t total_received;
			uint64_t total_sent;
			uint64_t scanned_height;
			uint64_t scanned_block_height;
			uint64_t start_height;
			uint64_t transaction_height;
			uint64_t blockchain_height;
			std::list<spent_output> spent_outputs;
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(locked_funds)
			KV_SERIALIZE(total_received)
			KV_SERIALIZE(total_sent)
			KV_SERIALIZE(scanned_height)
			KV_SERIALIZE(scanned_block_height)
			KV_SERIALIZE(start_height)
			KV_SERIALIZE(transaction_height)
			KV_SERIALIZE(blockchain_height)
			KV_SERIALIZE(spent_outputs)
			END_KV_SERIALIZE_MAP()
		};
	};
	
	//-----------------------------------------------
	struct COMMAND_RPC_GET_UNSPENT_OUTS
	{
		struct request
		{
			std::string amount;
			std::string address;
			std::string view_key;
			// OpenMonero specific
			uint64_t mixin;
			bool use_dust;
			std::string dust_threshold;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(amount)
			KV_SERIALIZE(address)
			KV_SERIALIZE(view_key)
			KV_SERIALIZE(mixin)
			KV_SERIALIZE(use_dust)
			KV_SERIALIZE(dust_threshold)
			END_KV_SERIALIZE_MAP()
		};
		
		
		struct output {
			uint64_t amount;
			std::string public_key;
			uint64_t  index;
			uint64_t global_index;
			std::string rct;
			std::string tx_hash;
			std::string tx_pub_key;
			std::string tx_prefix_hash;
			std::vector<std::string> spend_key_images;
			uint64_t timestamp;
			uint64_t height;
			
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(amount)
			KV_SERIALIZE(public_key)
			KV_SERIALIZE(index)
			KV_SERIALIZE(global_index)
			KV_SERIALIZE(rct)
			KV_SERIALIZE(tx_hash)
			KV_SERIALIZE(tx_pub_key)
			KV_SERIALIZE(tx_prefix_hash)
			KV_SERIALIZE(spend_key_images)
			KV_SERIALIZE(timestamp)
			KV_SERIALIZE(height)
			END_KV_SERIALIZE_MAP()
		};
		
		struct response
		{
			uint64_t amount;
			std::list<output> outputs;
			uint64_t per_kb_fee;
			std::string status;
			std::string reason;
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(amount)
			KV_SERIALIZE(outputs)
			KV_SERIALIZE(per_kb_fee)
			KV_SERIALIZE(status)
			KV_SERIALIZE(reason)
			END_KV_SERIALIZE_MAP()
		};
	};
	
	//-----------------------------------------------
	struct COMMAND_RPC_GET_RANDOM_OUTS
	{
		struct request
		{
			std::vector<std::string> amounts;
			uint32_t count;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(amounts)
			KV_SERIALIZE(count)
			END_KV_SERIALIZE_MAP()
		};
		
		
		struct output {
			std::string public_key;
			uint64_t global_index;
			std::string rct; // 64+64+64 characters long (<rct commit> + <encrypted mask> + <rct amount>)
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(public_key)
			KV_SERIALIZE(global_index)
			KV_SERIALIZE(rct)
			END_KV_SERIALIZE_MAP()
		};
		
		struct amount_out {
			uint64_t amount;
			std::vector<output> outputs;
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(amount)
			KV_SERIALIZE(outputs)
			END_KV_SERIALIZE_MAP()
			
		};
		
		struct response
		{
			std::vector<amount_out> amount_outs;
			std::string Error;
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(amount_outs)
			KV_SERIALIZE(Error)
			END_KV_SERIALIZE_MAP()
		};
	};
	//-----------------------------------------------
	struct COMMAND_RPC_SUBMIT_RAW_TX
	{
		struct request
		{
			std::string address;
			std::string view_key;
			std::string tx;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(address)
			KV_SERIALIZE(view_key)
			KV_SERIALIZE(tx)
			END_KV_SERIALIZE_MAP()
		};
		
		
		struct response
		{
			std::string status;
			std::string error;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(status)
			KV_SERIALIZE(error)
			END_KV_SERIALIZE_MAP()
		};
	};
	//-----------------------------------------------
	struct COMMAND_RPC_LOGIN
	{
		struct request
		{
			std::string address;
			std::string view_key;
			bool create_account;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(address)
			KV_SERIALIZE(view_key)
			KV_SERIALIZE(create_account)
			END_KV_SERIALIZE_MAP()
		};
		
		
		struct response
		{
			std::string status;
			std::string reason;
			bool new_address;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(status)
			KV_SERIALIZE(reason)
			KV_SERIALIZE(new_address)
			END_KV_SERIALIZE_MAP()
		};
	};
	//-----------------------------------------------
	struct COMMAND_RPC_IMPORT_WALLET_REQUEST
	{
		struct request
		{
			std::string address;
			std::string view_key;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(address)
			KV_SERIALIZE(view_key)
			END_KV_SERIALIZE_MAP()
		};
		
		
		struct response
		{
			std::string payment_id;
			uint64_t import_fee;
			bool new_request;
			bool request_fulfilled;
			std::string payment_address;
			std::string status;
			
			BEGIN_KV_SERIALIZE_MAP()
			KV_SERIALIZE(payment_id)
			KV_SERIALIZE(import_fee)
			KV_SERIALIZE(new_request)
			KV_SERIALIZE(request_fulfilled)
			KV_SERIALIZE(payment_address)
			KV_SERIALIZE(status)
			END_KV_SERIALIZE_MAP()
		};
	};
};
