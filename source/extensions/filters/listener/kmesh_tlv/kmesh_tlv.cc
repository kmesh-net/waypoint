/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "kmesh_tlv.h"

#include "source/common/network/address_impl.h"
#include "source/common/network/utility.h"
#include "source/common/network/filter_state_dst_address.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace KmeshTlv {

Network::FilterStatus KmeshTlvFilter::onAccept(Network::ListenerFilterCallbacks& cb) {
  ENVOY_LOG(trace, "kmesh_tlv: new connection accepted");
  cb_ = &cb;
  // Waiting for data.
  return Network::FilterStatus::StopIteration;
}

Network::FilterStatus KmeshTlvFilter::onData(Network::ListenerFilterBuffer& buffer) {
  const ReadOrParseState read_state = parseBuffer(buffer);
  switch (read_state) {
  case ReadOrParseState::Error:
    cb_->socket().ioHandle().close();
    return Network::FilterStatus::StopIteration;
  case ReadOrParseState::TryAgainLater:
    return Network::FilterStatus::StopIteration;
  case ReadOrParseState::SkipFilter:
    return Network::FilterStatus::Continue;
  case ReadOrParseState::Done:
    return Network::FilterStatus::Continue;
  }
  return Network::FilterStatus::Continue;
}

ReadOrParseState KmeshTlvFilter::parseBuffer(Network::ListenerFilterBuffer& buffer) {
  ENVOY_LOG(trace, "kmesh tlv listener filter parse buffer");

  auto raw_slice = buffer.rawSlice();
  const uint8_t* buf = static_cast<const uint8_t*>(raw_slice.mem_);

  while (raw_slice.len_ >= expected_length_) {
    ENVOY_LOG(trace, "already has {} bytes in the buffer, expected length is {}", raw_slice.len_,
              expected_length_);

    switch (state_) {
    case TlvParseState::TypeAndLength:
      ENVOY_LOG(trace, "tlv parse state is TypeAndLength");

      if (buf[index_] == TLV_TYPE_SERVICE_ADDRESS) {
        ENVOY_LOG(trace, "process TVL_TYPE_SERVICE_ADDRESS");

        uint32_t content_len = 0;
        std::memcpy(&content_len, buf + index_ + 1, TLV_LENGTH_LEN);
        content_len = ntohl(content_len);
        ENVOY_LOG(trace, "get tlv length {}", content_len);

        if (content_len != TLV_TYPE_SERVICE_ADDRESS_IPV4_LEN &&
            content_len != TLV_TYPE_SERVICE_ADDRESS_IPV6_LEN) {
          ENVOY_LOG(error,
                    "the content length of tlv type service address could only be {} for ipv4 "
                    "address or {} for ipv6 address",
                    TLV_TYPE_SERVICE_ADDRESS_IPV4_LEN, TLV_TYPE_SERVICE_ADDRESS_IPV6_LEN);
        }

        expected_length_ += content_len;
        content_length_ = content_len;
        index_ += (TLV_TYPE_LEN + TLV_LENGTH_LEN);
        state_ = TlvParseState::Content;

      } else if (buf[index_] == TLV_TYPE_ENDING) {
        ENVOY_LOG(trace, "process TLV_TYPE_ENDING");

        buffer.drain(expected_length_);

        return ReadOrParseState::Done;
      } else {
        ENVOY_LOG(error, "invalid tlv type {}", buf[index_]);

        return ReadOrParseState::Error;
      }
      break;

    case TlvParseState::Content:
      ENVOY_LOG(trace, "tlv parse state is Content");

      sockaddr_storage addr;
      int len;

      if (content_length_ == TLV_TYPE_SERVICE_ADDRESS_IPV4_LEN) {
        len = sizeof(struct sockaddr_in);
        auto in4 = reinterpret_cast<struct sockaddr_in*>(&addr);
        std::memset(in4, 0, len);
        addr.ss_family = AF_INET;
        std::memcpy(&in4->sin_addr, buf + index_, 4);
        uint16_t port = 0;
        std::memcpy(&port, buf + index_ + 4, 2);
        in4->sin_port = port;
      } else {
        len = sizeof(struct sockaddr_in6);
        auto in6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
        std::memset(in6, 0, len);
        addr.ss_family = AF_INET6;
        std::memcpy(&in6->sin6_addr, buf + index_, 16);
        uint16_t port = 0;
        std::memcpy(&port, buf + index_ + 16, 2);
        in6->sin6_port = port;
      }

      std::string addrString =
          (*Envoy::Network::Address::addressFromSockAddr(addr, len, false))->asString();

      ENVOY_LOG(trace, "original dst addresss is {}", addrString);
      const auto address =
          Network::Utility::parseInternetAddressAndPortNoThrow(addrString, /*v6only=*/false);
      cb_->filterState().setData(
          "envoy.filters.listener.original_dst.local_ip",
          std::make_shared<Network::AddressObject>(address),
          StreamInfo::FilterState::StateType::Mutable,
          StreamInfo::FilterState::LifeSpan::Connection,
          StreamInfo::StreamSharingMayImpactPooling::SharedWithUpstreamConnectionOnce);
      expected_length_ += (TLV_TYPE_LEN + TLV_LENGTH_LEN);
      index_ += content_length_;
      state_ = TlvParseState::TypeAndLength;
    }
  }

  return ReadOrParseState::TryAgainLater;
}

} // namespace KmeshTlv
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy