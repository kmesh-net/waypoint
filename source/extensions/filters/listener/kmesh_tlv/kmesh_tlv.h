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

#pragma once

#include "envoy/network/filter.h"
#include "envoy/stream_info/filter_state.h"

#include "source/common/common/logger.h"

namespace Envoy {
namespace Extensions {
namespace ListenerFilters {
namespace KmeshTlv {

enum class ReadOrParseState { Done, TryAgainLater, Error, SkipFilter };

// The length of tlv type field.
constexpr uint8_t TLV_TYPE_LEN = 0x1;
// The length of tlv length field.
constexpr uint8_t TLV_LENGTH_LEN = 0x4;
// If tlv type field is `0x1`, then this tlv will include service address.
constexpr uint8_t TLV_TYPE_SERVICE_ADDRESS = 0x1;
// If tlv type field is `0xfe`, then it is the last
// tlv, after that will be payload data.
constexpr uint8_t TLV_TYPE_ENDING = 0xfe;
// If tvl type field is `0xff`, then this tlv will embed
// many sub tlvs.
constexpr uint8_t TLV_TYPE_EXTENSION = 0xff;
// If tlv type is service, for ipv4 address, the content length is 6
// (ip addr is 4 bytes and port is 2 bytes), for ipv6 address, the content
// length is 18 (ip addr is 16 bytes and port is 2 bytes).
constexpr uint8_t TLV_TYPE_SERVICE_ADDRESS_IPV4_LEN = 0x6;
constexpr uint8_t TLV_TYPE_SERVICE_ADDRESS_IPV6_LEN = 0x12;

enum TlvParseState { TypeAndLength = 0, Content = 1 };

/**
 * Implementation of a kmesh tlv listener filter.
 */
class KmeshTlvFilter : public Network::ListenerFilter, Logger::Loggable<Logger::Id::filter> {
public:
  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks& cb) override;

  size_t maxReadBytes() const override { return max_kmesh_tlv_len_; }

  Network::FilterStatus onData(Network::ListenerFilterBuffer&) override;

private:
  ReadOrParseState parseBuffer(Network::ListenerFilterBuffer& buffer);
  // TODO: set max length properly.
  static const size_t MAX_KMESH_TLV_LEN = 256;

  Network::ListenerFilterCallbacks* cb_{};

  TlvParseState state_{TypeAndLength};

  uint32_t expected_length_{TLV_TYPE_LEN + TLV_LENGTH_LEN};

  uint32_t index_{0};

  uint32_t content_length_{0};

  uint32_t max_kmesh_tlv_len_{MAX_KMESH_TLV_LEN};
};

} // namespace KmeshTlv
} // namespace ListenerFilters
} // namespace Extensions
} // namespace Envoy
