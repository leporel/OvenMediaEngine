
#include "ice_tcp_demultiplexer.h"
#include "stun/stun_message.h"
#include "stun/channel_data_message.h"
#include "ice_private.h"

bool IceTcpDemultiplexer::AppendData(const void *data, size_t length)
{
	_buffer->Append(data, length);
	return ParseData();
}

bool IceTcpDemultiplexer::AppendData(const std::shared_ptr<const ov::Data> &data)
{
	_buffer->Append(data);
	return ParseData();
}

bool IceTcpDemultiplexer::IsAvailablePacket()
{
	return !_packets.empty();
}

std::shared_ptr<IceTcpDemultiplexer::Packet> IceTcpDemultiplexer::PopPacket()
{
	if(IsAvailablePacket() == false)
	{
		return nullptr;
	}

	auto packet = _packets.front();
	_packets.pop();

	return packet;
}

// Detect connection type from the first packet
// RFC 4571 frames have 2-byte length prefix where the length value typically
// matches STUN message length, while raw STUN/TURN starts with type indicator byte
bool IceTcpDemultiplexer::DetectConnectionType()
{
	if (_buffer->GetLength() < RFC4571_HEADER_SIZE)
	{
		return false;
	}

	auto data = _buffer->GetDataAs<uint8_t>();
	auto first_byte = data[0];

	// RFC 7983 multiplexing: raw STUN starts with 0x00-0x03
	// TURN Channel Data starts with 0x40-0x4F (64-79)
	// RFC 4571: first 2 bytes are big-endian length

	// For RFC 4571, the first byte is high byte of length
	// STUN binding request is typically 20-100+ bytes, so high byte would be 0x00
	// and second byte would be the actual length (e.g., 0x44 for 68 bytes)

	// Check if this looks like RFC 4571 framing:
	// - First byte is 0x00 (high byte of small length)
	// - Second byte could be any value (low byte of length)
	// - After 2-byte prefix, byte at offset 2 should be STUN type indicator (0x00-0x03)

	if (_buffer->GetLength() >= RFC4571_HEADER_SIZE + 1)
	{
		auto third_byte = data[2];  // First byte after RFC 4571 length prefix

		// If first byte is 0x00 and third byte looks like STUN (0x00-0x03)
		// this is likely RFC 4571 framed ICE-TCP
		if (first_byte == 0x00 && third_byte >= 0x00 && third_byte <= 0x03)
		{
			// Verify: second byte (low byte of length) should be reasonable
			// STUN messages are at least 20 bytes
			auto second_byte = data[1];
			if (second_byte >= 20)
			{
				logtd("Detected ICE-TCP Direct connection (RFC 4571 framing)");
				_connection_type = ConnectionType::IceTcpDirect;
				return true;
			}
		}
	}

	// Otherwise, check for raw STUN or TURN
	if (first_byte >= 0 && first_byte <= 3)
	{
		// Raw STUN - this is TURN connection (first message is TURN Allocate)
		logtd("Detected TURN relay connection (raw STUN)");
		_connection_type = ConnectionType::TurnRelay;
		return true;
	}
	else if (first_byte >= 64 && first_byte <= 79)
	{
		// TURN Channel Data
		logtd("Detected TURN relay connection (Channel Data)");
		_connection_type = ConnectionType::TurnRelay;
		return true;
	}

	// Cannot determine yet, need more data or it's unknown format
	return false;
}

bool IceTcpDemultiplexer::ParseData()
{
	// First, detect connection type if unknown
	if (_connection_type == ConnectionType::Unknown)
	{
		if (!DetectConnectionType())
		{
			// Need more data to determine connection type
			if (_buffer->GetLength() < RFC4571_HEADER_SIZE + 1)
			{
				return true;  // Wait for more data
			}
			// If we have enough data but can't detect, log warning and try RFC 4571
			logtw("Could not detect TCP connection type, assuming ICE-TCP Direct (RFC 4571)");
			_connection_type = ConnectionType::IceTcpDirect;
		}
	}

	// For ICE-TCP Direct, use RFC 4571 framing
	if (_connection_type == ConnectionType::IceTcpDirect)
	{
		while (_buffer->GetLength() >= RFC4571_HEADER_SIZE)
		{
			auto result = ExtractRfc4571Frame();

			if (result == ExtractResult::SUCCESS)
			{
				continue;
			}
			else if (result == ExtractResult::NOT_ENOUGH_BUFFER)
			{
				return true;
			}
			else // FAILED
			{
				return false;
			}
		}
		return true;
	}

	// For TURN relay, use original parsing logic
	while(_buffer->GetLength() > MINIMUM_PACKET_HEADER_SIZE)
	{
		// Only STUN and TURN Channel should be input packet types to IceTcpDemultiplexer.
		// If another packet is input, it means a problem has occurred.

		auto type = IcePacketIdentifier::FindPacketType(_buffer);
		IceTcpDemultiplexer::ExtractResult result;

		if(type == IcePacketIdentifier::PacketType::STUN)
		{
			result = ExtractStunMessage();
		}
		else if(type == IcePacketIdentifier::PacketType::TURN_CHANNEL_DATA)
		{
			result = ExtractChannelMessage();
		}
		else
		{
			// Critical error
			return false;
		}

		// success
		if(result == ExtractResult::SUCCESS)
		{
			continue;
		}
		// retry later
		else if(result == ExtractResult::NOT_ENOUGH_BUFFER)
		{
			return true;
		}
		// error
		else if(result == ExtractResult::FAILED)
		{
			return false;
		}
	}

	return true;
}

IceTcpDemultiplexer::ExtractResult IceTcpDemultiplexer::ExtractStunMessage()
{
	ov::ByteStream stream(_buffer);
	StunMessage message;

	if(message.ParseHeader(stream) == false)
	{
		if(message.GetLastErrorCode() == StunMessage::LastErrorCode::NOT_ENOUGH_DATA)
		{
			// Not enough data, retry later
			return ExtractResult::NOT_ENOUGH_BUFFER;
		}
		else
		{
			// Invalid data
			return ExtractResult::FAILED;
		}
	}

	uint32_t packet_size = StunMessage::DefaultHeaderLength() + message.GetMessageLength();
	auto data = _buffer->Subdata(0, packet_size);
	auto packet = std::make_shared<IceTcpDemultiplexer::Packet>(IcePacketIdentifier::PacketType::STUN, data);

	_packets.push(packet);

	_buffer = _buffer->Subdata(packet_size);

	return ExtractResult::SUCCESS;
}

IceTcpDemultiplexer::ExtractResult IceTcpDemultiplexer::ExtractChannelMessage()
{
	ChannelDataMessage message;

	if(message.LoadHeader(*_buffer) == false)
	{
		if(message.GetLastErrorCode() == ChannelDataMessage::LastErrorCode::NOT_ENOUGH_DATA)
		{
			return ExtractResult::NOT_ENOUGH_BUFFER;
		}
		else
		{
			return ExtractResult::FAILED;
		}
	}

	uint32_t packet_size = message.GetPacketLength();
	auto data = _buffer->Subdata(0, packet_size);
	auto packet = std::make_shared<IceTcpDemultiplexer::Packet>(IcePacketIdentifier::PacketType::TURN_CHANNEL_DATA, data);

	_packets.push(packet);
	_buffer = _buffer->Subdata(packet_size);

	return ExtractResult::SUCCESS;
}

// Extract a frame using RFC 4571 framing (2-byte big-endian length prefix)
// This is used for direct ICE-TCP connections
IceTcpDemultiplexer::ExtractResult IceTcpDemultiplexer::ExtractRfc4571Frame()
{
	if (_buffer->GetLength() < RFC4571_HEADER_SIZE)
	{
		return ExtractResult::NOT_ENOUGH_BUFFER;
	}

	// Read 2-byte big-endian length prefix
	auto data = _buffer->GetDataAs<uint8_t>();
	uint16_t frame_length = (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);

	// Sanity check: frame length should be reasonable (STUN min 20, max ~65535)
	if (frame_length < 20 || frame_length > 65535)
	{
		logte("RFC 4571: Invalid frame length: %u", frame_length);
		return ExtractResult::FAILED;
	}

	// Check if we have the complete frame
	size_t total_size = RFC4571_HEADER_SIZE + frame_length;
	if (_buffer->GetLength() < total_size)
	{
		return ExtractResult::NOT_ENOUGH_BUFFER;
	}

	// Extract the payload (without the 2-byte length prefix)
	auto payload = _buffer->Subdata(RFC4571_HEADER_SIZE, frame_length);

	// Identify the packet type from the payload
	auto type = IcePacketIdentifier::FindPacketType(payload);

	logtd("RFC 4571: Extracted frame, length=%u, type=%s",
		  frame_length, IcePacketIdentifier::GetPacketTypeString(type).CStr());

	// Create packet with the payload (not including RFC 4571 length prefix)
	auto packet = std::make_shared<IceTcpDemultiplexer::Packet>(type, payload);
	_packets.push(packet);

	// Remove the processed frame from buffer
	_buffer = _buffer->Subdata(total_size);

	return ExtractResult::SUCCESS;
}
