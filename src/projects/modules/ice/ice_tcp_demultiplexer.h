//
// Created by getroot on 21. 01. 28.
//
#pragma once

#include <base/ovlibrary/ovlibrary.h>
#include "ice_packet_identifier.h"

//#define FIXED_STUN_HEADER_SIZE	20
//#define FIXED_TURN_CHANNEL_HEADER_SIZE	4
#define MINIMUM_PACKET_HEADER_SIZE	4

// RFC 4571 framing header size (2-byte length prefix)
#define RFC4571_HEADER_SIZE	2

// It only demultiplexes the stream input to ICE/TCP.
// Use identifier for packets that are input to UDP.

class IceTcpDemultiplexer
{
public:
	// Connection type determines the framing format
	enum class ConnectionType : uint8_t
	{
		Unknown,    // Not yet determined
		TurnRelay,  // TURN relay (uses Channel Data framing or raw STUN)
		IceTcpDirect  // Direct ICE-TCP (uses RFC 4571 framing)
	};

	IceTcpDemultiplexer()
	{
		_buffer = std::make_shared<ov::Data>(65535);
		_connection_type = ConnectionType::Unknown;
	}

	// In the case of a turn channel data message, it parses the header and stores the application data.
	class Packet
	{
	public:
		Packet(IcePacketIdentifier::PacketType type, const std::shared_ptr<ov::Data> &data)
		{
			_type = type;
			_data = data;
		}

		IcePacketIdentifier::PacketType GetPacketType()
		{
			return _type;
		}

		std::shared_ptr<ov::Data> GetData()
		{
			return _data;
		}

	private:
		IcePacketIdentifier::PacketType _type = IcePacketIdentifier::PacketType::UNKNOWN;
		[[maybe_unused]] uint16_t _channel_number = 0;	// Only use if packet is from channel data message
		std::shared_ptr<ov::Data>	_data = nullptr;
	};

	bool AppendData(const void *data, size_t length);
	bool AppendData(const std::shared_ptr<const ov::Data> &data);

	bool IsAvailablePacket();
	std::shared_ptr<IceTcpDemultiplexer::Packet> PopPacket();

	// Set/Get connection type for proper framing handling
	void SetConnectionType(ConnectionType type) { _connection_type = type; }
	ConnectionType GetConnectionType() const { return _connection_type; }

	// Check if this connection uses RFC 4571 framing (ICE-TCP Direct)
	bool IsIceTcpDirect() const { return _connection_type == ConnectionType::IceTcpDirect; }

private:
	bool ParseData();
	bool DetectConnectionType();

	enum class ExtractResult : int8_t
	{
		SUCCESS = 1,
		NOT_ENOUGH_BUFFER = 0,
		FAILED = -1
	};
	// 1 : success
	// 0 : not enough memory
	// -1 : error
	ExtractResult ExtractStunMessage();
	ExtractResult ExtractChannelMessage();
	ExtractResult ExtractRfc4571Frame();  // New: for ICE-TCP Direct

	std::shared_ptr<ov::Data> _buffer;
	std::queue<std::shared_ptr<IceTcpDemultiplexer::Packet>> _packets;
	ConnectionType _connection_type;
};