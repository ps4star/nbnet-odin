package nbnet
import "core:fmt"
import "core:math"
import "core:math/linalg"
import "core:mem"
import "core:os"
import "core:time"

MAX_CLIENTS :: 1_024
CONNECTION_VECTOR_INITIAL_CAPACITY :: 32

GameServerEventType :: enum {
	NewConnection,
	ClientDisconnected,
	ClientMsgReceived,
}

GameServerStats :: struct {
	up_bandwidth: f32,
	down_bandwidth: f32,
}

GameServer :: struct {
	endpoint: Endpoint,
	clients: [dynamic]Connection,
	stats: GameServerStats,
	ctx: rawptr,
}

@private gserver := GameServer{}

/*int NBN_GameServer_Start(const char *protocol_name, uint16_t port, bool encryption)
{
    NBN_Config config = {protocol_name, NULL, port, encryption};

    NBN_Endpoint_Init(&__game_server.endpoint, config, true);

    if ((__game_server.clients = NBN_ConnectionVector_Create()) == NULL)
    {
        NBN_LogError("Failed to create connections vector");

        return NBN_ERROR;
    }

    if (NBN_Driver_GServ_Start(Endpoint_BuildProtocolId(config.protocol_name), config.port) < 0)
    {
        NBN_LogError("Failed to start network driver");

        return NBN_ERROR;
    }

    NBN_LogInfo("Started");

    return 0;
}*/
/*GameServer_start :: proc(protocol_name: string, port: u16, enc: bool) -> (int)
{
	// NOTE: Check for len(0) NOT FOR nil for the str field of this
	config: Config = {protocol_name, "", port, enc}
	Endpoint_init(&gserver.endpoint, config, true)

	err: mem.Allocator_Error; gserver.clients, err = make(type_of(gserver.clients))
	if bool(u8(err)) {
		log(.Error, "Failed to create connections dynamic array")
		return ERROR
	}

	if Driver_GServ_start(Endpoint_build_protocol_id(config.protocol_name), config.port) < 0 {
		log(.Error, "Failed to start network driver")
		return ERROR
	}

	log(.Info, "Started")
	return 0
}*/

/*void NBN_GameServer_Stop(void)
{
    NBN_GameServer_Poll(); /* Poll one last time to clear remaining events */

    NBN_Endpoint_Deinit(&__game_server.endpoint);
    NBN_ConnectionVector_Destroy(__game_server.clients);

    NBN_Driver_GServ_Stop();

    NBN_LogInfo("Stopped");
}*/
/*GameServer_stop :: proc()
{
	GameServer_poll()

	Endpoint_deinit(&gserver.endpoint)
	delete(&gserver.clients)

	Driver_GServ_stop()

	log(.Info, "Stopped")
}*/

/*void NBN_GameServer_RegisterMessage(
        uint8_t msg_type,
        NBN_MessageBuilder msg_builder,
        NBN_MessageDestructor msg_destructor,
        NBN_MessageSerializer msg_serializer)
{
    if (NBN_IsReservedMessage(msg_type))
    {
        NBN_LogError("Message type %d is reserved by the library", msg_type);
        NBN_Abort();
    }

    NBN_Endpoint_RegisterMessageBuilder(&__game_server.endpoint, msg_builder, msg_type);
    NBN_Endpoint_RegisterMessageDestructor(&__game_server.endpoint, msg_destructor, msg_type);
    NBN_Endpoint_RegisterMessageSerializer(&__game_server.endpoint, msg_serializer, msg_type);
}*/

/*void NBN_GameServer_RegisterChannel(uint8_t type, uint8_t id)
{
    if (id == NBN_CHANNEL_RESERVED_UNRELIABLE || id == NBN_CHANNEL_RESERVED_RELIABLE || id == NBN_CHANNEL_RESERVED_LIBRARY_MESSAGES)
    {
        NBN_LogError("Channel id %d is reserved by the library", type);
        NBN_Abort();
    }

    NBN_Endpoint_RegisterChannel(&__game_server.endpoint, (NBN_ChannelType)type, id);
}*/

/*void NBN_GameServer_AddTime(double time)
{
    for (unsigned int i = 0; i < __game_server.clients->count; i++)
        NBN_Connection_AddTime(__game_server.clients->connections[i], time);

#if defined(NBN_DEBUG) && defined(NBN_USE_PACKET_SIMULATOR)
    NBN_PacketSimulator_AddTime(&__game_server.endpoint.packet_simulator, time);
#endif
}*/

/*int NBN_GameServer_Poll(void)
{
    if (NBN_EventQueue_IsEmpty(&__game_server.endpoint.event_queue))
    {
        if (GameServer_CloseStaleClientConnections() < 0)
            return NBN_ERROR;

        if (NBN_Driver_GServ_RecvPackets() < 0)
            return NBN_ERROR;

        __game_server.stats.download_bandwidth = 0;

        for (unsigned int i = 0; i < __game_server.clients->count; i++)
        {
            NBN_Connection *client = __game_server.clients->connections[i];

            for (unsigned int i = 0; i < NBN_MAX_CHANNELS; i++)
            {
                NBN_Channel *channel = client->channels[i];

                if (channel)
                {
                    NBN_Message *msg;

                    while ((msg = channel->GetNextRecvedMessage(channel)) != NULL)
                    {
                        if (GameServer_ProcessReceivedMessage(msg, client) < 0)
                        {
                            NBN_LogError("Failed to process received message");

                            return NBN_ERROR;
                        }
                    }
                }
            }

            if (!client->is_closed)
                Connection_UpdateAverageDownloadBandwidth(client);

            __game_server.stats.download_bandwidth += client->stats.download_bandwidth;
            client->last_read_packets_time = client->time;
        }

        GameServer_RemoveClosedClientConnections();
    }


    while (true)
    {
        bool ret = NBN_EventQueue_Dequeue(&__game_server.endpoint.event_queue, &server_last_event);

        if (!ret)
            return NBN_NO_EVENT;

        int ev = GameServer_HandleEvent();

        if (ev != NBN_SKIP_EVENT)
            return ev;
    }
}*/

/*int NBN_GameServer_SendPackets(void)
{
    __game_server.stats.upload_bandwidth = 0;

    for (unsigned int i = 0; i < __game_server.clients->count; i++)
    {
        NBN_Connection *client = __game_server.clients->connections[i];

        if (!client->is_stale && NBN_Connection_FlushSendQueue(client) < 0)
            return NBN_ERROR;

        __game_server.stats.upload_bandwidth += client->stats.upload_bandwidth;
    }

    return 0;
}*/

/*void NBN_GameServer_SetContext(void *context)
{
    __game_server.context = context;
}*/

/*void *NBN_GameServer_GetContext(void)
{
    return __game_server.context;
}*/

/*NBN_Connection *NBN_GameServer_CreateClientConnection(uint32_t id, void *driver_data)
{
    NBN_Connection *client = NBN_Endpoint_CreateConnection(&__game_server.endpoint, id, driver_data);

#ifdef NBN_DEBUG
    client->OnMessageAddedToRecvQueue = __game_server.endpoint.OnMessageAddedToRecvQueue;
#endif

    return client;
}*/

/*int NBN_GameServer_CloseClientWithCode(NBN_Connection *client, int code)
{ 
    return GameServer_CloseClientWithCode(client, code, false);
}*/

/*int NBN_GameServer_CloseClient(NBN_Connection *client)
{
    return GameServer_CloseClientWithCode(client, -1, false);
}*/

/*NBN_OutgoingMessage *NBN_GameServer_CreateMessage(uint8_t msg_type, void *msg_data)
{
    return Endpoint_CreateOutgoingMessage(&__game_server.endpoint, msg_type, msg_data);
}*/

/*NBN_OutgoingMessage *NBN_GameServer_CreateByteArrayMessage(uint8_t *bytes, unsigned int length)
{
    if (length > NBN_BYTE_ARRAY_MAX_SIZE)
    {
        NBN_LogError("Byte array cannot exceed %d bytes", NBN_BYTE_ARRAY_MAX_SIZE);

        return NULL;
    }

    NBN_ByteArrayMessage *msg = NBN_ByteArrayMessage_Create();

    memcpy(msg->bytes, bytes, length);

    msg->length = length;

    return NBN_GameServer_CreateMessage(NBN_BYTE_ARRAY_MESSAGE_TYPE, msg);
}*/

/*int NBN_GameServer_SendMessageTo(NBN_Connection *client, NBN_OutgoingMessage *outgoing_msg, uint8_t channel_id)
{
    /* The only message type we can send to an unaccepted client is a NBN_ClientAcceptedMessage message
     * or a NBN_PublicCryptoInfoMessage */
    assert(client->is_accepted ||
            outgoing_msg->type == NBN_CLIENT_ACCEPTED_MESSAGE_TYPE || NBN_PUBLIC_CRYPTO_INFO_MESSAGE_TYPE);

    if (Endpoint_EnqueueOutgoingMessage(&__game_server.endpoint, client, outgoing_msg, channel_id) < 0)
    {
        NBN_LogError("Failed to create outgoing message for client %d");

        /* Do not close the client if we failed to send the close client message to avoid infinite loops */
        if (outgoing_msg->type != NBN_CLIENT_CLOSED_MESSAGE_TYPE)
        {
            GameServer_CloseClientWithCode(client, -1, false);

            return NBN_ERROR;
        }
    }

    return 0;
}*/

/*int NBN_GameServer_SendUnreliableMessageTo(NBN_Connection *client, NBN_OutgoingMessage *outgoing_msg)
{
    return NBN_GameServer_SendMessageTo(client, outgoing_msg, NBN_CHANNEL_RESERVED_UNRELIABLE);
}*/

/*int NBN_GameServer_SendReliableMessageTo(NBN_Connection *client, NBN_OutgoingMessage *outgoing_msg)
{
    return NBN_GameServer_SendMessageTo(client, outgoing_msg, NBN_CHANNEL_RESERVED_RELIABLE);
}*/

/*int NBN_GameServer_BroadcastMessage(NBN_OutgoingMessage *outgoing_msg, uint8_t channel_id)
{
    for (unsigned int i = 0; i < __game_server.clients->count; i++)
    {
        NBN_Connection *client = __game_server.clients->connections[i];

        if (!client->is_closed && !client->is_stale && client->is_accepted)
        {
            if (NBN_GameServer_SendMessageTo(client, outgoing_msg, channel_id) < 0)
                return NBN_ERROR;
        }
    }

    return 0;
}*/

/*int NBN_GameServer_BroadcastUnreliableMessage(NBN_OutgoingMessage *outgoing_msg)
{
    return NBN_GameServer_BroadcastMessage(outgoing_msg, NBN_CHANNEL_RESERVED_UNRELIABLE);
}*/

/*int NBN_GameServer_BroadcastReliableMessage(NBN_OutgoingMessage *outgoing_msg)
{
    return NBN_GameServer_BroadcastMessage(outgoing_msg, NBN_CHANNEL_RESERVED_RELIABLE);
}*/

/*NBN_Stream *NBN_GameServer_GetConnectionAcceptDataWriteStream(NBN_Connection *client)
{
    return (NBN_Stream *)&client->accept_data_w_stream;
}*/

/*int NBN_GameServer_AcceptIncomingConnection(void)
{
    assert(server_last_event.type == NBN_NEW_CONNECTION);
    assert(server_last_event.data.connection != NULL);

    NBN_Connection *client = server_last_event.data.connection;
    NBN_ClientAcceptedMessage *msg = NBN_ClientAcceptedMessage_Create();

    assert(msg != NULL);

    NBN_WriteStream_Flush(&client->accept_data_w_stream);

    memcpy(msg->data, client->accept_data, NBN_ACCEPT_DATA_MAX_SIZE);

    NBN_OutgoingMessage *outgoing_msg = NBN_GameServer_CreateMessage(NBN_CLIENT_ACCEPTED_MESSAGE_TYPE, msg);

    if (outgoing_msg == NULL)
        return NBN_ERROR;

    if (NBN_GameServer_SendReliableMessageTo(client, outgoing_msg) < 0)
        return NBN_ERROR;

    client->is_accepted = true;

    NBN_LogTrace("Client %d has been accepted", client->id);

    return 0;
}*/

/*int NBN_GameServer_RejectIncomingConnectionWithCode(int code)
{
    assert(server_last_event.type == NBN_NEW_CONNECTION);
    assert(server_last_event.data.connection != NULL);

    return GameServer_CloseClientWithCode(server_last_event.data.connection, code, false);
}*/

/*int NBN_GameServer_RejectIncomingConnection(void)
{
    return NBN_GameServer_RejectIncomingConnectionWithCode(-1);
}*/

/*NBN_Connection *NBN_GameServer_GetIncomingConnection(void)
{
    assert(server_last_event.type == NBN_NEW_CONNECTION);
    assert(server_last_event.data.connection != NULL);

    return server_last_event.data.connection;
}*/

/*uint8_t *NBN_GameServer_GetConnectionData(NBN_Connection *client)
{
    return client->connection_data;
}*/

/*NBN_Connection *NBN_GameServer_GetDisconnectedClient(void)
{
    assert(server_last_event.type == NBN_CLIENT_DISCONNECTED);

    return server_last_event.data.connection;
}*/

/*NBN_MessageInfo NBN_GameServer_GetMessageInfo(void)
{
    assert(server_last_event.type == NBN_CLIENT_MESSAGE_RECEIVED);

    return server_last_event.data.message_info;
}*/

/*NBN_GameServerStats NBN_GameServer_GetStats(void)
{
    return __game_server.stats;
}*/

/*bool NBN_GameServer_IsEncryptionEnabled(void)
{
    return __game_server.endpoint.config.is_encryption_enabled;
}*/

when NBN_DEBUG > 0 {

/*void NBN_GameServer_Debug_RegisterCallback(NBN_ConnectionDebugCallback cb_type, void *cb)
{
    switch (cb_type)
    {
        case NBN_DEBUG_CB_MSG_ADDED_TO_RECV_QUEUE:
            __game_server.endpoint.OnMessageAddedToRecvQueue = (void (*)(NBN_Connection *, NBN_Message *))cb;
            break;
    }
}*/

}

/*static int GameServer_AddClient(NBN_Connection *client)
{
    if (__game_server.clients->count >= NBN_MAX_CLIENTS)
        return NBN_ERROR;

    if (NBN_ConnectionVector_Add(__game_server.clients, client) < 0)
        return NBN_ERROR;

    return 0;
}*/

/*static int GameServer_CloseClientWithCode(NBN_Connection *client, int code, bool disconnection)
{
    NBN_LogTrace("Closing connection %d", client->id);

    if (!client->is_closed && client->is_accepted)
    {
        if (!disconnection)
        {
            NBN_Event e;

            e.type = NBN_CLIENT_DISCONNECTED;
            e.data.connection = client;

            if (!NBN_EventQueue_Enqueue(&__game_server.endpoint.event_queue, e))
                return NBN_ERROR;
        }
    }

    if (client->is_stale)
    {
        client->is_closed = true;

        return 0;
    }

    client->is_closed = true;

    if (!disconnection)
    {
        NBN_LogDebug("Send close message for client %d (code: %d)", client->id, code);

        NBN_ClientClosedMessage *msg = NBN_ClientClosedMessage_Create();

        msg->code = code;

        NBN_OutgoingMessage *outgoing_msg = NBN_GameServer_CreateMessage(NBN_CLIENT_CLOSED_MESSAGE_TYPE, msg);

        if (outgoing_msg == NULL)
            return NBN_ERROR;

        NBN_GameServer_SendMessageTo(client, outgoing_msg, NBN_CHANNEL_RESERVED_LIBRARY_MESSAGES);
    }

    return 0;
}*/

/*static unsigned int GameServer_GetClientCount(void)
{
    return __game_server.clients->count;
}*/

/*static int GameServer_ProcessReceivedMessage(NBN_Message *message, NBN_Connection *client)
{
    NBN_Event ev;

    ev.type = NBN_CLIENT_MESSAGE_RECEIVED;

    if (message->header.type == NBN_MESSAGE_CHUNK_TYPE)
    {
        NBN_Channel *channel = client->channels[message->header.channel_id];

        if (!NBN_Channel_AddChunk(channel, message))
            return 0;

        NBN_Message complete_message;

        if (NBN_Channel_ReconstructMessageFromChunks(channel, client, &complete_message) < 0)
        {
            NBN_LogError("Failed to reconstruct message from chunks");

            return NBN_ERROR;
        }

        NBN_MessageInfo msg_info = { complete_message.header.type, complete_message.data, client };

        ev.data.message_info = msg_info;
    }
    else
    {
        NBN_MessageInfo msg_info = { message->header.type, message->data, client };

        ev.data.message_info = msg_info;
    }

    if (!NBN_EventQueue_Enqueue(&__game_server.endpoint.event_queue, ev))
        return NBN_ERROR;

    return 0;
}*/

/*static int GameServer_CloseStaleClientConnections(void)
{
    for (unsigned int i = 0; i < __game_server.clients->count; i++)
    {
        NBN_Connection *client = __game_server.clients->connections[i];

        if (!client->is_closed && !client->is_stale && NBN_Connection_CheckIfStale(client))
        {
            NBN_LogInfo("Client %d connection is stale, closing it.", client->id);

            client->is_stale = true;

            if (GameServer_CloseClientWithCode(client, -1, false) < 0)
                return NBN_ERROR;
        }
    }

    return 0;
}*/

/*static void GameServer_RemoveClosedClientConnections(void)
{
    unsigned int count = __game_server.clients->count;

    for (unsigned int i = 0; i < count; i++)
    {
        NBN_Connection *client = __game_server.clients->connections[i];

        if (client && client->is_closed && client->is_stale)
        {
            NBN_LogDebug("Remove closed client connection (ID: %d)", client->id);

            NBN_Driver_GServ_RemoveClientConnection(client);
            NBN_ConnectionVector_Remove(__game_server.clients, client); // actually destroying the connection should be done in user code
        }
    }
}*/

/*static int GameServer_HandleEvent(void)
{
    switch (server_last_event.type)
    {
        case NBN_CLIENT_MESSAGE_RECEIVED:
            return GameServer_HandleMessageReceivedEvent();

        default:
            break;
    }

    return server_last_event.type;
}*/

/*static int GameServer_HandleMessageReceivedEvent(void)
{
    NBN_MessageInfo message_info = server_last_event.data.message_info;

    // skip all events related to a closed or stale connection
    if (message_info.sender->is_closed || message_info.sender->is_stale)
        return NBN_SKIP_EVENT;

    if (message_info.type == NBN_DISCONNECTION_MESSAGE_TYPE)
    {
        NBN_Connection *cli = server_last_event.data.message_info.sender;

        NBN_LogInfo("Received disconnection message from client %d", cli->id);

        if (GameServer_CloseClientWithCode(cli, -1, true) < 0)
            return NBN_ERROR;

        cli->is_stale = true;

        GameServer_RemoveClosedClientConnections();

        server_last_event.type = NBN_CLIENT_DISCONNECTED;
        server_last_event.data.connection = cli;

        return NBN_CLIENT_DISCONNECTED;
    }

    int ret = NBN_CLIENT_MESSAGE_RECEIVED;
 
    if (NBN_GameServer_IsEncryptionEnabled() && message_info.type == NBN_PUBLIC_CRYPTO_INFO_MESSAGE_TYPE)
    {
        ret = NBN_NO_EVENT;

        NBN_PublicCryptoInfoMessage *pub_crypto_msg = (NBN_PublicCryptoInfoMessage*)message_info.data;

        if (Connection_BuildSharedKey(&message_info.sender->keys1, pub_crypto_msg->pub_key1) < 0)
        {
            NBN_LogError("Failed to build shared key (first key)");
            NBN_Abort();
        }

        if (Connection_BuildSharedKey(&message_info.sender->keys2, pub_crypto_msg->pub_key2) < 0)
        {
            NBN_LogError("Failed to build shared key (second key)");
            NBN_Abort();
        }

        if (Connection_BuildSharedKey(&message_info.sender->keys3, pub_crypto_msg->pub_key3) < 0)
        {
            NBN_LogError("Failed to build shared key (third key)");
            NBN_Abort();
        }

        NBN_LogDebug("Received public crypto info of client %d", message_info.sender->id);

        if (GameServer_StartEncryption(message_info.sender))
        {
            NBN_LogError("Failed to start encryption of client %d", message_info.sender->id);
            NBN_Abort();
        }

        message_info.sender->can_decrypt = true; 
    }
    else if (message_info.type == NBN_CONNECTION_REQUEST_MESSAGE_TYPE)
    {
        ret = NBN_NO_EVENT;

        NBN_ConnectionRequestMessage *msg = (NBN_ConnectionRequestMessage *)message_info.data;

        memcpy(message_info.sender->connection_data, msg->data, NBN_CONNECTION_DATA_MAX_SIZE);

        NBN_Event e;

        e.type = NBN_NEW_CONNECTION;
        e.data.connection = message_info.sender;

        if (!NBN_EventQueue_Enqueue(&__game_server.endpoint.event_queue, e))
            return NBN_ERROR;
    }

    return ret;
}*/

// region Game server driver
/*int NBN_Driver_GServ_RaiseEvent(NBN_Driver_GServ_EventType ev, void *data)
{
    switch (ev)
    {
        case NBN_DRIVER_GSERV_CLIENT_CONNECTED:
            return Driver_GServ_OnClientConnected((NBN_Connection*)data);

        case NBN_DRIVER_GSERV_CLIENT_PACKET_RECEIVED:
            return Driver_GServ_OnClientPacketReceived((NBN_Packet*)data);
    }

    return 0;
}*/

/*static int Driver_GServ_OnClientConnected(NBN_Connection *client)
{
    if (GameServer_AddClient(client) < 0)
    {
        NBN_LogError("Failed to add client");

        return NBN_ERROR;
    }

    if (NBN_GameServer_IsEncryptionEnabled())
    {
        if (GameServer_SendCryptoPublicInfoTo(client) < 0)
        {
            NBN_LogError("Failed to send public key to client %d", client->id);
            NBN_Abort();
        }
    }

    return 0;
}*/

/*static int Driver_GServ_OnClientPacketReceived(NBN_Packet *packet)
{
    if (Endpoint_ProcessReceivedPacket(&__game_server.endpoint, packet, packet->sender) < 0)
    {
        NBN_LogError("An error occured while processing packet from client %d, closing the client", packet->sender->id);

        return GameServer_CloseClientWithCode(packet->sender, -1, false);
    }

    return 0;
}*/

/*static int GameServer_SendCryptoPublicInfoTo(NBN_Connection *client)
{
    NBN_PublicCryptoInfoMessage *msg = NBN_PublicCryptoInfoMessage_Create();

    memcpy(msg->pub_key1, client->keys1.pub_key, ECC_PUB_KEY_SIZE);
    memcpy(msg->pub_key2, client->keys2.pub_key, ECC_PUB_KEY_SIZE);
    memcpy(msg->pub_key3, client->keys3.pub_key, ECC_PUB_KEY_SIZE);
    memcpy(msg->aes_iv, client->aes_iv, AES_BLOCKLEN);

    NBN_OutgoingMessage *outgoing_msg = NBN_GameServer_CreateMessage(NBN_PUBLIC_CRYPTO_INFO_MESSAGE_TYPE, msg);

    if (outgoing_msg == NULL)
        return NBN_ERROR;

    if (NBN_GameServer_SendReliableMessageTo(client, outgoing_msg) < 0)
        return NBN_ERROR;

    NBN_LogDebug("Sent server's public key to the client %d", client->id);

    return 0;
}*/

/*static int GameServer_StartEncryption(NBN_Connection *client)
{
    Connection_StartEncryption(client);

    NBN_OutgoingMessage *outgoing_msg = NBN_GameServer_CreateMessage(
            NBN_START_ENCRYPT_MESSAGE_TYPE, NBN_StartEncryptMessage_Create());

    if (outgoing_msg == NULL)
        return NBN_ERROR;

    if (NBN_GameServer_SendReliableMessageTo(client, outgoing_msg) < 0)
        return NBN_ERROR;

    return 0;
}*/