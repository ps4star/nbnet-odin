package nbnet
import "core:fmt"
import "core:math"
import "core:math/linalg"
import "core:mem"
import "core:os"
import "core:time"

ConnectionStatus :: enum int {
	Connected = 2,
	Disconnected,
	MsgReceived,
}

GameClient :: struct {
	endpoint: Endpoint,
	server_connection: ^Connection,
	is_connected: bool,
	ctx: rawptr,
}

@private gclient: GameClient