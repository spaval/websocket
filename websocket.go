package websocket

import (
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/spaval/websocket/security"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Client represents a WebSocket connection with a unique ID.
type Client struct {
	conn *websocket.Conn
	id   string
	send chan []byte
}

// Hub manages multiple clients and message broadcasting.
type Hub struct {
	clients    map[string]*Client
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.Mutex
}

// NewHub initializes a new WebSocket hub.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[string]*Client),
		broadcast:  make(chan []byte),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run starts the hub's main loop to manage client connections.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client.id] = client
			h.mu.Unlock()
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client.id]; ok {
				delete(h.clients, client.id)
				close(client.send)
			}
			h.mu.Unlock()
		case message := <-h.broadcast:
			h.mu.Lock()
			for _, client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client.id)
				}
			}
			h.mu.Unlock()
		}
	}
}

// Read listens for incoming messages and forwards them to the hub.
func (c *Client) Read(h *Hub) {
	defer func() {
		h.unregister <- c
		c.conn.Close()
	}()

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		if len(message) > 0 && message[0] == '@' {
			h.mu.Lock()
			target, exists := h.clients[string(message[1:])]
			h.mu.Unlock()

			if exists {
				target.send <- message
			}
		} else {
			h.broadcast <- message
		}
	}
}

// Write sends messages from the hub to the client.
func (c *Client) Write() {
	for message := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
			break
		}
	}
	c.conn.Close()
}

// Serve handles new WebSocket connections and authenticates them.
func Serve(h *Hub, w http.ResponseWriter, r *http.Request, jwtSecret string) {
	tokenString := r.URL.Query().Get("token")
	userID, valid := security.VerifyToken(tokenString, jwtSecret)
	if !valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading connection:", err)
		return
	}

	client := &Client{conn: conn, id: userID, send: make(chan []byte, 256)}
	h.register <- client

	go client.Read(h)
	go client.Write()
}
