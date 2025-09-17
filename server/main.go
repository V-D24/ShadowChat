package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type JoinRequest struct {
	User string `json:"user"`
	Room string `json:"room"`
}

type Peer struct {
	User string
	Conn *websocket.Conn
}

var (
	upgrader   = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	rooms      = make(map[string]map[string]*Peer) // room -> user -> peer
	roomsMutex = sync.Mutex{}
)

func joinHandler(w http.ResponseWriter, r *http.Request) {
	var req JoinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	roomsMutex.Lock()
	defer roomsMutex.Unlock()

	if _, ok := rooms[req.Room]; !ok {
		rooms[req.Room] = make(map[string]*Peer)
	}

	// Return current users in the room
	users := []string{}
	for user := range rooms[req.Room] {
		users = append(users, user)
	}
	json.NewEncoder(w).Encode(users)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}

	defer conn.Close()

	// First message from client must be join info
	var joinMsg JoinRequest
	if err := conn.ReadJSON(&joinMsg); err != nil {
		log.Println("failed read join:", err)
		return
	}

	roomsMutex.Lock()
	if _, ok := rooms[joinMsg.Room]; !ok {
		rooms[joinMsg.Room] = make(map[string]*Peer)
	}
	rooms[joinMsg.Room][joinMsg.User] = &Peer{User: joinMsg.User, Conn: conn}
	roomsMutex.Unlock()

	log.Printf("%s joined room %s", joinMsg.User, joinMsg.Room)

	// Listen loop
	for {
		var msg map[string]string
		if err := conn.ReadJSON(&msg); err != nil {
			log.Println("read error:", err)
			break
		}

		// msg must have "to" and "payload"
		to := msg["to"]
		payload := msg["payload"]

		roomsMutex.Lock()
		if peer, ok := rooms[joinMsg.Room][to]; ok {
			peer.Conn.WriteJSON(map[string]string{
				"from":    joinMsg.User,
				"payload": payload,
			})
		}
		roomsMutex.Unlock()
	}

	// cleanup
	roomsMutex.Lock()
	delete(rooms[joinMsg.Room], joinMsg.User)
	if len(rooms[joinMsg.Room]) == 0 {
		delete(rooms, joinMsg.Room)
	}
	roomsMutex.Unlock()
	log.Printf("%s left room %s", joinMsg.User, joinMsg.Room)
}

func main() {
	http.HandleFunc("/join", joinHandler)
	http.HandleFunc("/ws", wsHandler)
	fmt.Println("ShadowChat relay server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
