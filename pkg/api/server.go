package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/avereha/pod/pkg/pod"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	http.Handler

	pod  *pod.Pod
	conn *websocket.Conn
}

func New(pod *pod.Pod) *Server {

	ret := &Server{
		pod: pod,
	}

	return ret
}

func (s *Server) Start(addr string) {
	s.setupRoutes()
	s.pod.SetWebMessageHook(func(msg []byte) {
		s.sendMessage(msg)
	})
	log.Infof("Pod simulator control panel on http://%s/", displayAddr(addr))
	log.Fatal(http.ListenAndServe(addr, nil))
}

func displayAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return "localhost" + addr
	}
	return addr
}

func (s *Server) sendMessage(msg []byte) {
	if s.conn != nil {
		if err := s.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			log.Println(err)
			return
		}
	}
}

func (s *Server) setupRoutes() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, indexHTML)
	})
	http.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.pod.Status())
	})
	http.HandleFunc("/command", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST a command", http.StatusMethodNotAllowed)
			return
		}
		body, err := ioutil.ReadAll(r.Body)
		if err == nil {
			err = s.handleCommand(body)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, s.pod.Status())
	})
	// The websocket API, for github.com/ps2/pod_simulator_frontend.
	http.Handle("/ws", s)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// upgrade this connection to a WebSocket
	// connection
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		return
	}

	s.conn = ws
	// listen indefinitely for new messages coming
	// through on our WebSocket connection

	s.reader(ws)
}

// define a reader which will listen for
// new messages being sent to our WebSocket
// endpoint
func (s *Server) reader(conn *websocket.Conn) {
	for {
		// Send current state initially
		state, err := s.pod.GetPodStateJson()
		if err := conn.WriteMessage(websocket.TextMessage, state); err != nil {
			log.Println(err)
			return
		}

		_, p, err := conn.ReadMessage()
		if err != nil {
			log.Println(err)
			return
		}
		log.Debugf("Received: %s", p)
		if err := s.handleCommand(p); err != nil {
			log.Error(err)
		}
	}
}

func (s *Server) handleCommand(bytes []byte) error {
	var msg map[string]interface{}
	if err := json.Unmarshal(bytes, &msg); err != nil {
		return err
	}

	command, ok := msg["command"].(string)
	if !ok {
		return errors.New("command is not a string or not in msg")
	}
	value, hasValue := msg["value"].(float64)
	needValue := func(what string, min, max float64) error {
		if !hasValue {
			return fmt.Errorf("%s is not a number or not in msg", what)
		}
		if value < min || value > max {
			return fmt.Errorf("%s %v: want %v to %v", what, value, min, max)
		}
		return nil
	}

	switch command {
	case "changeReservoir":
		if err := needValue("reservoir", 0, 200); err != nil {
			return err
		}
		s.pod.SetReservoir(float32(value))
	case "setAlerts":
		if err := needValue("alert mask", 0, 255); err != nil {
			return err
		}
		s.pod.SetAlerts(uint8(value))
	case "setFault":
		if err := needValue("fault", 0, 255); err != nil {
			return err
		}
		s.pod.SetFault(uint8(value))
	case "setActiveTime":
		if err := needValue("active time in minutes", 0, 100*60); err != nil {
			return err
		}
		s.pod.SetActiveTime(int(value))
	case "crashNextCommand":
		beforeProcessing, ok := msg["beforeProcessing"].(bool)
		if !ok {
			return errors.New("beforeProcessing is not a bool or not in msg")
		}
		s.pod.CrashNextCommand(beforeProcessing)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
	return nil
}

// We'll need to define an Upgrader
// this will require a Read and Write buffer size
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,

	// We'll need to check the origin of our connection
	// this will allow us to make requests from our React
	// development server to here.
	// For now, we'll do no checking and just allow any connection
	CheckOrigin: func(r *http.Request) bool { return true },
}
