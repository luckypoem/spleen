package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"

	"github.com/luckypoem/spleen/server/util"
)

func main() {
	var conf string
	var config map[string]interface{}
	flag.StringVar(&conf, "c", ".server.json", "server config")
	flag.Parse()

	bytes, err := ioutil.ReadFile(conf)
	if err != nil {
		log.Fatalf("Reading %s failed.", conf)
	}

	if err := json.Unmarshal(bytes, &config); err != nil {
		log.Fatalf("Parsing %s failed.", conf)
	}

	localIP := config["local_ip"].(string)
	localPort := int(config["local_port"].(float64))
	s := server.NewServer(localIP, localPort)
	err = s.Listen()
	if err != nil {
		log.Printf("Listen failed. %s", err.Error())
	}
}
