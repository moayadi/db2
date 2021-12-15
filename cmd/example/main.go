package main

import (
	"fmt"
	client "vault-plugin-secrets-hashicups/db2client"
)

func main() {


	hostname := "10.0.2.2"
	port := "50000"

	result := client.Createconnection(hostname, port, "dojo","moayad", "T5SEEDfd", "vCu5RYrR")
	if result != nil {
		fmt.Println("Pass")
	} else {
		fmt.Println("Fail")
	}

	db2client, _ := client.NewClient(&hostname, &port)
	//db2client := new(client.Client)


	//db2client.UpdatePassword(hostname, port, "dojo","moayad", "vCu5RYrb", "vCu5RYrR")
	db2client.UpdatePassword(hostname, port, "dojo","moayad", "T5SEEDfd", "vCu5RYrD")


}

