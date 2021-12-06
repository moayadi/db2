package db2client

import (
	"database/sql"
	//"time"
	//"fmt"

	_ "github.com/ibmdb/go_ibm_db"
)

func NewClient(host, port *string) (*Client,error) {
	var c = Client{
		Hostname: *host,
		Port:     *port,
	}
	return &c, nil
}

type Client struct {
	Hostname string
	Port   	 string
	Database string
	Username string
	Password string
	ConnectionString string
	RotateStatement  string
}


func (c *Client) UpdatePassword(hostname, port, database, username, currentpassword, newpassword string) (error) {

	//connectionString := "HOSTNAME=" + hostname + ";PORT=" + port + ";DATABASE=" + database + ";UID=" + username + ";PWD=" + currentpassword
	rotateStatement := "HOSTNAME=" + hostname + ";PORT=" + port + ";DATABASE=" + database + ";UID=" + username + ";PWD=" + currentpassword + ";NEWPWD=" + newpassword

	println(rotateStatement)

	//Connect and change the password, with the NEWPWD parameter
	db, err := sql.Open("go_ibm_db", rotateStatement)
	db.Exec("DROP table rocket")
	_, err = db.Exec("create table rocket(a int)")
	if err != nil {
		println("error dropping table")
		return err
	} else {
		println("success creating and dropping table")
	}
	db.Close()
	return err


	//start another connect with the old password, using con
	//this should return an error since it shouldn't  be able to connect.

	//db1, err := sql.Open("go_ibm_db", rotateStatement)
	//db1.Exec("DROP table rocket")
	//_, err = db1.Exec("create table rocket(a int)")
	//if err != nil {
	//	println("error dropping table")
	//} else {
	//	println("success creating and dropping table")
	//}
	//db1.Close()
}

func TestConnect(hostname, port, database, username, currentpassword, newpassword string) error {

	connectionString := "HOSTNAME=" + hostname + ";PORT=" + port + ";DATABASE=" + database + ";UID=" + username + ";PWD=" + currentpassword
	//rotateStatement := "HOSTNAME=" + hostname + ";PORT=" + port + ";DATABASE=" + database + ";UID=" + username + ";PWD=" + currentpassword + ";NEWPWD=" + newpassword

	println(connectionString)

	//Connect and change the password, with the NEWPWD parameter
	db, err := sql.Open("go_ibm_db", connectionString)
	_,err =  db.Exec("DROP table rocket")
	_,err = db.Exec("create table rocket(a int)")
	if err != nil {
		println("error dropping table")
		return err
	} else {
		println("success creating and dropping table")
	}
	db.Close()
	return err
	
}

func Createconnection(hostname, port, database, username, currentpassword, newpassword string) (db *sql.DB) {
	connectionString := "HOSTNAME=" + hostname + ";PORT=" + port + ";DATABASE=" + database + ";UID=" + username + ";PWD=" + currentpassword
	db, _ = sql.Open("go_ibm_db", connectionString)
	return db
}
