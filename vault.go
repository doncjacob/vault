package vault

import (
	"fmt"
	"time"
	"errors"
	"net/http"	
	"github.com/hashicorp/vault/api"	
)

//Login - Struct to hold login variables
type Login struct{
	Ldapusername string
	Ldappassword string
	VaultAddr string
	VaultPath string
}

//Vault - Interface to Initialize Vault
type Vault interface{
	vaultInit() (string, error)
	GetToken() (string, error)
	GetKeys(token string) (map[string]interface{}, error)
}


var httpClient = &http.Client{
	Timeout:10 * time.Second,
}

func (l *Login) vaultInit() error{
	if( len(l.Ldapusername)<0 && len(l.Ldappassword) <0 && len(l.VaultAddr) <0 && len(l.VaultPath) <0 ){
			return errors.New("Please provide the correct credentials")
	}
	return nil
}

//GetToken - Gets the token from ldap credentials
func (l *Login) GetToken() (string, error) {

	err := l.vaultInit()
	if err != nil {return "", err}

	// create a vault client
	client, err := api.NewClient(&api.Config{Address: l.VaultAddr, HttpClient: httpClient})
	if err != nil {return "", err}

	// to pass the password
	options := map[string]interface{}{
		"password": l.Ldappassword,
	}
	path := fmt.Sprintf("auth/ldap/login/%s", l.Ldapusername)
	
	// PUT call to get a token
	secret, err := client.Logical().Write(path, options)
	if err != nil {return "", err}
	token := secret.Auth.ClientToken

	return token, nil
}

//GetKeys - Get keys for a particular secret
func (l *Login) GetKeys(secret,token string) (map[string]interface{}, error){

	err := l.vaultInit()
	if err != nil {
		return nil, err
	}

	client, err := api.NewClient(&api.Config{Address: l.VaultAddr, HttpClient: httpClient})
	if err != nil {
		return nil, err
	}

	client.SetToken(token)
	data, err := client.Logical().Read(l.VaultPath + "/" + secret)
	if err != nil {
		return nil, err
	}
	return data.Data, nil
}
