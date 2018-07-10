package security

var AccountPermission = Permission{Class: "Account", Actions: []string{"CREATE", "READ", "UPDATE", "ACTIVATE", "DEACTIVATE", "LOCK", "INITIALIZE"}}
