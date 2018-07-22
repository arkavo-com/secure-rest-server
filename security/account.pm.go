package security

var AccountPermission = Permission{Class: "Account", Actions: []string{"CREATE", "READ", "UPDATE", "UPDATE_PASSWORD", "ACTIVATE", "DEACTIVATE", "LOCK", "INITIALIZE"}}
