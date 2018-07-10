package security

var SessionPermission = Permission{Class: "Session", Actions: []string{"CREATE", "READ", "IDLE", "EXPIRE", "TERMINATE", "REDUCE"}}
