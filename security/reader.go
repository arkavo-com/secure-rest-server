package security

type AccountReader interface {
	ReadAccount(name string) (*Account, error)
}

type RoleReader interface {
	ReadRole(name string) (*Role, error)
}

type PolicyReader interface {
	ReadPolicy() *Policy
}
