package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"secure-rest-server/security"
	"secure-rest-server/security/account"
	"secure-rest-server/security/configuration"
	"secure-rest-server/security/permission"
	"secure-rest-server/security/policy"
	"secure-rest-server/security/rest"
	"secure-rest-server/security/role"
	"secure-rest-server/security/session"
	"strings"

	"github.com/globalsign/mgo"
	"github.com/go-openapi/spec"
	"github.com/gomodule/redigo/redis"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Llongfile)
	var accountReader security.AccountReader
	var policyReader security.PolicyReader
	var roleReader security.RoleReader
	// store
	sURL, err := url.Parse(configuration.Account.Store.Url)
	// configuration.Permission.Store.URL
	if err != nil {
		log.Println("store url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		// workaround for ssl ParseURL bug
		mongoUrl := sURL.String()
		ssl := strings.Contains(mongoUrl, "ssl=true")
		if ssl {
			mongoUrl = strings.Replace(mongoUrl, "ssl=true", "", -1)
		}
		// MongoDB
		info, err := mgo.ParseURL(mongoUrl)
		if err != nil {
			log.Println("mongodb url error", err)
		}
		if ssl {
			tlsConfig := &tls.Config{}
			info.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
				conn, err := tls.Dial("tcp", addr.String(), tlsConfig)
				return conn, err
			}
		}
		_, err = mgo.DialWithInfo(info)
		if err != nil {
			log.Println("mongodb dial error", err)
		}
		accountReader = account.RegisterStoreProviderMgo(info)
		policyReader = policy.RegisterStoreProviderMgo(info)
		role.RegisterStoreProviderMgo(info)
		permission.RegisterStoreProviderMgo(info)
	case "postgres":
	case "redis":
		// role
		c, err := redis.Dial(
			configuration.Role.Store.Redis.Network,
			configuration.Role.Store.Redis.Address,
			redis.DialDatabase(int(configuration.Role.Store.Redis.Database)),
			redis.DialPassword(configuration.Role.Store.Redis.Password),
		)
		if err != nil {
			log.Println("redis dial error", err)
		}
		role.RegisterStoreProviderRedis(c)
		// session
		c, err = redis.Dial(
			configuration.Session.Store.Redis.Network,
			configuration.Session.Store.Redis.Address,
			redis.DialDatabase(int(configuration.Role.Store.Redis.Database)),
			redis.DialPassword(configuration.Session.Store.Redis.Password),
		)
		if err != nil {
			log.Println("redis dial error", err)
		}
		session.RegisterStoreProviderRedis(c)
		// permission
		c, err = redis.Dial(
			configuration.Permission.Store.Redis.Network,
			configuration.Permission.Store.Redis.Address,
			redis.DialDatabase(int(configuration.Role.Store.Redis.Database)),
			redis.DialPassword(configuration.Permission.Store.Redis.Password),
		)
		permission.RegisterStoreProviderRedis(c)
	default:
		log.Println("development mode enabled - memory database")
		accountReader = account.RegisterStoreProviderMemdb()
		policyReader = policy.RegisterStoreProviderMemdb()
		roleReader = role.RegisterStoreProviderMemdb()
		session.RegisterStoreProviderMemdb()
		permission.RegisterStoreProviderMemdb()
	}
	if accountReader == nil {
		log.Fatal("accountReader uninitialized")
	}
	if policyReader == nil {
		log.Fatal("policyReader uninitialized")
	}
	if roleReader == nil {
		log.Fatal("roleReader uninitialized")
	}
	// openapi paths
	pa := spec.Paths{Paths: map[string]spec.PathItem{}}
	// session
	session.RegisterHttpHandler(pa, accountReader, roleReader, policyReader)
	// role
	role.RegisterHttpHandler(pa)
	// permission
	permission.RegisterHttpHandler(pa)
	// account
	account.RegisterHttpHandler(pa, accountReader)
	// policy
	policy.RegisterHttpHandler(pa)
	// openapi handler
	http.HandleFunc("/api", rest.HandlerFunc(pa))
	// interrupt
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	// server
	server := http.Server{
		Addr: configuration.Server.Address,
		Handler: rest.HeaderHandler{
			ServeMux: http.DefaultServeMux,
			Origin:   configuration.Server.Origin,
		},
	}
	go func() {
		log.Println("listening on address ", server.Addr)
		if err := server.ListenAndServeTLS(
			configuration.Server.Certificate,
			configuration.Server.Key,
		); err != nil {
			log.Fatal(err)
		}
	}()
	<-stop
	server.Shutdown(context.Background())
}
