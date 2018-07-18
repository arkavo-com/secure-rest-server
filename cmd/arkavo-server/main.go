package main

import (
	"context"
	"database/sql"
	"log"
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

	"github.com/globalsign/mgo"
	"github.com/go-openapi/spec"
	"github.com/gomodule/redigo/redis"
	_ "github.com/lib/pq"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Llongfile)
	// account
	var accountReader security.AccountReader
	sURL, err := url.Parse(configuration.Account.Store.Url)
	if err != nil {
		log.Println("store url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		info, err := dialMgo(*configuration.Account.Store)
		if err == nil {
			accountReader = account.RegisterStoreProviderMgo(&info)
		}
	case "postgres":
		db, err := sql.Open("postgres", sURL.String())
		if err != nil {
			log.Println(err)
		}
		err = db.Ping()
		if err != nil {
			log.Println(err)
		}
		if err == nil {
			accountReader = account.RegisterStoreProviderPostgres(db)
		}
	case "redis":
		c, err := dialRedis(*configuration.Account.Store)
		if err == nil {
			accountReader = account.RegisterStoreProviderRedis(c)
		}
	default:
		log.Println("development mode enabled - memory database")
		accountReader = account.RegisterStoreProviderMemdb()
	}
	if accountReader == nil {
		log.Fatal("accountReader uninitialized")
	}
	// permission
	sURL, err = url.Parse(configuration.Permission.Store.Url)
	if err != nil {
		log.Println("store url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		info, err := dialMgo(*configuration.Permission.Store)
		if err == nil {
			permission.RegisterStoreProviderMgo(&info)
		}
	case "postgres":
		db, err := sql.Open("postgres", sURL.String())
		if err != nil {
			log.Println(err)
		}
		err = db.Ping()
		if err != nil {
			log.Println(err)
		}
		if err == nil {
			permission.RegisterStoreProviderPostgres(db)
		}
	case "redis":
		c, err := dialRedis(*configuration.Permission.Store)
		if err == nil {
			permission.RegisterStoreProviderRedis(c)
		}
	default:
		permission.RegisterStoreProviderMemdb()
	}
	// policy
	var policyReader security.PolicyReader
	sURL, err = url.Parse(configuration.Policy.Store.Url)
	if err != nil {
		log.Println("store url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		info, err := dialMgo(*configuration.Policy.Store)
		if err == nil {
			policyReader = policy.RegisterStoreProviderMgo(&info)
		}
	case "redis":
		c, err := dialRedis(*configuration.Policy.Store)
		if err == nil {
			policyReader = policy.RegisterStoreProviderRedis(c)
		}
	default:
		policyReader = policy.RegisterStoreProviderMemdb()
	}
	if policyReader == nil {
		log.Fatal("policyReader uninitialized")
	}
	// role
	var roleReader security.RoleReader
	sURL, err = url.Parse(configuration.Role.Store.Url)
	if err != nil {
		log.Println("store url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		info, _ := dialMgo(*configuration.Role.Store)
		if err == nil {
			roleReader = role.RegisterStoreProviderMgo(&info)
		}
	case "postgres":
		db, err := sql.Open("postgres", sURL.String())
		if err != nil {
			log.Println(err)
		}
		err = db.Ping()
		if err != nil {
			log.Println(err)
		}
		if err == nil {
			roleReader = role.RegisterStoreProviderPostgres(db)
		}
	case "redis":
		c, _ := dialRedis(*configuration.Role.Store)
		if err == nil {
			roleReader = role.RegisterStoreProviderRedis(c)
		}
	default:
		roleReader = role.RegisterStoreProviderMemdb()
	}
	if roleReader == nil {
		log.Fatal("roleReader uninitialized")
	}
	// session
	sURL, err = url.Parse(configuration.Session.Store.Url)
	if err != nil {
		log.Println("store url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		info, _ := dialMgo(*configuration.Session.Store)
		if err == nil {
			session.RegisterStoreProviderMgo(&info)
		}
	case "postgres":
		db, err := sql.Open("postgres", sURL.String())
		if err != nil {
			log.Println(err)
		}
		err = db.Ping()
		if err != nil {
			log.Println(err)
		}
		if err == nil {
			session.RegisterStoreProviderPostgres(db)
		}
	case "redis":
		c, _ := dialRedis(*configuration.Session.Store)
		if err == nil {
			session.RegisterStoreProviderRedis(c)
		}
	default:
		session.RegisterStoreProviderMemdb()
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

func dialMgo(c security.Configuration_Store) (mgo.DialInfo, error) {
	info, err := mgo.ParseURL(c.Url)
	if err != nil {
		log.Println("mongodb url error", err)
		return *info, err
	}
	// connection test fast
	temp := info.FailFast
	info.FailFast = true
	_, err = mgo.DialWithInfo(info)
	if err != nil {
		log.Println("mongodb dial error", err)
	}
	info.FailFast = temp
	return *info, err
}

func dialRedis(c security.Configuration_Store) (redis.Conn, error) {
	conn, err := redis.Dial(
		c.Redis.Network,
		c.Redis.Address,
		redis.DialDatabase(int(c.Redis.Database)),
		redis.DialPassword(c.Redis.Password),
	)
	if err != nil {
		log.Println("redis dial error", err)
	}
	return conn, err
}
