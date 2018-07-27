package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"secure-rest-server/security"
	"secure-rest-server/security/account"
	"secure-rest-server/security/configuration"
	"secure-rest-server/security/permission"
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
		log.Println("account url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		s, err := dialMongo(*configuration.Account.Store)
		if err == nil {
			accountReader = account.StoreMongo(s)
		}
	case "postgres":
		db, err := dialPostgres(*configuration.Account.Store)
		if err == nil {
			accountReader = account.StorePostgres(db)
		}
	case "redis":
		c, err := dialRedis(*configuration.Account.Store)
		if err == nil {
			accountReader = account.StoreRedis(c)
		}
	default:
		log.Println("development mode enabled - memory database")
		accountReader = account.StoreMem()
	}
	if accountReader == nil {
		log.Fatal("accountReader uninitialized")
	}
	// permission
	sURL, err = url.Parse(configuration.Permission.Store.Url)
	if err != nil {
		log.Println("permission url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		info, err := dialMgo(*configuration.Permission.Store)
		if err == nil {
			permission.RegisterStoreProviderMgo(&info)
		}
	case "postgres":
		db, err := dialPostgres(*configuration.Permission.Store)
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
	// role
	var roleReader security.RoleReader
	sURL, err = url.Parse(configuration.Role.Store.Url)
	if err != nil {
		log.Println("role url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		info, _ := dialMgo(*configuration.Role.Store)
		if err == nil {
			roleReader = role.RegisterStoreProviderMgo(&info)
		}
	case "postgres":
		db, err := dialPostgres(*configuration.Role.Store)
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
		log.Println("session url error", err)
	}
	switch sURL.Scheme {
	case "mongodb":
		info, _ := dialMgo(*configuration.Session.Store)
		if err == nil {
			session.RegisterStoreProviderMgo(&info)
		}
	case "postgres":
		db, err := dialPostgres(*configuration.Session.Store)
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
	session.RegisterHttpHandler(pa, accountReader, roleReader)
	// role
	role.RegisterHttpHandler(pa)
	// permission
	permission.RegisterHttpHandler(pa)
	// account
	account.HandlePath(pa, accountReader)
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
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSNextProto: nil,
		TLSConfig: &tls.Config{
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: configuration.Server.Tls.PreferServerCipherSuites,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
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

func dialPostgres(c security.Configuration_Store) (*sql.DB, error) {
	db, err := sql.Open("postgres", c.Url)
	if err != nil {
		log.Println("postgres url error", err)
	}
	err = db.Ping()
	if err != nil {
		log.Println("postgres dial error", err)
	}
	return db, err
}

func dialMongo(c security.Configuration_Store) (*mgo.Session, error) {
	info, err := mgo.ParseURL(c.Url)
	if err != nil {
		log.Println("mongodb url error", err)
		return nil, err
	}
	// connection test fast
	temp := info.FailFast
	info.FailFast = true
	s, err := mgo.DialWithInfo(info)
	if err != nil {
		log.Println("mongodb dial error", err)
	}
	info.FailFast = temp
	return s, err
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
