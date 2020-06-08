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

	"github.com/arkavo-com/secure-rest-server/security"
	"github.com/arkavo-com/secure-rest-server/security/account"
	"github.com/arkavo-com/secure-rest-server/security/configuration"
	"github.com/arkavo-com/secure-rest-server/security/permission"
	"github.com/arkavo-com/secure-rest-server/security/rest"
	"github.com/arkavo-com/secure-rest-server/security/role"
	"github.com/arkavo-com/secure-rest-server/security/session"
	"github.com/globalsign/mgo"
	"github.com/go-openapi/spec"
	"github.com/gomodule/redigo/redis"
	_ "github.com/lib/pq"
)

const (
	mongodbStore  = "mongodb"
	postgresStore = "postgres"
	redisStore    = "redis"
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
	case mongodbStore:
		s, err := dialMongo(*configuration.Account.Store)
		if err == nil {
			accountReader = account.StoreMongo(s)
		}
	case postgresStore:
		db, err := dialPostgres(*configuration.Account.Store)
		if err == nil {
			accountReader = account.StorePostgres(db)
		}
	case redisStore:
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
	case mongodbStore:
		s, err := dialMongo(*configuration.Permission.Store)
		if err == nil {
			permission.StoreMongo(s)
		}
	case postgresStore:
		db, err := dialPostgres(*configuration.Permission.Store)
		if err == nil {
			permission.StorePostgres(db)
		}
	case redisStore:
		c, err := dialRedis(*configuration.Permission.Store)
		if err == nil {
			permission.StoreRedis(c)
		}
	default:
		permission.StoreMem()
	}
	// role
	var roleReader security.RoleReader
	sURL, err = url.Parse(configuration.Role.Store.Url)
	if err != nil {
		log.Println("role url error", err)
	}
	switch sURL.Scheme {
	case mongodbStore:
		s, err := dialMongo(*configuration.Role.Store)
		if err == nil {
			roleReader = role.StoreMongo(s)
		}
	case postgresStore:
		db, err := dialPostgres(*configuration.Role.Store)
		if err == nil {
			roleReader = role.StorePostgres(db)
		}
	case redisStore:
		c, err := dialRedis(*configuration.Role.Store)
		if err == nil {
			roleReader = role.StoreRedis(c)
		}
	default:
		roleReader = role.StoreMem()
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
	case mongodbStore:
		s, err := dialMongo(*configuration.Session.Store)
		if err == nil {
			session.StoreMongo(s)
		}
	case postgresStore:
		db, err := dialPostgres(*configuration.Session.Store)
		if err == nil {
			session.StorePostgres(db)
		}
	case redisStore:
		c, err := dialRedis(*configuration.Session.Store)
		if err == nil {
			session.StoreRedis(c)
		}
	default:
		session.StoreMem()
	}
	// openapi paths
	pa := spec.Paths{Paths: map[string]spec.PathItem{}}
	// session
	session.HandlePath(pa, accountReader, roleReader)
	// role
	role.HandlePath(pa)
	// permission
	permission.HandlePath(pa)
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
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			PreferServerCipherSuites: true,
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
	_ = server.Shutdown(context.Background())
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
