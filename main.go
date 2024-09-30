package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	ctx "context"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"github.com/thehellruler/telegraph/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	ID    primitive.ObjectID `json:"_id" bson:"_id"`
	Uname string             `json:"uname" bson:"uname"`
	Pass  string             `json:"pass" bson:"pass"`
	Name  string             `json:"name" bson:"name"`
}
type Item struct {
	ID     primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	PName  string             `json:"pname" bson:"pname"`
	PType  string             `json:"ptype" bson:"ptype"`
	PStock string             `json:"pstock" bson:"pstock"`
	Price  string             `json:"price" bson:"price"`
	Photo  string             `json:"photo" bson:"photo"`
	Cat    string             `json:"cat" bson:"cat"`
	Desc   string             `json:"desc" bson:"desc"`
	ShId   string             `json:"shid" bson:"shid"`
}
type ResForApi struct {
}
type Shop struct {
	ID      primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	SName   string             `json:"name" bson:"name"`
	OName   string             `json:"uname" bson:"uname"`
	Area    string             `json:"area" bson:"area"`
	SPass   string             `json:"pass" bson:"pass"`
	MLink   string             `json:"lnk" bson:"lnk"`
	Contact string             `json:"contact" bson:"contact"`
}

var (
	adcoll, cmscoll *mongo.Collection
)

func main() {
	godotenv.Load()
	router := mux.NewRouter()
	router.HandleFunc("/", basicAuth(Home, false))
	router.HandleFunc("/upload", ToTele)
	router.HandleFunc("/apiforapp", Appesh)
	router.HandleFunc("/apiforshop", ApiForShop)
	router.HandleFunc("/admin", basicAuth(Shopesh, true))
	/*
		router.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
			fmt.Println(r.Body)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintln(w, strforlogout)
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}) */
	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusSeeOther) })
	handler := cors.Default().Handler(router)
	srv := &http.Server{
		Addr:         ":4000",
		Handler:      handler,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	serverAPI := options.ServerAPI(options.ServerAPIVersion1)
	opts := options.Client().ApplyURI(os.Getenv("URI")).SetServerAPIOptions(serverAPI)

	client, err := mongo.Connect(ctx.TODO(), opts)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err = client.Disconnect(ctx.TODO()); err != nil {
			panic(err)
		}
	}()
	adcoll = client.Database("Cluster0").Collection("admins")
	cmscoll = client.Database("Cluster0").Collection("cms")
	if err := client.Ping(ctx.TODO(), nil); err != nil {
		panic(err)
	}
	fmt.Println("You are successfully connected to MongoDB!")
	log.Printf("starting server on %s", srv.Addr)
	err = srv.ListenAndServe()
	log.Fatal(err)

}
func Home(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		{
			dat := json.NewDecoder(r.Body)
			var bod map[string]string
			dat.Decode(&bod)
			w.WriteHeader(http.StatusOK)
			var data []Item
			res, err := cmscoll.Find(ctx.TODO(), bson.D{{"shid", bod["idd"]}})
			if err != nil || res.RemainingBatchLength() == 0 {
				data = nil
			} else {
				res.All(ctx.TODO(), &data)
			}
			datfr := make(map[string]any)
			datfr["Nm"] = bod["name"]
			datfr["Dt"] = data
			datfr["Id"] = bod["idd"]
			tmpl, _ := template.ParseFiles("templates\\main.tmpl")
			tmpl.Execute(w, datfr)
		}
	case "POST":
		{
			dat := json.NewDecoder(r.Body)
			var file Item
			dat.Decode(&file)
			cmscoll.InsertOne(ctx.TODO(), file)
		}
	}
}
func basicAuth(next http.HandlerFunc, ad bool) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			username, password, ok := r.BasicAuth()
			if ok && CheckInp(username) {
				if ad {
					usernameHash := sha256.Sum256([]byte(username))
					passwordHash := sha256.Sum256([]byte(password))
					expectedUsernameHash := sha256.Sum256([]byte(os.Getenv("USER")))
					expectedPasswordHash := sha256.Sum256([]byte(os.Getenv("PASS")))

					usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
					passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

					if usernameMatch && passwordMatch {
						next.ServeHTTP(w, r)
						return
					}
				} else {
					passwordHash := sha256.Sum256([]byte(password))
					res := adcoll.FindOne(ctx.TODO(), bson.D{{Key: "uname", Value: username}})
					if err := res.Err(); err == nil {
						var resUser User
						res.Decode(&resUser)
						expectedPasswordHash := sha256.Sum256([]byte(resUser.Pass))
						passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

						if passwordMatch {
							bod := make(map[string]string)
							bod["name"] = resUser.Name
							bod["idd"] = resUser.ID.Hex()
							str, _ := json.Marshal(bod)
							r.Body = io.NopCloser(strings.NewReader(string(str)))
							next.ServeHTTP(w, r)
							return
						}
					}
				}
			}
			w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		}
		next.ServeHTTP(w, r)
	})
}

func CheckInp(inp string) bool {
	re, _ := regexp.Compile(`^\w+$`)
	return re.Match([]byte(inp))
}

func ToTele(w http.ResponseWriter, r *http.Request) {
	file, _, _ := r.FormFile("file")
	red := bufio.NewReader(file)
	lnk, err := telegraph.Upload(red, "photo")
	res := make(map[string]string)
	if err != nil {
		res["err"] = err.Error()
	} else {
		res["link"] = "https://graph.org" + lnk
	}
	js, _ := json.Marshal(res)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, string(js))
}
func Appesh(w http.ResponseWriter, r *http.Request) {
	cur, _ := cmscoll.Find(ctx.TODO(), bson.D{{}})
	var items []Item
	if err := cur.All(ctx.TODO(), &items); err != nil {
		fmt.Println(err.Error())
	}
	data, _ := json.Marshal(items)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, string(data))
}

var strforlogout = `
<!DOCTYPE html>
<html>
<head>
    <title>Logout</title>
</head>
<body>    
<script>

</script>
</body>
</html>
`

func ApiForShop(w http.ResponseWriter, r *http.Request) {
	cur, _ := adcoll.Find(ctx.TODO(), bson.D{{}})
	var Shops []Shop
	if err := cur.All(ctx.TODO(), &Shops); err != nil {
		fmt.Println(err.Error())
	}
	data, _ := json.Marshal(Shops)
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, string(data))
}

func Shopesh(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		{
			tmpl, _ := template.ParseFiles("templates\\admin.tmpl")
			var Data []Shop
			res, _ := adcoll.Find(ctx.TODO(), bson.D{{}})
			res.All(ctx.TODO(), &Data)
			tmpl.Execute(w, Data)
		}
	case "POST":
		{
			dat := json.NewDecoder(r.Body)
			var shopTo Shop
			dat.Decode(&shopTo)
			adcoll.InsertOne(ctx.TODO(), shopTo)
		}
	}
}
