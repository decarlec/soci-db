package test

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"sociapi.com/main/database"
	"sociapi.com/main/setup"
)

var driver neo4j.DriverWithContext
var db *database.Database
var ctx context.Context = context.Background()

func TestCreateUser(t *testing.T) {
	driver = setup.Get_db_driver(ctx)
	db = database.NewDatabase(driver)
	defer driver.Close(ctx)
	username := "test"

	//Clean up user
	defer db.DeleteUser(ctx, username)

	//Create user
	expected := database.User{
		Id:           uuid.NewString(),
		Username:     username,
		Email:        "test@email.com",
		PasswordHash: database.NewPasswordHash("test"),
	}
	user, err := db.CreateUser(ctx, expected)
	if err != nil || user == nil {
		panic(err)
	}

	//Get User
	actual, err := db.GetUserWithName(ctx, username)
	if err != nil {
		panic(err)
	}

	if !reflect.DeepEqual(&expected, actual) {
		t.Errorf("Created user did not match expected user: \r\n Expected: %v \r\n Actual: %v", expected, actual)
	}
}

func TestCreateAndGetGothicUser(t *testing.T) {
	driver = setup.Get_db_driver(ctx)
	db = database.NewDatabase(driver)
	defer driver.Close(ctx)

	username := "gothicTest"

	//Clean up user
	defer db.DeleteUser(ctx, username)

	//Create user
	expected := database.User{
		Id:       uuid.NewString(),
		Username: username,
	}
	user, err := db.CreateUser(ctx, expected)
	if err != nil || user == nil {
		panic(err)
	}
}
