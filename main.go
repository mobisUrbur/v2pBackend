package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var (
	alertMutex         sync.Mutex
	pedestrianEntities map[string]Entity
	nearbyCarsEntities []Entity
	dbPool             *pgxpool.Pool               // 대규모로 하려면 필요
	secretKey          = []byte("your_secret_key") // 비밀 키 설정
	pedestrianUUIDs    []string
	carUUIDs           []string
)

func init() {
	pedestrianEntities = make(map[string]Entity)
}

func main() {
	// PostgreSQL 연결 설정
	connConfig, err := pgxpool.ParseConfig("postgresql://postgres:1234@localhost:5432/v2p")
	if err != nil {
		fmt.Println("Error parsing connection config:", err)
		return
	}

	// PostgreSQL 연결 풀 생성
	dbPool, err = pgxpool.ConnectConfig(context.Background(), connConfig)
	if err != nil {
		fmt.Println("Error connecting to the database:", err)
		return
	}
	defer dbPool.Close()

	e := echo.New()

	e.Use(middleware.CORS())

	// API 엔드포인트 등록
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, Response{Message: "API is running"})
	})

	// 주기적으로 작업을 수행하는 goroutine 시작
	go FindCollsionUUID()

	// 보행자 관련 엔드포인트 등록
	// 보행자 미래 위치 받는 엔드포인트 추가
	e.POST("/updatePosition", updatePedestrainPosionHandler)

	// 회원가입을 처리하는 엔드포인트 추가
	e.POST("/signup", signupHandler)

	// 로그인을 처리하는 엔드포인트 추가
	e.POST("/login", loginHandler)

	// 클라이언트가 /peduuids 엔드포인트에 GET 요청을 보낼 때의 핸들러
	e.GET("/peduuids", func(c echo.Context) error {
		// 클라이언트에게 현재 저장된 보행자 UUID 목록을 응답
		return c.JSON(http.StatusOK, map[string]interface{}{"pedestrianUUIDs": pedestrianUUIDs})
	})

	// 자동차 관련 엔드포인트 등록
	// 자동차 미래 위치 받는 엔드포인트 추가
	e.POST("/updateCarPosionHandler", updateCarPosionHandler)

	// 회원가입을 처리하는 엔드포인트 추가
	e.POST("/carSignupHandler", carSignupHandler)

	// 로그인을 처리하는 엔드포인트 추가
	e.POST("/carLoginHandler", carLoginHandler)

	// 클라이언트가 /caruuids 엔드포인트에 GET 요청을 보낼 때의 핸들러
	e.GET("/caruuids", func(c echo.Context) error {
		// 클라이언트에게 현재 저장된 보행자 UUID 목록을 응답
		return c.JSON(http.StatusOK, map[string]interface{}{"carUUIDs": carUUIDs})
	})

	// 클라이언트가 /nearped 엔드포인트에 GET 요청을 보낼 때의 핸들러
	e.GET("/nearPedfindHandler", nearPedfindHandler)

	// 서버 시작
	e.Start(":8080")
}

// ////////////////////// 자동차 관련 //////////////////////////
// 좌표를 저장하기 위한 구조체
type LatLng struct {
	Lat float64
	Lng float64
}

// 자동차 미래 위치 기준 근방 보행자 찾는 핸들러
func getCollisionLatLng(carUUID string) ([]LatLng, error) {
	query := `
		SELECT
			ST_X(pedprediction.geom) AS lat,
			ST_Y(pedprediction.geom) AS lng
		FROM
			pedprediction
		LEFT JOIN LATERAL (
			SELECT
				carprediction.id
			FROM
				carprediction
			WHERE
				ST_DWithin(
					ST_Transform(pedprediction.geom, 3857),
					ST_Transform(carprediction.geom, 3857),
					40
				)
			ORDER BY
				pedprediction.geom <-> carprediction.geom
		) AS carprediction ON true
		WHERE
			carprediction.id IS NOT NULL
			AND carprediction.id = $1;
		`

	var lat, lng float64
	err := dbPool.QueryRow(context.Background(), query, carUUID).Scan(&lat, &lng)
	if err != nil {
		fmt.Println("Error getting collision coordinates:", err)
		return nil, err
	}

	coordinates := []LatLng{{Lat: lat, Lng: lng}}
	return coordinates, nil
}

type CarUUID struct {
	UserID string `json:"id"`
}

// 자동차 미래 위치 기준 근방 보행자 찾는 핸들러
func nearPedfindHandler(c echo.Context) error {
	var data CarUUID

	if err := c.Bind(&data); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Message: "Invalid JSON format"})
	}

	fmt.Println("Received car UUID:", data)
	// 근방 보행자 찾는 함수 호출
	coordinates, _ := getCollisionLatLng(data.UserID)

	// 클라이언트에 응답 보내기
	return c.JSON(http.StatusOK, map[string]interface{}{"pedestrianGPSs": coordinates})
}

type CarPredictPosition struct {
	UserID    string  `json:"userID"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// 위치 정보를 PostGIS 데이터베이스에 저장
func saveCarPositionToDatabase(userID string, latitude, longitude float64) error {
	query := "INSERT INTO carPrediction (id, geom) VALUES ($1, ST_SetSRID(ST_MakePoint($2, $3), 4326))"
	_, err := dbPool.Exec(context.Background(), query, userID, longitude, latitude)
	return err
}

// JSON 데이터를 받는 핸들러
func updateCarPosionHandler(c echo.Context) error {
	var data CarPredictPosition

	if err := c.Bind(&data); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Message: "Invalid JSON format"})
	}

	// 받은 데이터를 사용하여 원하는 작업 수행
	fmt.Printf("Received position update: userID %s, Latitude %f, Longitude %f\n", data.UserID, data.Latitude, data.Longitude)

	// 데이터베이스에 위치 저장 함수 호출
	if err := saveCarPositionToDatabase(data.UserID, data.Latitude, data.Longitude); err != nil {
		fmt.Println("데이터베이스에 위치 저장 중 오류 발생:", err)
		// 오류 처리 필요에 따라 추가
		return c.JSON(http.StatusInternalServerError, Response{Message: "데이터베이스에 위치 저장 중 오류 발생"})
	}

	return c.JSON(http.StatusOK, Response{Message: "Position updated successfully"})
}

// 자동차 정보를 PostGIS 데이터베이스에 저장
func saveCarToDatabase(id, email, password string) error {
	query := "INSERT INTO cars (id, email, password) VALUES ($1, $2, $3, $4, $5)"
	_, err := dbPool.Exec(context.Background(), query, id, email, password)
	return err
}

// 회원가입 API 응답 데이터 모델
type carSignUpResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"` // 새로 추가한 ID 필드
}

// 회원가입 요청 데이터 모델
type carSignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// 회원가입을 처리하는 핸들러
func carSignupHandler(c echo.Context) error {
	var userData carSignupRequest
	if err := c.Bind(&userData); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Message: "잘못된 요청 형식"})
	}
	// 고유 ID 생성
	userID := generateUniqueID()

	// 사용자 정보를 데이터베이스에 저장
	if err := saveCarToDatabase(userID, userData.Email, string(userData.Password)); err != nil {
		return c.JSON(http.StatusInternalServerError, Response{Message: "사용자 정보 저장 중 오류 발생"})
	}

	// 클라이언트에 응답 보내기
	return c.JSON(http.StatusOK, carSignUpResponse{Message: "사용자가 성공적으로 가입되었습니다!", ID: userID})
}

// 이메일로 자동차 정보 조회
func getCarByEmail(email string) (User, error) {
	var user User
	query := "SELECT id, email, password FROM cars WHERE email = $1"
	row := dbPool.QueryRow(context.Background(), query, email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	return user, err
}

// 로그인 요청 데이터 모델
type CarLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// 로그인 응답 데이터 모델
type CarLoginResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"`
}

// 로그인을 처리하는 핸들러
func carLoginHandler(c echo.Context) error {
	var loginData CarLoginRequest
	if err := c.Bind(&loginData); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Message: "잘못된 요청 형식"})
	}

	fmt.Println("Received login request:", loginData.Email, loginData.Password)

	// 데이터베이스에서 이메일로 사용자 찾기
	user, err := getCarByEmail(loginData.Email)
	fmt.Println("id찾기", user.Email, user.Password, user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, Response{Message: "사용자 조회 중 오류 발생"})
	}

	fmt.Println("비밀번호 해싱 안함", string(loginData.Password), user.Password)
	// 두 string이 같은지 비교
	if string(loginData.Password) != user.Password {
		fmt.Println("비밀번호가 일치하지 않음", string(loginData.Password))
		return c.JSON(http.StatusUnauthorized, Response{Message: "이메일 또는 비밀번호가 잘못되었습니다"})
	}

	// 클라이언트에 응답 보내기
	return c.JSON(http.StatusOK, CarLoginResponse{Message: "로그인 성공", ID: user.ID})
}

////////////////////////// 보행자 관련 //////////////////////////

// 로그인을 처리하는 핸들러
func loginHandler(c echo.Context) error {
	var loginData LoginRequest
	if err := c.Bind(&loginData); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Message: "잘못된 요청 형식"})
	}

	fmt.Println("Received login request:", loginData.Email, loginData.Password)

	// 데이터베이스에서 이메일로 사용자 찾기
	user, err := getUserByEmail(loginData.Email)
	fmt.Println("id찾기", user.Email, user.Password, user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, Response{Message: "사용자 조회 중 오류 발생"})
	}

	// // 임시 비밀번호 보안 걸어둔거 때문에 잘안돼서 일단 없이 진행
	// // 비밀번호 검증
	// hashedinput, err := bcrypt.GenerateFromPassword([]byte(loginData.Password), bcrypt.DefaultCost)
	// fmt.Println("비밀번호 해싱", string(hashedinput), user.Password)
	// // 두 string이 같은지 비교
	// if string(hashedinput) != user.Password {
	// 	fmt.Println("비밀번호가 일치하지 않음", string(loginData.Password))
	// 	return c.JSON(http.StatusUnauthorized, Response{Message: "이메일 또는 비밀번호가 잘못되었습니다"})
	// }
	// err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(hashedinput))
	// if err != nil {
	// 	// 비밀번호가 일치하지 않음
	// 	return c.JSON(http.StatusUnauthorized, Response{Message: "이메일 또는 비밀번호가 잘못되었습니다"})
	// }

	fmt.Println("비밀번호 해싱 안함", string(loginData.Password), user.Password)
	// 두 string이 같은지 비교
	if string(loginData.Password) != user.Password {
		fmt.Println("비밀번호가 일치하지 않음", string(loginData.Password))
		return c.JSON(http.StatusUnauthorized, Response{Message: "이메일 또는 비밀번호가 잘못되었습니다"})
	}

	// 토큰 생성
	accessToken, refreshToken, err := generateTokens(user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, Response{Message: "토큰 생성 중 오류 발생"})
	}

	// 클라이언트에 응답 보내기
	return c.JSON(http.StatusOK, LoginResponse{Message: "로그인 성공", ID: user.ID, Email: user.Email, AccessToken: accessToken, RefreshToken: refreshToken})
}

// 토큰 생성 함수
func generateTokens(userID string) (string, string, error) {
	// access 토큰 생성
	accessToken, err := generateToken(userID)
	if err != nil {
		return "", "", err
	}

	// refresh 토큰 생성
	refreshToken, err := generateToken(userID)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// 토큰 생성 함수
func generateToken(userID string) (string, error) {
	// 토큰 만료 시간 설정 (예: 1시간)
	expirationTime := time.Now().Add(1 * time.Hour)

	// 토큰 생성
	claims := &jwt.StandardClaims{
		Subject:   userID,
		ExpiresAt: expirationTime.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// 토큰 서명
	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// 이메일로 사용자 정보 조회
func getUserByEmail(email string) (User, error) {
	var user User
	query := "SELECT id, email, password FROM pedestrians WHERE email = $1"
	row := dbPool.QueryRow(context.Background(), query, email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	return user, err
}

// 로그인 요청 데이터 모델
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// 로그인 응답 데이터 모델
type LoginResponse struct {
	Message      string `json:"message"`
	ID           string `json:"id,omitempty"`
	Email        string `json:"email,omitempty"`
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty"`
}

// 사용자 정보 모델
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// 회원가입을 처리하는 핸들러
func signupHandler(c echo.Context) error {
	var userData SignupRequest
	if err := c.Bind(&userData); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Message: "잘못된 요청 형식"})
	}

	// // 비밀번호를 유효성 검사하고 해싱
	// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	// if err != nil {
	// 	return c.JSON(http.StatusInternalServerError, Response{Message: "비밀번호 해싱 중 오류 발생"})
	// }
	hashedPassword := userData.Password // 일단 해싱 없이 진행

	// 고유 ID 생성
	userID := generateUniqueID()

	// 사용자 정보를 데이터베이스에 저장
	if err := saveUserToDatabase(userID, userData.Email, string(hashedPassword), userData.Gender, userData.Region); err != nil {
		return c.JSON(http.StatusInternalServerError, Response{Message: "사용자 정보 저장 중 오류 발생"})
	}

	// 클라이언트에 응답 보내기
	return c.JSON(http.StatusOK, SignUpResponse{Message: "사용자가 성공적으로 가입되었습니다!", ID: userID, Email: userData.Email})
}

// 새로운 고유한 ID를 생성하는 함수
func generateUniqueID() string {
	return uuid.New().String()
}

func deletepedPrediction() {
	query := "DELETE FROM pedPrediction"
	_, err := dbPool.Exec(context.Background(), query)
	if err != nil {
		fmt.Println("Error deleting position:", err)
	}
}

func deletecarPrediction() {
	query := "DELETE FROM carPrediction"
	_, err := dbPool.Exec(context.Background(), query)
	if err != nil {
		fmt.Println("Error deleting position:", err)
	}
}

// 주기적으로 작업을 수행하는 함수
func FindCollsionUUID() {
	ticker := time.NewTicker(5 * time.Second)

	for range ticker.C {
		// 충돌이 예상되는지 확인할 모든 보행자와 차량을 가져오는 쿼리문 실행
		pedestrianUUIDs, carUUIDs = getCollisionUUID()
		// 원래 저장되어있던 미래 예측 데이터 다 지우고 새로 받아오기

		// 저장된 미래 위치 지우는 쿼리문 실행
		// deletepedPrediction()
		// deletecarPrediction()
	}
}

// 충돌이 예상되는 자동차와 보행자의 uuid 쌍을 가져오는 쿼리문 실행
func getCollisionUUID() ([]string, []string) {
	query := `
		SELECT
			array_agg(pedprediction.id) AS pedestrian_uuid,
			array_agg(carprediction.id) AS car_uuid
		FROM
			pedprediction
		LEFT JOIN LATERAL (
			SELECT
				carprediction.id
			FROM
				carprediction
			WHERE
				ST_DWithin(
					ST_Transform(pedprediction.geom, 3857),
					ST_Transform(carprediction.geom, 3857),
					20
				)
			ORDER BY
				pedprediction.geom <-> carprediction.geom
			LIMIT 1
		) AS carprediction ON true
		WHERE
			carprediction.id IS NOT NULL;
		`
	var pedestrianUUIDs, carUUIDs []string
	err := dbPool.QueryRow(context.Background(), query).Scan(&pedestrianUUIDs, &carUUIDs)
	if err != nil {
		fmt.Println("Error getting collision UUIDs:", err)
		return nil, nil
	}

	return pedestrianUUIDs, carUUIDs
}

// 회원 정보를 PostGIS 데이터베이스에 저장
func saveUserToDatabase(id, email, hashedPassword, gender, region string) error {
	query := "INSERT INTO pedestrians (id, email, password, gender, region) VALUES ($1, $2, $3, $4, $5)"
	_, err := dbPool.Exec(context.Background(), query, id, email, hashedPassword, gender, region)
	return err
}

// 보행자 미래 위치 정보를 PostGIS 데이터베이스에 저장
func savePedPositionToDatabase(userID string, latitude, longitude float64) error {
	query := "INSERT INTO pedPrediction (id, geom) VALUES ($1, ST_SetSRID(ST_MakePoint($2, $3), 4326))"
	_, err := dbPool.Exec(context.Background(), query, userID, longitude, latitude)
	return err
}

// 회원가입 API 응답 데이터 모델
type SignUpResponse struct {
	Message string `json:"message"`
	ID      string `json:"id,omitempty"` // 새로 추가한 ID 필드
	Email   string `json:"email,omitempty"`
}

// 회원가입 요청 데이터 모델
type SignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password1"`
	Gender   string `json:"gender"`
	Region   string `json:"region"`
}

// API 응답 데이터 모델
type Response struct {
	Message string `json:"message"`
}

// 사용자 정의 데이터 모델
type Entity struct {
	ID        string   `json:"id"`
	Predicted Position `json:"predicted"`
}

type Position struct {
	UserID    string  `json:"userID"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

// JSON 데이터를 받는 핸들러
func updatePedestrainPosionHandler(c echo.Context) error {
	var data Position

	if err := c.Bind(&data); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Message: "Invalid JSON format"})
	}

	// 받은 데이터를 사용하여 원하는 작업 수행
	fmt.Printf("Received position update: userID %s, Latitude %f, Longitude %f\n", data.UserID, data.Latitude, data.Longitude)

	// 데이터베이스에 위치 저장 함수 호출
	if err := savePedPositionToDatabase(data.UserID, data.Latitude, data.Longitude); err != nil {
		fmt.Println("데이터베이스에 위치 저장 중 오류 발생:", err)
		// 오류 처리 필요에 따라 추가
		return c.JSON(http.StatusInternalServerError, Response{Message: "데이터베이스에 위치 저장 중 오류 발생"})
	}

	return c.JSON(http.StatusOK, Response{Message: "Position updated successfully"})
}
