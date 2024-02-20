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
	"golang.org/x/crypto/bcrypt"
)

var (
	alertMutex         sync.Mutex
	pedestrianEntities map[string]Entity
	nearbyCarsEntities []Entity
	dbPool             *pgxpool.Pool               // 대규모로 하려면 필요
	secretKey          = []byte("your_secret_key") // 비밀 키 설정
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
	// go periodicTask()

	// JSON 데이터를 받는 엔드포인트 추가
	e.POST("/updatePosition", updatePositionHandler)

	// 회원가입을 처리하는 엔드포인트 추가
	e.POST("/signup", signupHandler)

	// 로그인을 처리하는 엔드포인트 추가
	e.POST("/login", loginHandler)

	// 서버 시작
	e.Start(":8080")
}

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

	// 임시 비밀번호 보안 걸어둔거 때문에 잘안돼서 일단 없이 진행
	// // 비밀번호 검증
	// err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	// if err != nil {
	// 	// 비밀번호가 일치하지 않음
	// 	return c.JSON(http.StatusUnauthorized, Response{Message: "이메일 또는 비밀번호가 잘못되었습니다"})
	// }
	// fmt.Println("비밀번호 일치")

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

	// 비밀번호를 유효성 검사하고 해싱
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userData.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, Response{Message: "비밀번호 해싱 중 오류 발생"})
	}

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

// 주기적으로 작업을 수행하는 함수
func periodicTask() {
	ticker := time.NewTicker(5 * time.Second)

	for range ticker.C {
		// 모든 보행자에 대해 주기적으로 작업을 수행
		for pedestrianID := range pedestrianEntities {
			// 보행자의 현재 위치와 예상 위치를 계산해 변수에 담는다
			me := refreshPedestrianEntity(pedestrianID)

			// 보행자는 주기적으로 반경 10m 이내에 있는 모든 차의 현재 위치와 예상 이동 위치를 가져온다.
			nearbyCars := getNearbyCars(me.Predicted, 10) // 반경을 10m로 설정
			nearbyCarsEntities = nearbyCars

			for _, car := range nearbyCars {
				if isCollisionExpected(me, car) {
					// 충돌이 예상되면 알림을 보낸다
					sendAlert(me.ID, car.ID)
				}
			}

			fmt.Println("Pedestrian", me.Predicted.UserID, "is at", me.Predicted.Latitude, me.Predicted.Longitude)

			// 현재 위치 정보를 데이터베이스에 저장
			if err := savePositionToDatabase(me.ID, me.Predicted.Latitude, me.Predicted.Longitude); err != nil {
				fmt.Println("Error saving position to database:", err)
			}
		}
	}
}

// 회원 정보를 PostGIS 데이터베이스에 저장
func saveUserToDatabase(id, email, hashedPassword, gender, region string) error {
	query := "INSERT INTO pedestrians (id, email, password, gender, region) VALUES ($1, $2, $3, $4, $5)"
	_, err := dbPool.Exec(context.Background(), query, id, email, hashedPassword, gender, region)
	return err
}

// 위치 정보를 PostGIS 데이터베이스에 저장
func savePositionToDatabase(userID string, latitude, longitude float64) error {
	query := "INSERT INTO points (name, geom) VALUES ($1, ST_SetSRID(ST_MakePoint($2, $3), 4326))"
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
	Password string `json:"password"`
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

// POSTGIS 데이터베이스에서 쿼리하여 반경 내의 차량을 가져온다
func getNearbyCars(position Position, radius float64) []Entity {
	// 실제로는 데이터베이스 쿼리 등을 수행해야 하지만 현재는 빈 슬라이스 반환
	return []Entity{}
}

// 충돌이 예상되는지 계산하는 로직
func isCollisionExpected(pedestrian Entity, car Entity) bool {
	// 보행자와 차량의 예상 위치가 충돌할 것으로 예상되면 true를 반환한다
	return pedestrian.Predicted == car.Predicted
}

// 알림을 보내는 로직
func sendAlert(pedestrianID string, carID string) {
	// 여러 고루틴에서 동시에 알림을 보내지 않도록 Mutex를 사용
	alertMutex.Lock()
	defer alertMutex.Unlock()

	// 실제로는 여기에 알림을 보내는 로직을 추가해야 한다.
	fmt.Printf("Alert: Pedestrian %s and Car %s are expected to collide!\n", pedestrianID, carID)
}

// 보행자 정보를 업데이트하는 로직
func refreshPedestrianEntity(id string) Entity {
	// 1. 핸드폰 gps 좌표 받아서 entity에 저장하고
	// 2. AI 서비스 호출해서 예상 위치 받아서 entity에 저장
	nowLongitude, nowLatitude := getCurrentPosition()
	futureLongitude, futureLatitude := predictFuturePosition(nowLongitude, nowLatitude)

	// 3. entity 반환
	pedestrianEntities[id] = Entity{
		ID: id,
		Predicted: Position{
			Latitude:  futureLatitude,
			Longitude: futureLongitude,
		},
	}
	return pedestrianEntities[id]
}

// 현재 위치를 가져오는 로직
func getCurrentPosition() (float64, float64) {
	// 핸드폰 GPS 좌표를 가져오는 로직 (실제로는 외부 라이브러리나 장치와 통신 필요)
	return 37.5665, 126.9780 // 서울의 위도와 경도를 임의로 반환
}

// 예상 위치를 계산하는 로직
func predictFuturePosition(longitude float64, latitude float64) (float64, float64) {
	// AI 서비스를 호출하여 예상 위치를 계산하는 로직 (실제로는 외부 API 호출 등이 필요)
	return latitude + 0.001, longitude + 0.001 // 임의의 변화를 가하여 예상 위치 계산
}

// JSON 데이터를 받는 핸들러
func updatePositionHandler(c echo.Context) error {
	var data Position

	if err := c.Bind(&data); err != nil {
		return c.JSON(http.StatusBadRequest, Response{Message: "Invalid JSON format"})
	}

	// 받은 데이터를 사용하여 원하는 작업 수행
	fmt.Printf("Received position update: userID %s, Latitude %f, Longitude %f\n", data.UserID, data.Latitude, data.Longitude)

	// 데이터베이스에 위치 저장 함수 호출
	if err := savePositionToDatabase(data.UserID, data.Latitude, data.Longitude); err != nil {
		fmt.Println("데이터베이스에 위치 저장 중 오류 발생:", err)
		// 오류 처리 필요에 따라 추가
		return c.JSON(http.StatusInternalServerError, Response{Message: "데이터베이스에 위치 저장 중 오류 발생"})
	}

	return c.JSON(http.StatusOK, Response{Message: "Position updated successfully"})
}
